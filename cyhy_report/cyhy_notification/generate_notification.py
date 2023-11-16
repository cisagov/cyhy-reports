#!/usr/bin/env python

"""Create a Cyber Hygiene notification PDF.

Usage:
  cyhy-notification [options] OWNER ...
  cyhy-notification (-h | --help)
  cyhy-notification --version

Options:
  -a --anonymize                 Make a sample anonymous notification.
  -d --debug                     Keep intermediate files for debugging.
  -e --encrypt                   Encrypt with config key and owner keys if
                                   the owner has a key in the datastore.
  -f --final                     Remove draft watermark.
  -h --help                      Show this screen.
  --version                      Show version.
  --cyhy-section=SECTION         Configuration section to use to access the
                                 cyhy database.
"""

# Standard Python Libraries
import codecs
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Third-Party Libraries
import chevron
from docopt import docopt
from netaddr import IPAddress
from pyPdf import PdfFileWriter, PdfFileReader
import unicodecsv as csv

# cisagov Libraries
from cyhy.core import Config
from cyhy.db import database
from cyhy.util import to_json, utcnow
from cyhy_report.cyhy_notification._version import __version__

# constants
SEVERITY_LEVELS = ["Informational", "Low", "Medium", "High", "Critical"]
VULNERABILITY_FINDINGS_CSV_FILE = "findings.csv"
RISKY_SERVICES_CSV_FILE = "potentially-risky-services.csv"
MUSTACHE_FILE = "notification.mustache"
NOTIFICATION_JSON = "notification.json"
NOTIFICATION_PDF = "notification.pdf"
ENCRYPTED_NOTIFICATION_PDF = "e_notification.pdf"
NOTIFICATION_TEX = "notification.tex"
ASSETS_DIR_SRC = "../assets"
ASSETS_DIR_DST = "assets"
IPV4_ADDRESS_RE = re.compile(r"\d+\.\d+\.(\d+\.\d+)")
ANONYMOUS_IPV4 = r"x.x.\1"
LATEX_ESCAPE_MAP = {
    "$": "\\$",
    "%": "\\%",
    "&": "\\&",
    "#": "\\#",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "[": "{[}",
    "]": "{]}",
    "'": "{'}",
    "\\": "\\textbackslash{}",
    "~": "\\textasciitilde{}",
    "<": "\\textless{}",
    ">": "\\textgreater{}",
    "^": "\\textasciicircum{}",
    "`": "{}`",
    "\n": "\\newline{}",
}

# Number of days a vulnerability can be active until it's considered
# "overdue" to be mitigated
DAYS_UNTIL_OVERDUE_CRITICAL = 15
DAYS_UNTIL_OVERDUE_HIGH = 30

# The list of services below determined to be (potentially) risky was created
# by the Cyber Hygiene team and it may change in the future.
# The service names (keys in the dict below) come from the nmap services list:
#  https://svn.nmap.org/nmap/nmap-services
RISKY_SERVICES_MAP = {
    "ms-wbt-server": "RDP",
    "telnet": "Telnet",
    "rtelnet": "Telnet",
    "microsoft-ds": "SMB",
    "smbdirect": "SMB",
    "ldap": "LDAP",
    "netbios-ns": "NetBIOS",
    "netbios-dgm": "NetBIOS",
    "netbios-ssn": "NetBIOS",
    "ftp": "FTP",
    "rsftp": "FTP",
    "ni-ftp": "FTP",
    "tftp": "FTP",
    "bftp": "FTP",
    "msrpc": "RPC",
    "sqlnet": "SQL",
    "sqlserv": "SQL",
    "sql-net": "SQL",
    "sqlsrv": "SQL",
    "msql": "SQL",
    "mini-sql": "SQL",
    "mysql-cluster": "SQL",
    "ms-sql-s": "SQL",
    "ms-sql-m": "SQL",
    "irc": "IRC",
    "kerberos-sec": "Kerberos",
    "kpasswd5": "Kerberos",
    "klogin": "Kerberos",
    "kshell": "Kerberos",
    "kerberos-adm": "Kerberos",
    "kerberos": "Kerberos",
    "kerberos_master": "Kerberos",
    "krb_prop": "Kerberos",
    "krbupdate": "Kerberos",
    "kpasswd": "Kerberos",
}

# For BOD 23-02, we define a list of services that may indicate potential
# publicly-accessible networked management interfaces that should be protected.
POTENTIAL_NMI_SERVICES = [
    "microsoft-ds",   # SMB
    "ms-wbt-server",  # RDP
    "rtelnet",        # Telnet
    "smbdirect",      # SMB
    "telnet",         # Telnet
]

class NotificationGenerator(object):
    """The class for generating notification documents."""

    def __init__(
        self,
        cyhy_db,
        owner,
        debug=False,
        final=False,
        anonymize=False,
        encrypt_key=None,
    ):
        """Construct a NotificationGenerator."""
        self.__cyhy_db = cyhy_db
        self.__owner = owner
        self.__results = None  # reusable query results
        self.__debug = debug
        self.__draft = not final
        self.__anonymize = anonymize
        self.__encrypt_key = encrypt_key
        self.__generated_time = utcnow()

    def generate_notification(self):
        """Generate a notification PDF."""
        # Create a working directory
        original_working_dir = os.getcwdu()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # Set up the working directory
        self.__setup_work_directory(temp_working_dir)

        # Access database and cache results
        self.__run_queries()

        # If no notifications are found, exit without creating a PDF
        if not self.__results["notifications"]:
            # Revert to original working directory
            os.chdir(original_working_dir)

            if not self.__debug:
                # Delete temp working directory
                shutil.rmtree(temp_working_dir)

            return False, self.__results

        # Store key if present
        owner_key = self.__results["owner_request_doc"].get("key")

        # Anonymize data if requested
        if self.__anonymize:
            for t in self.__results["tickets"]:
                if t["owner"] == self.__owner:
                    t["owner"] = "SAMPLE"
                else:
                    t["owner"] = "SUB_ORG"
                t["plugin_output"] = (
                    "Output details from the vulnerability "
                    "scan plugin would be shown here."
                )
            self.__owner = "SAMPLE"
            self.__results["owner_request_doc"]["agency"]["acronym"] = "SAMPLE"
            self.__results = self.__anonymize_structure(self.__results)

        # Generate attachments
        self.__generate_attachments()

        # Generate json input to mustache
        self.__generate_mustache_json(NOTIFICATION_JSON)

        # Generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, NOTIFICATION_JSON, NOTIFICATION_TEX)

        # Generate PDF
        pdf_generated_rc = self.__generate_final_pdf()

        # Mark notifications as generated in the database
        if pdf_generated_rc == 0:
            if not self.__anonymize:
                # Skip this step for anonymized notifications
                self.__mark_notifications_as_generated()
        else:
            sys.exit(pdf_generated_rc)

        # Encrypt if requested and possible
        if self.__encrypt_key is not None and owner_key is not None:
            self.__encrypt_pdf(
                NOTIFICATION_PDF,
                ENCRYPTED_NOTIFICATION_PDF,
                self.__encrypt_key,
                owner_key,
            )
            shutil.move(ENCRYPTED_NOTIFICATION_PDF, NOTIFICATION_PDF)
            was_encrypted = True
        else:
            was_encrypted = False

        # Revert working directory
        os.chdir(original_working_dir)

        # Copy report to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, NOTIFICATION_PDF)
            timestamp = self.__generated_time.isoformat().replace(":", "").split(".")[0]
            dest_filename = "cyhy-notification-{}-{}.pdf".format(
                self.__owner, timestamp
            )
            shutil.move(src_filename, dest_filename)
            shutil.rmtree(temp_working_dir)

        return was_encrypted, self.__results

    def __setup_work_directory(self, work_dir):
        """Set up the working directory."""
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in (MUSTACHE_FILE,):
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # Copy static assets
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src, dir_dst)

    ##########################################################################
    # Database Access
    ##########################################################################
    def __load_tickets(self, ticket_ids):
        """Load tickets into memory.

        Also, merge some of their latest vulnerability/portscan fields.  These
        tickets should not be saved back to the database because they receive
        extra fields from their latest vulnerabilty/port scan.
        """
        # We use an aggregation here because a regular find/sort query can
        # exceed the memory limit of MongoDB: "Sort operation used more than
        # the maximum 33554432 bytes of RAM. Add an index, or specify a
        # smaller limit."
        tickets = list(
            self.__cyhy_db.TicketDoc.collection.aggregate(
                [
                    {"$match": {"_id": {"$in": ticket_ids}}},
                    {"$sort":
                        {
                            "details.kev": -1,
                            "details.cvss_base_score": -1,
                            "time_opened": 1,
                            "details.name": 1
                        },
                    }
                ],
                cursor={},
                allowDiskUse=True,
            )
        )

        for ticket in tickets:
            # Flatten structure by copying details to ticket root
            ticket.update(ticket["details"])

            # Process tickets that are based on vuln_scans
            if ticket["source"] in ["nessus"]:
                ticket["based_on_vulnscan"] = True
                ticket["based_on_portscan"] = False
                try:
                    latest_vuln = self.__cyhy_db.TicketDoc(ticket).latest_vuln()
                except database.VulnScanNotFoundException as e:
                    print("\n  Warning (non-fatal): {}".format(e.message))
                    # The vuln_scan has likely been archived; get the vuln_scan
                    #  _id and time from the VulnScanNotFoundException and set
                    # description and solution to 'Not available'
                    latest_vuln = {
                        "_id": e.vuln_scan_id,
                        "time": e.vuln_scan_time,
                        "description": "Not available",
                        "solution": "Not available",
                    }
                # Copy latest detection time to ticket and rename 'last_detected'
                ticket["last_detected"] = latest_vuln["time"]
            # Process tickets that are based on port_scans
            elif ticket["source"] in ["nmap"]:
                ticket["based_on_portscan"] = True
                ticket["based_on_vulnscan"] = False
                try:
                    latest_port = self.__cyhy_db.TicketDoc(ticket).latest_port()
                except database.PortScanNotFoundException as e:
                    print("\n  Warning (non-fatal): {}".format(e.message))
                    # The port_scan has likely been archived; get the port_scan
                    #  _id and time from the PortScanNotFoundException
                    latest_port = {
                        "_id": e.port_scan_id,
                        "time": e.port_scan_time,
                    }
                # Copy latest detection time to ticket and rename 'last_detected'
                ticket["last_detected"] = latest_port["time"]
                # Assign the category for this service
                ticket["category"] = RISKY_SERVICES_MAP.get(ticket["service"])
                # Check if this service is in the list of potential
                # network management interface services
                ticket["possible_nmi"] = ticket.get("service") in POTENTIAL_NMI_SERVICES

            if ticket["based_on_vulnscan"]:
                # Copy useful parts of latest vuln into ticket
                ticket.update(
                    {
                        k: latest_vuln.get(k)
                        for k in ["description", "solution", "plugin_output"]
                    }
                )

            # Calculate ticket age and store in the ticket
            ticket["age"] = (ticket["last_detected"] - ticket["time_opened"]).days

        # Convert severity integer to text (e.g. 4 -> Critical)
        self.__convert_levels_to_text(tickets, "severity")

        return tickets

    def __run_queries(self):
        """Run all DB queries and store results for later use."""
        self.__results = dict()

        # Get owner's request doc
        self.__results["owner_request_doc"] = self.__cyhy_db.RequestDoc.find_one(
            {"_id": self.__owner}
        )

        # Get all descendants of owner
        self.__results["owner_and_all_descendants"] = [
            self.__owner
        ] + self.__cyhy_db.RequestDoc.get_all_descendants(self.__owner)

        # Get all notifications for owner and descendants
        self.__results["notifications"] = list(
            self.__cyhy_db.NotificationDoc.find(
                {"ticket_owner": {"$in": self.__results["owner_and_all_descendants"]}}
            )
        )

        # Get all tickets mentioned in notifications
        ticket_ids = [n["ticket_id"] for n in self.__results["notifications"]]
        self.__results["tickets"] = self.__load_tickets(ticket_ids)

        # Determine if owner is a Federal org
        federal_orgs = self.__cyhy_db.RequestDoc.get_all_descendants("FEDERAL")
        self.__results["is_federal"] = self.__owner in federal_orgs

    ##########################################################################
    # Utilities
    ##########################################################################
    def __convert_levels_to_text(self, data, field):
        """Convert integer severity levels to their string counterparts."""
        for row in data:
            row[field] = SEVERITY_LEVELS[int(row[field])]

    def __anonymize_structure(self, data):
        """Anonymize a data structure."""
        if isinstance(data, basestring):
            return re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, data)
        elif isinstance(data, IPAddress):
            return re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, str(data))
        elif isinstance(data, dict):
            new_dict = dict()
            for k, v in data.items():
                new_dict[k] = self.__anonymize_structure(v)
            return new_dict
        elif isinstance(data, (list, tuple)):
            new_list = list()
            for i in data:
                new_list.append(self.__anonymize_structure(i))
            if isinstance(data, tuple):
                return tuple(new_list)
            else:
                return new_list
        else:
            return data

    def __latex_escape(self, to_escape):
        """Lookup and return escaped LaTeX special characters."""
        return "".join([LATEX_ESCAPE_MAP.get(i, i) for i in to_escape])

    def __latex_escape_structure(self, data):
        """Escape LaTeX special characters for a data structure.

        Assumes that all sequences contain dicts.
        """
        if isinstance(data, dict):
            for k, v in data.items():
                if k.endswith("_tex"):  # Skip special tex values
                    continue
                if isinstance(v, basestring):
                    data[k] = self.__latex_escape(v)
                else:
                    self.__latex_escape_structure(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure(i)

    ##########################################################################
    #  Attachment Generation
    ##########################################################################
    def __generate_attachments(self):
        """Generate attachments to the notification PDF."""
        self.__generate_findings_attachment()
        self.__generate_risky_services_attachment()

    def __generate_findings_attachment(self):
        """Create CSV based on vulnerability tickets in the notification."""
        header_fields = [
            "owner",
            "ip_int",
            "ip",
            "port",
            "known_exploited",
            "known_ransomware",
            "severity",
            "initial_detection",
            "latest_detection",
            "age_days",
            "cvss_base_score",
            "cve",
            "name",
            "description",
            "solution",
            "source",
            "plugin_id",
            "plugin_output",
        ]
        data_fields = [
            "owner",
            "ip_int",
            "ip",
            "port",
            "kev",
            "kev_ransomware",
            "severity",
            "time_opened",
            "last_detected",
            "age",
            "cvss_base_score",
            "cve",
            "name",
            "description",
            "solution",
            "source",
            "source_id",
            "plugin_output",
        ]

        if self.__anonymize:
            # Remove ip_int column if we are trying to be anonymous
            header_fields.remove("ip_int")
            data_fields.remove("ip_int")

        with open(VULNERABILITY_FINDINGS_CSV_FILE, "wb") as out_file:
            header_writer = csv.DictWriter(
                out_file, header_fields, extrasaction="ignore"
            )
            header_writer.writeheader()
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction="ignore")
            for ticket in self.__results["tickets"]:
                if ticket["based_on_vulnscan"]:
                    data_writer.writerow(ticket)

    def __generate_risky_services_attachment(self):
        """Create CSV based on portscan tickets in the notification."""
        header_fields = [
            "owner",
            "ip_int",
            "ip",
            "port",
            "service",
            "category",
            "possible_nmi",
            "initial_detection",
            "latest_detection",
            "age_days",
        ]
        data_fields = [
            "owner",
            "ip_int",
            "ip",
            "port",
            "service",
            "category",
            "possible_nmi",
            "time_opened",
            "last_detected",
            "age",
        ]

        if self.__anonymize:
            # Remove ip_int column if we are trying to be anonymous
            header_fields.remove("ip_int")
            data_fields.remove("ip_int")

        with open(RISKY_SERVICES_CSV_FILE, "wb") as out_file:
            header_writer = csv.DictWriter(
                out_file, header_fields, extrasaction="ignore"
            )
            header_writer.writeheader()
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction="ignore")
            for ticket in self.__results["tickets"]:
                if ticket["based_on_portscan"]:
                    data_writer.writerow(ticket)

    ##########################################################################
    # Final Document Generation and Assembly
    ##########################################################################
    def __generate_mustache_json(self, filename):
        """Create the JSON data to be used in mustache/LaTeX rendering."""
        result = dict()

        result["draft"] = self.__draft
        result["owner_acronym"] = self.__results["owner_request_doc"]["agency"][
            "acronym"
        ]
        result["is_federal"] = self.__results["is_federal"]
        result["notification_date_tex"] = self.__generated_time.strftime("{%d}{%m}{%Y}")
        result["days_until_criticals_overdue"] = DAYS_UNTIL_OVERDUE_CRITICAL
        result["days_until_highs_overdue"] = DAYS_UNTIL_OVERDUE_HIGH

        # Initialize flags for ticket types in this notification
        result["detected_urgent_vulns"] = False
        result["detected_risky_services"] = False

        result["tickets"] = self.__results["tickets"]
        for t in result["tickets"]:
            # Make port 0 into "NA"
            if t["port"] == 0:
                t["port"] = "NA"

            # Make LaTeX-friendly dates and times
            t["time_opened_date_tex"] = t["time_opened"].strftime("{%d}{%m}{%Y}")
            t["time_opened_time_tex"] = t["time_opened"].strftime("{%H}{%M}{%S}")
            t["last_detected_date_tex"] = t["last_detected"].strftime("{%d}{%m}{%Y}")
            t["last_detected_time_tex"] = t["last_detected"].strftime("{%H}{%M}{%S}")

            # Set flags for ticket types in this notification
            if t["source"] in ["nessus"]:
                result["detected_urgent_vulns"] = True
            if t["source"] in ["nmap"]:
                result["detected_risky_services"] = True

        # Only need to display the owner if there are descendants involved
        if self.__results["owner_and_all_descendants"] != [self.__owner]:
            result["display_owner"] = True

        # Escape LaTeX special characters in all result fields
        self.__latex_escape_structure(result)

        with open(filename, "wb") as out:
            out.write(to_json(result))

    def __generate_latex(self, mustache_file, json_file, latex_file):
        """Create a LaTex file based on a mustache template and JSON data."""
        template = codecs.open(mustache_file, "r", encoding="utf-8").read()

        with codecs.open(json_file, "r", encoding="utf-8") as data_file:
            data = json.load(data_file)

        r = chevron.render(template, data).decode("utf-8")
        with codecs.open(latex_file, "w", encoding="utf-8") as output:
            output.write(r)

    def __generate_final_pdf(self):
        """Create a PDF from a LaTeX file."""
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, "w")

        return_code = subprocess.call(
            ["xelatex", NOTIFICATION_TEX], stdout=output, stderr=subprocess.STDOUT
        )
        assert return_code == 0, "xelatex pass 1 of 2 return code was {}".format(
            return_code
        )

        # 2nd xelatex is needed to get table to format correctly
        return_code = subprocess.call(
            ["xelatex", NOTIFICATION_TEX], stdout=output, stderr=subprocess.STDOUT
        )
        assert return_code == 0, "xelatex pass 2 of 2 return code was {}".format(
            return_code
        )

        return return_code

    def __encrypt_pdf(self, name_in, name_out, user_key, owner_key):
        """Encrypt a PDF file with both a user key and an owner key."""
        pdf_writer = PdfFileWriter()
        pdf_reader = PdfFileReader(open(name_in, "rb"))

        # Metadata copy hack see:
        # http://stackoverflow.com/questions/2574676/change-metadata-of-pdf-file-with-pypdf
        metadata = pdf_reader.getDocumentInfo()
        pdf_writer._info.getObject().update(metadata)  # Copy metadata to dest

        for i in xrange(pdf_reader.getNumPages()):
            pdf_writer.addPage(pdf_reader.getPage(i))

        pdf_writer.encrypt(user_pwd=user_key, owner_pwd=owner_key.encode("ascii"))

        with file(name_out, "wb") as f:
            pdf_writer.write(f)

    def __mark_notifications_as_generated(self):
        """Update notification documents in the database.

        Add this owner to the list of owners that a notification was
        generated for.
        """
        notification_ids = [n["_id"] for n in self.__results["notifications"]]
        self.__cyhy_db.NotificationDoc.collection.update_many(
            {"_id": {"$in": notification_ids}},
            {"$push": {"generated_for": self.__owner}},
        )


def main():
    """Generate a notification PDF."""
    args = docopt(__doc__, version=__version__)
    cyhy_db = database.db_from_config(args["--cyhy-section"])

    for owner in args["OWNER"]:
        if args["--encrypt"]:
            report_key = Config(args["--cyhy-section"]).report_key
        else:
            report_key = None

        if args["--anonymize"]:
            print("Generating anonymized notification based on {} ...".format(owner)),
        else:
            print("Generating notification for {} ...".format(owner)),
        generator = NotificationGenerator(
            cyhy_db,
            owner,
            debug=args["--debug"],
            final=args["--final"],
            anonymize=args["--anonymize"],
            encrypt_key=report_key,
        )
        was_encrypted, results = generator.generate_notification()

        if results:
            if len(results["notifications"]) > 0:
                if was_encrypted:
                    print("Done (encrypted)")
                else:
                    print("Done")
            else:
                print("No notifications found, no PDF created!")

        # import IPython
        # IPython.embed()  # <<< BREAKPOINT >>>


if __name__ == "__main__":
    main()
