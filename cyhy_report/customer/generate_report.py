#!/usr/bin/env python

'''Create PDF Cyber Hygiene reports.

Usage:
  cyhy-report [options] OWNER ...
  cyhy-report (-h | --help)
  cyhy-report --version

Options:
  -a --anonymize                 Make a sample anonymous report.
  -d --debug                     Keep intermediate files for debugging.
  -e --encrypt                   Encrypt with config key and owner keys if
                                   the owner has a key in the datastore.
  -f --final                     Remove draft watermark.
  -h --help                      Show this screen.
  -n --nolog                     Do not log that this report was created.
  -o --overview=FILENAME         Create an overview of all reports
  -p --previous=SNAPSHOT_ID      Generate a previous report.
  --version                      Show version.
  --cyhy-section=SECTION         Configuration section to use to access the
                                 cyhy database.
  --scan-section=SECTION         Configuration section to use to access the
                                 scan database.
  -t --title-date=YYYYMMDD       Change the title page date.
'''

# standard python libraries
import csv
import sys
import os
import copy
import datetime
import time
import json
import codecs
import tempfile
import shutil
import subprocess
import re
from unicodecsv import DictWriter
from collections import OrderedDict
from dateutil import tz

# third-party libraries (install with pip)
from netaddr import IPAddress
import dateutil
import pystache
from pandas import Series, DataFrame
import pandas as pd
import numpy as np
import progressbar as pb
from bson import ObjectId
from docopt import docopt
from pyPdf import PdfFileWriter, PdfFileReader
#from PyPDF2 import PdfFileWriter, PdfFileReader

# intra-project modules
from cyhy.core import *
from cyhy.util import *
from cyhy.db import database
import queries
import graphs

# constants
VERBOSE = True
SECTION = None
SNAPSHOT_HISTORY_LIMIT = 30
MAX_REPORTCARD_BOX_DISPLAY = 5000
CRITICAL_AGE_OVER_TIME_CUTOFF_DAYS = 365    # Determines how far back we look at tickets for critical-vuln-ages-over-time figure
TICKET_AGE_BUCKET_CUTOFF_DAYS = 30  # Dividing line between 'young' and 'old' tickets in Cyber Exposure-esque graphs
ACTIVE_CRITICAL_AGE_CUTOFF_DAYS = 180 # Max number of days to display in __figure_active_critical_vuln_age_distribution()
ACTIVE_CRITICAL_AGE_BUCKETS = [(0,7), (7,14), (14,21), (21,30), (30,90)]
FALSE_POSITIVE_EXPIRING_SOON_DAYS = 30
STATIC_SERVICES = set(['http','https','smtp','ssh','domain','ftp'])
SEVERITY_LEVELS = ['Informational', 'Low', 'Medium', 'High', 'Critical']
OMITTED_MESSAGE_NO_VULNS = 'No Vulnerabilities Detected\nFigure Omitted'
OMITTED_MESSAGE_NO_VULNS_MITIGATED = 'No Vulnerabilities Mitigated\nFigure Omitted'
OMITTED_MESSAGE_TOO_MANY_VULNS = 'Too Many Vulnerabilities\nTo Display\nFigure Omitted'
OMITTED_MESSAGE_NO_SERVICES = 'No Services Detected\nFigure Omitted'
OMITTED_MESSAGE_NO_OPERATING_SYSTEMS = 'No Operating Systems Detected\nFigure Omitted'
OMITTED_MESSAGE_NO_VULN_RESPONSIVENESS_DATA = 'No Vulnerability Responsiveness\nData Available\nFigure Omitted'
OMITTED_MESSAGE_NO_CRITICALS_TO_DISPLAY = 'No Critical Vulnerabilities To Display\nFigure Omitted'
OMITTED_MESSAGE_NO_CRITICALS = 'No Critical Vulnerabilities Detected\nFigure Omitted'
MUSTACHE_FILE = 'report.mustache'
REPORT_JSON = 'report.json'
REPORT_PDF = 'report.pdf'
ENCRYPTED_REPORT_PDF = 'e_report.pdf'
REPORT_TEX = 'report.tex'
PLACEHOLDER_PDF = 'assets/placeholder.pdf'
ASSETS_DIR_SRC = '../assets'
ASSETS_DIR_DST = 'assets'
LATEX_ESCAPE_MAP = {
    '$':'\\$',
    '%':'\\%',
    '&':'\\&',
    '#':'\\#',
    '_':'\\_',
    '{':'\\{',
    '}':'\\}',
    '[':'{[}',
    ']':'{]}',
    "'":"{'}",
    '\\':'\\textbackslash{}',
    '~':'\\textasciitilde{}',
    '<':'\\textless{}',
    '>':'\\textgreater{}',
    '^':'\\textasciicircum{}',
    '`':'{}`',
    '\n': '\\newline{}',
}

IPV4_ADDRESS_RE = re.compile(r'\d+\.\d+\.(\d+\.\d+)')
ANONYMOUS_IPV4 = r'x.x.\1'

CVE_ID_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
CVE_URL = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'

BLUE =      '#5c90ba'
GREEN =     '#7bbe5e'
YELLOW =    '#cfc666'
ORANGE =    '#cf9c66'
RED =       '#c66270'
BLACK =     '#000000'

RC_DARK_BLUE = "#002d60"
RC_DARK_RED = "#963513"
RC_LIGHT_GREEN = "#5e9732"
RC_LIGHT_BLUE = "#0078ae"
RC_LIGHT_RED = "#c21734"
RC_ORANGE = "#f15a2d"

# The list of services below determined to be (potentially) risky was created
# by the Cyber Hygiene team and it may change in the future.
# The service names (keys in the dict below) come from the nmap services list:
#  https://svn.nmap.org/nmap/nmap-services
RISKY_SERVICES_MAP = {
    'ms-wbt-server': 'rdp',
    'telnet': 'telnet',
    'rtelnet': 'telnet',
    'microsoft-ds': 'smb',
    'smbdirect': 'smb',
    'ldap': 'ldap',
    'netbios-ns': 'netbios',
    'netbios-dgm': 'netbios',
    'netbios-ssn': 'netbios',
    'ftp': 'ftp',
    'rsftp': 'ftp',
    'ni-ftp': 'ftp',
    'tftp': 'ftp',
    'bftp': 'ftp',
    'msrpc': 'rpc',
    'sqlnet': 'sql',
    'sqlserv': 'sql',
    'sql-net': 'sql',
    'sqlsrv': 'sql',
    'msql': 'sql',
    'mini-sql': 'sql',
    'mysql-cluster': 'sql',
    'ms-sql-s': 'sql',
    'ms-sql-m': 'sql',
    'irc': 'irc',
    'kerberos-sec': 'kerberos',
    'kpasswd5': 'kerberos',
    'klogin': 'kerberos',
    'kshell': 'kerberos',
    'kerberos-adm': 'kerberos',
    'kerberos': 'kerberos',
    'kerberos_master': 'kerberos',
    'krb_prop': 'kerberos',
    'krbupdate': 'kerberos',
    'kpasswd': 'kerberos'
}

def SafeDataFrame(data=None, *args, **kwargs):
    '''A wrapper around pandas DataFrame so that empty lists still
    return a DataFrame with columns if requested.'''
    if not data:
        data = None
    return DataFrame(data, *args, **kwargs)

class ReportGenerator(object):
    def __init__(self, cyhy_db, scan_db, owner, debug=False,
                 snapshot_id=None, title_date=None, final=False,
                 anonymize=False, encrypt_key=None, log_report=True):
        self.__cyhy_db = cyhy_db
        self.__scan_db = scan_db
        self.__owner = owner
        self.__snapshots = None
        self.__no_history = None # True if only one snapshot
        self.__latest_snapshots = None
        self.__start_time = None
        self.__end_time = None
        self.__results = None # reusable query results
        self.__debug = debug
        self.__snapshot_id = snapshot_id # starting snapshot or None for latest
        self.__title_date = title_date
        self.__draft = not final
        self.__anonymize = anonymize
        self.__encrypt_key = encrypt_key
        self.__report_oid = ObjectId()
        self.__generated_time = utcnow()
        self.__log_report_to_db = log_report

    def __fetch_owner_snapshots(self):
        '''loads snapshots sorted with the most recent first'''
        self.__snapshots = [s for s in
            self.__cyhy_db.SnapshotDoc.find({'owner':self.__owner}).sort([('end_time',-1)]).limit(SNAPSHOT_HISTORY_LIMIT)]
        # if this is a historical report find the correct starting snapshot
        if self.__snapshot_id:
            while self.__snapshot_id != self.__snapshots[0]['_id']:
                self.__snapshots.pop(0)
                if len(self.__snapshots) == 0:
                    raise Exception('Could not find requested snapshot %s for %s' % (self.__snapshot_id, self.__owner))
        self.__no_history = len(self.__snapshots) == 1


    def __fetch_latest_snapshots(self):
        '''returns latest snapshots for all owners'''
        self.__latest_snapshots = [s for s in
            self.__cyhy_db.SnapshotDoc.find({'latest':True})]

    def generate_report(self):
        # get latest snapshots
        self.__fetch_owner_snapshots()
        if len(self.__snapshots) == 0:
            print 'No snapshots found for %s.' % self.__owner
            return

        self.__fetch_latest_snapshots()

        # get start and end time from latest snapshot
        self.__start_time = self.__snapshots[0]['start_time']
        self.__end_time = self.__snapshots[0]['end_time']

        # create a working directory
        original_working_dir = os.getcwdu()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # setup the working directory
        self.__setup_work_directory(temp_working_dir)

        # access database and cache results
        self.__run_queries()

        # store key if present
        owner_key = self.__results['owner'].get('key', None)

        # anonymize data if requested
        if self.__anonymize:
            for t in self.__results['tickets_0'] + self.__results['tickets_1'] + self.__results['recently_detected_closed_tickets'] + self.__results['false_positive_tickets']:
                if t['owner'] == self.__owner:
                    t['owner'] = 'SAMPLE'
                else:
                    t['owner'] = 'SUB_ORG'
            self.__owner = 'SAMPLE'
            self.__snapshots[0]['owner'] = 'SAMPLE'
            self.__results = self.__anonymize_structure(self.__results)
            self.__results['owner']['agency']['name'] = 'Sample Organization'
            self.__results['owner']['agency']['acronym'] = 'SAMPLE'
            # Anonymize the ED 19-01 data, if present
            if 'second_level_domains' in self.__results:
                self.__results['second_level_domains'] = ['example.com']
            if 'certs' in self.__results:
                for d in self.__results['certs']['unexpired_and_recently_expired_certs']:
                    d['subjects'] = ['sample.com']
                    d['pem'] = 'REDACTED'

            tech_poc_count = distro_poc_count = 1
            for contact in self.__results['owner']['agency']['contacts']:
                if contact['type'] == POC_TYPE.TECHNICAL:
                    contact['name'] = 'Technical POC {}'.format(tech_poc_count)
                    contact['email'] = 'tech_poc_{}@sample.org'.format(tech_poc_count)
                    contact['phone'] = '555-555-{}'.format(str(tech_poc_count % 10) * 4)
                    tech_poc_count += 1
                elif contact['type'] == POC_TYPE.DISTRO:
                    contact['name'] = 'Distro POC {}'.format(distro_poc_count)
                    contact['email'] = 'distro_poc_{}@sample.org'.format(distro_poc_count)
                    contact['phone'] = ''
                    distro_poc_count += 1
            self.__log_report_to_db = False         # Don't log anonymous reports to our DB

        # generate derived data for tables
        self.__generate_table_data()

        # generate pdf figures
        self.__generate_figures()

        # generate attachments
        self.__generate_attachments()

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)

        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        # generate report figures + latex
        self.__generate_final_pdf()

        # encrypt if requested and possible
        if self.__encrypt_key != None and owner_key != None:
            self.__encrypt_pdf(REPORT_PDF, ENCRYPTED_REPORT_PDF, self.__encrypt_key, owner_key)
            shutil.move(ENCRYPTED_REPORT_PDF, REPORT_PDF)
            was_encrypted = True
        else:
            was_encrypted = False

        # revert working directory
        os.chdir(original_working_dir)

        # copy report to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            timestamp = self.__end_time.isoformat().replace(':','').split('.')[0]
            dest_filename = 'cyhy-%s-%s.pdf' % (self.__owner, timestamp)
            shutil.move(src_filename, dest_filename)
            shutil.rmtree(temp_working_dir)

        if self.__log_report_to_db:
            # add a doc in reports collection to log that this report was generated
            self.__log_report()

        return was_encrypted, self.__results

    def __setup_work_directory(self, work_dir):
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in (MUSTACHE_FILE, ):
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # copy static assets
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src,dir_dst)


    ###############################################################################
    # Database Access
    ###############################################################################
    def __load_tickets(self, snapshot_oids):
        '''load tickets into memory, and merge some of their latest vulnerability fields.
        These tickets should not be saved back to the database as they are modified in evil ways.'''
        tickets = list(self.__cyhy_db.TicketDoc.find({'source':'nessus', 'snapshots':{'$in':snapshot_oids}, 'false_positive':False}))
        for t in tickets:
            t.connection = None # neuter this monstrosity so it can't be saved (easily)
            try:
                v = t.latest_vuln()
            except VulnScanNotFoundException as e:
                print '\n  Warning (non-fatal): {}'.format(e.message)
                # The vuln_scan has likely been archived; get the vuln_scan _id and time from the
                #   VulnScanNotFoundException and set description and solution to 'Not available'
                v = {'_id':e.vuln_scan_id, 'time':e.vuln_scan_time, 'description':'Not available', 'solution':'Not available'}
            # flatten structure by copying details to ticket root
            t.update(t['details'])
            # copy some parts of vuln into ticket
            t.update({k: v[k] for k in ['description', 'solution']})
            t['last_detected'] = v['time']  # rename latest vuln's 'time' to more useful 'last_detected' in ticket
            t['age'] = (t['last_detected'] - t['time_opened']).days
        return tickets

    def __load_detected_closed_tickets(self, start_date, end_date):
        '''load closed tickets that were detected between start_date and end_date'''
        ss0_owners = [self.__snapshots[0]['owner']] + self.__snapshots[0].get('descendants_included', [])
        # Fetch all tickets that closed after start_date (could potentially have been detected at some point after start_date)
        tickets = list(self.__cyhy_db.TicketDoc.find({'source':'nessus', 'open':False, 'owner':{'$in':ss0_owners}, 'time_closed':{'$gt':start_date}}))
        tix_detected_in_range = list()
        for t in tickets:
            t['last_detected'] = t.last_detection_date
            if t['last_detected'] > start_date and t['last_detected'] <= end_date:  # This is a ticket we want
                t.connection = None                 # neuter ticket so it can't be saved (easily)
                t.update(t['details'])              # flatten structure by copying details to ticket root
                t.pop('events')                     # get rid of events list; it's not needed anymore
                t['age'] = (t['last_detected'] - t['time_opened']).days
                tix_detected_in_range.append(t)
        return tix_detected_in_range

    def __load_false_positive_tickets(self):
        '''load false_positive tickets'''
        ss0_owners = [self.__snapshots[0]['owner']] + self.__snapshots[0].get('descendants_included', [])
        # Fetch all false_positive tickets
        tickets = list(self.__cyhy_db.TicketDoc.find({'source':'nessus', 'false_positive':True, 'owner':{'$in':ss0_owners}}))
        for t in tickets:
            t.connection = None                 # neuter ticket so it can't be saved (easily)
            t.update(t['details'])              # flatten structure by copying details to ticket root
            t['last_detected'] = t.last_detection_date
            t['fp_effective_date'], t['fp_expiration_date'] = t.false_positive_dates
            t['fp_expiration_date'] = t['fp_expiration_date'].replace(hour=0, minute=0, second=0, microsecond=0)  # we only display the date in the report; getting rid of the time makes our sort below more useful
            t['expiring_soon'] = t['fp_expiration_date'] < self.__generated_time + datetime.timedelta(days=FALSE_POSITIVE_EXPIRING_SOON_DAYS)
        tickets.sort(key=lambda t: (t['fp_expiration_date'], -t['severity'], t['time_opened']))
        self.__convert_levels_to_text(tickets, 'severity')
        return tickets

    def __load_ticket_age_data(self, start_date, severity, graph_bucket_cutoff_days):
        tomorrow = self.__generated_time + datetime.timedelta(days=1)
        days_to_graph = pd.to_datetime(pd.date_range(start_date, self.__generated_time), utc=True)
        ss0_owners = [self.__snapshots[0]['owner']] + self.__snapshots[0].get('descendants_included', [])

        # Calculate Buckets
        tix = self.__cyhy_db.TicketDoc.find({'source':'nessus', 'details.severity':severity, 'false_positive':False, 'owner':{'$in':ss0_owners},
                                '$or':[{'time_closed':{'$gte':start_date}}, {'time_closed':None}]},
                                {'_id':False, 'time_opened':True, 'time_closed':True})
        tix = list(tix)
        if len(tix):
            df = DataFrame(tix)
            df.time_closed = df.time_closed.fillna(tomorrow, downcast='infer')  # for accounting purposes, say all open tix will close tomorrow
            # downcast='infer' needed above to avoid "NotImplementedError: reshaping is not supported for Index objects" (pandas 0.19.1)
            df.time_closed = pd.to_datetime(df.time_closed, utc=True)   # convert times to datetime64
            df.time_opened = pd.to_datetime(df.time_opened, utc=True)

            results_df = DataFrame(index=days_to_graph, columns=['young','old','total'])
            old_delta = np.timedelta64(graph_bucket_cutoff_days, 'D')

            for start_of_day, values in results_df.iterrows():
                end_of_day = start_of_day + np.timedelta64(1, 'D') - np.timedelta64(1, 'ns')
                open_on_day_mask = (df.time_opened <= end_of_day) & (df.time_closed > start_of_day)
                age_on_date = start_of_day - df.time_opened
                age_on_date_masked = age_on_date.mask(open_on_day_mask == False)
                values['total'] = open_on_day_mask.value_counts().get(True, 0)
                values['young'] = (age_on_date_masked < old_delta).value_counts().get(True, 0)
                values['old'] = (age_on_date_masked >= old_delta).value_counts().get(True, 0)
            return results_df
        else:
            return DataFrame([])

    def __load_risky_services_tickets(self, snapshot_oid):
        '''load risky services tickets into memory.'''
        tickets = list(self.__cyhy_db.TicketDoc.find(
            {'source': 'nmap',
             'source_id': 1,    # 1 = 'risky service detected'
             'snapshots': snapshot_oid,
             'false_positive': False},
            {'details.service': True,
             'ip': True,
             'ip_int': True,
             'owner': True,
             'port': True,
             'time_opened': True}))
        for t in tickets:
            # Neuter the connection so it can't be saved (easily)
            t.connection = None
            # Move service to main level of ticket
            t['service'] = t['details'].get('service')
            t.pop('details')

            t['category'] = RISKY_SERVICES_MAP.get(t['service'])
            if not self.__no_history:
                previous_snapshot_timestamp = self.__snapshots[1]['end_time']
            t['newly_opened_since_last_report'] = False
            if self.__no_history or t[
              'time_opened'] > previous_snapshot_timestamp:
                t['newly_opened_since_last_report'] = True
        return tickets

    def __risky_services_metrics(self, tickets):
        '''calculate risky service metrics.'''
        risky_service_metrics = {'total_count': 0}
        risky_service_categories = set(RISKY_SERVICES_MAP.values())
        # Initialize risky_service_metrics
        for category in risky_service_categories:
            risky_service_metrics[category] = {
                'count': 0, 'any_newly_opened': False}

        for ticket in tickets:
            category = ticket['category']
            if category in risky_service_categories:
                risky_service_metrics['total_count'] += 1
                risky_service_metrics[category]['count'] += 1
                if ticket['newly_opened_since_last_report']:
                    risky_service_metrics[category]['any_newly_opened'] = True
        return risky_service_metrics

    def __vulnerability_occurrence(self, tickets):
        df = SafeDataFrame(tickets, columns=['cvss_base_score','name','severity'])
        if df.empty:
            return DataFrame(None, columns=['cvss_base_score','plugin_name','severity','count'])
        grouper = df.groupby(['cvss_base_score','name','severity'], as_index=False)
        s = grouper.size()                # works in pandas 0.17.1; in pandas 0.16.2 we did: s = grouper.severity.count()
        df = s.reset_index(name='count')
        df.rename(columns={'name':'plugin_name'}, inplace=True)
        return df

    def __top_risky_hosts(self, tickets):
        df = SafeDataFrame(tickets, columns=['ip','severity','cvss_base_score'])
        df['total'] = 1
        df['low'] = (df['severity'] == 1).astype(int)
        df['medium'] = (df['severity'] == 2).astype(int)
        df['high'] = (df['severity'] == 3).astype(int)
        df['critical'] = (df['severity'] == 4).astype(int)
        df['weighted'] = np.power(df['cvss_base_score'], 7) / np.power(10,6)
        grouper = df.groupby(['ip'], as_index=False)
        df2 = grouper.agg({'total':np.sum, 'low':np.sum, 'medium':np.sum, 'high':np.sum, 'critical':np.sum, 'weighted':np.sum})
        df2.sort_values(by='weighted', ascending=False, inplace=True)
        df2.reset_index(drop=True, inplace=True)
        return df2

    def __vulnerability_density(self, tickets):
        df = DataFrame(tickets)
        if df.empty:
            return Series(index=['1-5','6-9','10+']).fillna(0)
        grouper = df.groupby('ip')
        s1 = grouper.size()
        df2 = s1.reset_index()
        df2.rename(columns={0:'total'}, inplace=True)
        df2['1-5'] = ((df2['total'] >= 1) & (df2['total'] <= 5)).astype(int)
        df2['6-9'] = ((df2['total'] >= 6) & (df2['total'] <= 9)).astype(int)
        df2['10+'] = ((df2['total'] >= 10)).astype(int)
        s2 = df2.sum(numeric_only=True)
        del(s2['total'])
        return s2

    def __run_queries(self):
        '''Run all queries and store results'''
        self.__results = dict()
        ss0_snapshot_oid = self.__snapshots[0]['_id']

        # fetch descendant snapshots of self.__snapshots[0] (if any)
        if self.__snapshots[0].get('descendants_included'):
            self.__results['ss0_descendant_snapshots'] = [s for s in self.__cyhy_db.SnapshotDoc.find({'parents':ss0_snapshot_oid, '_id':{'$ne':ss0_snapshot_oid}}).sort([('owner',1)])]

        self.__results['tickets_0'] = self.__load_tickets([ss0_snapshot_oid])
        self.__results['false_positive_tickets'] = self.__load_false_positive_tickets()

        if self.__no_history:
            self.__results['tickets_1'] = []
            ss1_snapshot_oid = []
            self.__results['recently_detected_closed_tickets'] = self.__load_detected_closed_tickets(self.__snapshots[0]['start_time'], self.__generated_time)
        else:
            ss1_snapshot_oid = self.__snapshots[1]['_id']
            self.__results['tickets_1'] = self.__load_tickets([ss1_snapshot_oid])
            self.__results['recently_detected_closed_tickets'] = self.__load_detected_closed_tickets(self.__snapshots[1]['end_time'], self.__generated_time)

        self.__results['owner'] = self.__cyhy_db.requests.find_one({'_id':self.__owner})
        if self.__cyhy_db.RequestDoc.find_one('EXECUTIVE'):
            self.__results['owner_is_federal_executive'] = self.__owner in self.__cyhy_db.RequestDoc.get_all_descendants('EXECUTIVE')
        else:
            self.__results['owner_is_federal_executive'] = False

        self.__results['risky_services_tickets'] = self.__load_risky_services_tickets(
            ss0_snapshot_oid)
        self.__results['risky_services_metrics'] = self.__risky_services_metrics(
            self.__results['risky_services_tickets'])

        results = database.run_pipeline_cursor(queries.operating_system_count_pl([ss0_snapshot_oid]), self.__cyhy_db)
        database.id_expand(results)
        self.__results['operating_system_count'] = results

        ss0_owners = [self.__snapshots[0]['owner']] + self.__snapshots[0].get('descendants_included', [])
        results = database.run_pipeline_cursor(queries.ip_geoloc_pl(ss0_owners), self.__cyhy_db)
        database.id_expand(results)
        self.__results['ip_geoloc'] = results

        results = database.run_pipeline_cursor(queries.services_attachment_pl([ss0_snapshot_oid]), self.__cyhy_db)
        self.__results['services_attachment'] = results

        ss0_host_scans = list(self.__cyhy_db.host_scans.aggregate([{'$match':{'snapshots':ss0_snapshot_oid}},
                                                              {'$project':{'_id':0, 'owner':1, 'ip_int':1, 'ip':1, 'name':1, 'hostname':1}},
                                                              {'$sort':{'ip_int':1}}], cursor={}, allowDiskUse=True))

        active_host_ip_ints = set(i['_id'] for i in self.__cyhy_db.hosts.find({'state.up':True,
                                                                          'owner':{'$in':ss0_owners}},
                                                                          {'_id':1}))
        self.__results['hosts_attachment'] = [i for i in ss0_host_scans if i['ip_int'] in active_host_ip_ints]

        results = self.__cyhy_db.snapshots.find({'latest':True},{'_id':0, 'owner':1, 'cvss_average_all':1, 'cvss_average_vulnerable':1})
        self.__results['all_cvss_scores'] = [i for i in results]

        results = database.run_pipeline_cursor(queries.host_latest_scan_time_span_pl(ss0_owners), self.__cyhy_db)
        if results:
            if results[0]['start_time'] < self.__snapshots[0]['start_time']:
                self.__results['address_scan_start_date'] = results[0]['start_time']
            else:
                self.__results['address_scan_start_date'] = self.__snapshots[0]['start_time']
            self.__results['address_scan_end_date'] = results[0]['end_time']
        else:
            self.__results['address_scan_start_date'] = self.__snapshots[0]['start_time']
            self.__results['address_scan_end_date'] = self.__snapshots[0]['end_time']

        results = database.run_pipeline_cursor(queries.host_latest_vulnscan_time_span_pl(ss0_owners), self.__cyhy_db)
        if results:
            self.__results['vuln_scan_start_date'] = results[0]['start_time']
            self.__results['vuln_scan_end_date'] = results[0]['end_time']
        else:
            self.__results['vuln_scan_start_date'] = self.__results['vuln_scan_end_date'] = None

        self.__results['earliest_snapshot_start_time'] = list(self.__cyhy_db.SnapshotDoc.collection.find({'owner':{'$in':ss0_owners}}, {'start_time':1}).sort([('start_time',1)]).limit(1))[0]['start_time']

        critical_ticket_date_cutoff = self.__generated_time - datetime.timedelta(days=CRITICAL_AGE_OVER_TIME_CUTOFF_DAYS)
        # If earliest snapshot start_time is more recent than critical_ticket_date_cutoff, use it instead
        if self.__results['earliest_snapshot_start_time'] > critical_ticket_date_cutoff:
            ticket_age_start_date = self.__results['earliest_snapshot_start_time'].replace(tzinfo=tz.tzutc())    # Explicitly set time zone to UTC
        else:
            ticket_age_start_date = critical_ticket_date_cutoff
        self.__results['critical_ticket_age_data'] = self.__load_ticket_age_data(ticket_age_start_date, 4, TICKET_AGE_BUCKET_CUTOFF_DAYS)

        # store descendant data for later
        if self.__results.get('ss0_descendant_snapshots'):
            self.__results['ss0_descendant_data'] = list()
            for snap in self.__results['ss0_descendant_snapshots']:
                address_count = len(snap.networks)
                addresses_scanned_percent = int(safe_percent(snap['addresses_scanned'], address_count, 0))
                vuln_host_percent = int(safe_percent(snap['vulnerable_host_count'], snap['host_count'], 0))
                tix_days_to_close, tix_days_open = self.__vulnerability_mitigation_performance(snap)

                if self.__anonymize:
                    snap['owner'] = 'SUB_ORG'

                self.__results['ss0_descendant_data'].append({'owner':snap['owner'], 'address_count':address_count, 'addresses_scanned':snap['addresses_scanned'], 'addresses_scanned_percent':addresses_scanned_percent, 'host_count':snap['host_count'], 'vulnerable_host_count':snap['vulnerable_host_count'], 'vuln_host_percent':vuln_host_percent, 'vulnerabilities':snap['vulnerabilities'], 'port_count':snap['port_count'], 'tix_days_to_close':tix_days_to_close, 'tix_days_open':tix_days_open})

        # Determine if this org is a suborg.  If an org's snapshot _id
        # IS NOT in its list of parents, then it is a sub-org.
        self.__results['is_suborg'] = not (self.__snapshots[0]['_id'] in self.__snapshots[0]['parents'])

        #
        # Run ED 19-01 queries, but only for Federal executive
        # agencies that are not suborgs.  We exclude suborgs because
        # all domains are associated with the parent org, and hence
        # there is nothing to display for suborgs.
        #
        if self.__results['owner_is_federal_executive'] and not self.__results['is_suborg']:
            certs = {}

            today = self.__generated_time
            seven_days = datetime.timedelta(days=7)
            seven_days_ago = today - seven_days
            seven_days_from_today = today + seven_days
            thirty_days = datetime.timedelta(days=30)
            thirty_days_ago = today - thirty_days
            thirty_days_from_today = today + thirty_days
            start_of_current_fy = report_dates(now=self.__generated_time)['fy_start']

            owner = self.__results['owner']['_id']
            owner_domains_cursor = self.__scan_db.domains.find({
                'agency.id': owner
            }, {
                '_id': True
            })
            self.__results['second_level_domains'] = [
                d['_id'] for d in owner_domains_cursor
            ]

            # Get all certs for this organization that are unexpired
            # or expired in the last 30 days.  This data will be used
            # to generate the CSV attachment.
            certs['unexpired_and_recently_expired_certs'] = list(
                self.__scan_db.certs.find({
                    'trimmed_subjects': {
                        '$in': self.__results['second_level_domains']
                    },
                    'not_after': {
                        '$gte': thirty_days_ago,
                    }
                })
            )

            # Get a count of certs for this organization:
            # * That were issued since the start of the current fiscal year
            # * That were issued in the last 30 days
            # * That were issued in the last 7 days
            # * That are unexpired
            # * That expired in the last seven days
            # * That expire in the next seven days
            # * That expired in the last thirty days
            # * That expire in the next thirty days
            cert_counts_groups = list(self.__scan_db.certs.aggregate([
                {
                    '$match': {
                        'trimmed_subjects': {
                            '$in': self.__results['second_level_domains']
                        }
                    }
                },
                {
                    '$group': {
                        '_id': 'certs_count',
                        'issued_current_fy': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$gte': [
                                            '$sct_or_not_before',
                                            start_of_current_fy
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'issued_in_last_thirty_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$gte': [
                                            '$sct_or_not_before',
                                            thirty_days_ago
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'issued_in_last_seven_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$gte': [
                                            '$sct_or_not_before',
                                            seven_days_ago
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'unexpired': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$gte': [
                                            '$not_after',
                                            today
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'expired_in_last_seven_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$and': [
                                            {
                                                '$gte': [
                                                    '$not_after',
                                                    seven_days_ago
                                                ]
                                            },
                                            {
                                                '$lte': [
                                                    '$not_after',
                                                    today
                                                ]
                                            }
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'expire_in_next_seven_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$and': [
                                            {
                                                '$gte': [
                                                    '$not_after',
                                                    today
                                                ]
                                            },
                                            {
                                                '$lte': [
                                                    '$not_after',
                                                    seven_days_from_today
                                                ]

                                            }
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'expired_in_last_thirty_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$and': [
                                            {
                                                '$gte': [
                                                    '$not_after',
                                                    thirty_days_ago
                                                ]
                                            },
                                            {
                                                '$lte': [
                                                    '$not_after',
                                                    today
                                                ]
                                            }
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        },
                        'expire_in_next_thirty_days': {
                            '$sum': {
                                '$cond': [
                                    {
                                        '$and': [
                                            {
                                                '$gte': [
                                                    '$not_after',
                                                    today
                                                ]
                                            },
                                            {
                                                '$lte': [
                                                    '$not_after',
                                                    thirty_days_from_today
                                                ]
                                            }
                                        ]
                                    },
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                }
            ], cursor={}))

            if len(cert_counts_groups) > 0:
                cert_counts = cert_counts_groups[0]

                # Get a count of all certs issued for this
                # organization since the start of the current fiscal
                # year
                certs['certs_issued_this_fy_count'] = cert_counts['issued_current_fy']

                # Get a count of all certs issued for this
                # organization in the last 30 days
                certs['certs_issued_last_thirty_days_count'] = cert_counts['issued_in_last_thirty_days']

                # Get a count of all certs issued for this
                # organization in the last 7 days
                certs['certs_issued_last_seven_days_count'] = cert_counts['issued_in_last_seven_days']

                # Get a count of all certs for this organization that
                # are unexpired
                certs['unexpired_certs_count'] = cert_counts['unexpired']

                # Get a count of all certs for this organization that
                # expired in the last 7 days
                certs['certs_expired_last_seven_days_count'] = cert_counts['expired_in_last_seven_days']

                # Get a count of all certs for this organization that
                # expire in the next 7 days
                certs['certs_expire_next_seven_days_count'] = cert_counts['expire_in_next_seven_days']

                # Get a count of all certs for this organization that
                # expired in the last 30 days
                certs['certs_expired_last_thirty_days_count'] = cert_counts['expired_in_last_thirty_days']

                # Get a count of all certs for this organization that
                # expire in the next 30 days
                certs['certs_expire_next_thirty_days_count'] = cert_counts['expire_in_next_thirty_days']
            else:
                # Set all counts to zero, since the query found nothing
                certs['certs_issued_this_fy_count'] = 0
                certs['certs_issued_last_thirty_days_count'] = 0
                certs['certs_issued_last_seven_days_count'] = 0
                certs['unexpired_certs_count'] = 0
                certs['certs_expired_last_seven_days_count'] = 0
                certs['certs_expire_next_seven_days_count'] = 0
                certs['certs_expired_last_thirty_days_count'] = 0
                certs['certs_expire_next_thirty_days_count'] = 0

            # Aggregate the unexpired certs for this organization by
            # issuer
            certs['ca_aggregation'] = list(
                self.__scan_db.certs.aggregate([
                    {
                        '$match': {
                            'trimmed_subjects': {
                                '$in': self.__results['second_level_domains']
                            },
                            'not_after': {
                                '$gte': today
                            }
                        }
                    },
	            {
                        '$group': {
                            '_id': {
                                'issuer': '$issuer'
                            },
                            'count': {
                                '$sum': 1
                            }
                        }
                    },
	            {
                        '$sort': {
                            'count': -1
                        }
                    }
	        ], cursor={})
            )

            self.__results['certs'] = certs

    ###############################################################################
    # Figure Generation
    ###############################################################################
    def __generate_figures(self):
        graphs.setup()
        self.__figure_vuln_severity_by_prominence()
        self.__figure_max_age_of_active_criticals()
        self.__figure_max_age_of_active_highs()
        self.__figure_top_five_high_risk_hosts()
        self.__figure_top_five_risk_based_vulnerabilities()
        self.__figure_top_five_vulnerabilities_count()
        self.__figure_vuln_responsiveness_time_to_close()
        self.__figure_vuln_responsiveness_time_open()
        self.__figure_critical_vuln_ages_over_time()
        self.__figure_active_critical_vuln_age_distribution()
        self.__figure_network_map()
        self.__figure_active_vulns_cvss_histogram()
        self.__figure_vulnerability_count_per_host()
        self.__figure_total_vulnerabilities_over_time()
        self.__figure_critical_high_vulns_over_time()
        self.__figure_medium_low_vulns_over_time()
        self.__figure_vulnerable_hosts_over_time()
        self.__figure_distinct_services_over_time()
        self.__figure_distinct_vulns_over_time()

    def __determine_bubble_sizes(self, severities, vuln_counts):
        vulns_sorted = sorted(vuln_counts.items(), key=lambda item: item[1])
        count = 0
        rank = 0
        vulns_ranked = dict()
        previous_value = None

        for severity, num_vulns in vulns_sorted:
            count += 1
            if num_vulns != previous_value:
                rank += count
                previous_value = num_vulns
                count = 0
            vulns_ranked[severity] = rank

        bubble_sizes = list()
        for severity in severities:
            # Magic numbers below are the result of trial and error to get a
            # bubble chart that looks reasonably good and that will never
            # have overlapping bubbles
            bubble_sizes.append(2 * vulns_ranked[severity] + 10)
        return bubble_sizes

    def __figure_vuln_severity_by_prominence(self):
        severities = [i.lower() for i in reversed(SEVERITY_LEVELS[1:])]
        vuln_data = list()
        active_vulns = dict()
        for severity in severities:
            vuln_data.append(
                (
                    self.__snapshots[0]['vulnerabilities'][severity],
                    self.__results['resolved_vulnerability_counts'][severity],
                    self.__results['new_vulnerability_counts'][severity],
                )
            )
            active_vulns[severity] = self.__snapshots[0]['vulnerabilities'][severity]

        bubble_sizes = self.__determine_bubble_sizes(severities, active_vulns)

        bubbles = graphs.MyBubbleChart(
            # Magic numbers below are the result of trial and error to get a
            # bubble chart that looks reasonably good and that will never
            # have overlapping bubbles
            [50, 20, 65, 35],   # Bubble x coordinates
            [80, 55, 45, 20],   # Bubble y coordinates
            bubble_sizes,
            (RC_DARK_RED, RC_ORANGE, RC_LIGHT_BLUE, RC_LIGHT_GREEN),
            [i.upper() for i in severities],
            vuln_data,
            ["RESOLVED", "NEW"])
        bubbles.plot("vuln-severity-by-prominence", size=1.0)

    def __figure_max_age_of_active_criticals(self):
        max_age_criticals = self.__results['ss0_tix_days_open']['critical']['max']
        # 15 days is top end of gauge for Criticals
        gauge = graphs.MyColorGauge(
            "Days", max_age_criticals, 15, RC_LIGHT_RED, RC_DARK_BLUE)
        gauge.plot("max-age-active-criticals", size=0.75)

    def __figure_max_age_of_active_highs(self):
        max_age_highs = self.__results['ss0_tix_days_open']['high']['max']
        # 30 days is top end of gauge for Highs
        gauge = graphs.MyColorGauge(
            "Days", max_age_highs, 30, RC_ORANGE, RC_DARK_BLUE)
        gauge.plot("max-age-active-highs", size=0.75)

    def __figure_top_five_high_risk_hosts(self):
        if self.__results['tickets_0']:
            df = self.__top_risky_hosts(self.__results['tickets_0'])
            df = df[:5] # trim to top 5
            dataLabels = ('Low', 'Medium', 'High', 'Critical')
            bar = graphs.MyStackedBar((df['low'], df['medium'], df['high'], df['critical']), df['ip'], dataLabels)
            bar.plot('top-five-high-risk-hosts', size=0.5)
        else: # no vulnerabilities
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
            message.plot('top-five-high-risk-hosts', size=0.5)

    def __figure_top_five_risk_based_vulnerabilities(self):
        df = self.__vulnerability_occurrence(self.__results['tickets_0'])
        if len(df):
            df['risk'] = np.power(df['cvss_base_score'],8) * df['count']
            df.sort_values(by='risk', ascending=False, inplace=True)
            df = df[:5] # trim to top 5
            df['plugin_name'] = self.__brief(df['plugin_name']) # shorten labels
            series = df.set_index('plugin_name')['count']
            severityLabels = ('Low', 'Medium', 'High', 'Critical')
            bar = graphs.MyBar(series, bigLabels=True, barSeverities=list(df['severity']), legendLabels=severityLabels)
            bar.plot('top-five-risk-based-vulnerabilities', size=0.5)
        else: # no vulnerabilities
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
            message.plot('top-five-risk-based-vulnerabilities', size=0.5)

    def __figure_top_five_vulnerabilities_count(self):
        df = self.__vulnerability_occurrence(self.__results['tickets_0'])
        if len(df):
            df.sort_values(by=['count', 'severity'], ascending=[False, False], inplace=True)
            df = df[:5] # trim to top 5
            df['plugin_name'] = self.__brief(df['plugin_name']) # shorten labels
            series = df.set_index('plugin_name')['count']
            severityLabels = ('Low', 'Medium', 'High', 'Critical')
            bar = graphs.MyBar(series, bigLabels=True, barSeverities=list(df['severity']), legendLabels=severityLabels)
            bar.plot('top-five-vulnerabilities-count', size=0.5)
        else: # no vulnerabilities
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
            message.plot('top-five-vulnerabilities-count', size=0.5)

    def __figure_vuln_responsiveness_time_to_close(self):
        df = DataFrame(self.__results['ss0_tix_days_to_close'])
        if len(df):
            median_days_to_close = df.loc['median']
            tix_closed_after_date = median_days_to_close.pop('tix_closed_after_date')   # Not currently displaying this date
            if median_days_to_close.sum() > 0:
                median_days_to_close = median_days_to_close.rename(lambda x: x.capitalize())
                bar = graphs.MyBar(median_days_to_close, barSeverities=[4,3,2,1])
                bar.plot('vuln-responsiveness-days-to-close', size=0.5)
            else:
                message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS_MITIGATED)
                message.plot('vuln-responsiveness-days-to-close', size=0.5)
        else: # no vuln responsiveness data (older snapshots didn't have this)
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULN_RESPONSIVENESS_DATA)
            message.plot('vuln-responsiveness-days-to-close', size=0.5)

    def __figure_vuln_responsiveness_time_open(self):
        df = DataFrame(self.__results['ss0_tix_days_open'])
        if len(df):
            median_days_open = df.loc['median']
            tix_open_as_of_date = median_days_open.pop('tix_open_as_of_date')           # Not currently displaying this date
            if median_days_open.sum() > 0:
                median_days_open = median_days_open.rename(lambda x: x.capitalize())
                bar = graphs.MyBar(median_days_open, barSeverities=[4,3,2,1])
                bar.plot('vuln-responsiveness-days-open', size=0.5)
            else:
                message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
                message.plot('vuln-responsiveness-days-open', size=0.5)
        else: # no vuln responsiveness data (older snapshots didn't have this)
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULN_RESPONSIVENESS_DATA)
            message.plot('vuln-responsiveness-days-open', size=0.5)

    def __figure_critical_vuln_ages_over_time(self):
        df = self.__results['critical_ticket_age_data']
        if len(df):
            line = graphs.MyStackedLine(df, ylabel='Critical Vulnerabilities', data_labels=['Active Less Than 30 Days', 'Active 30+ Days'], data_fill_colors=['#0099cc', '#cc0000'])
            line.plot('critical-vuln-ages-over-time', size=1.0)
        else:
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_CRITICALS_TO_DISPLAY)
            message.plot('critical-vuln-ages-over-time', size=0.7)

    def __figure_active_critical_vuln_age_distribution(self):
        max_age_cutoff = int(ACTIVE_CRITICAL_AGE_CUTOFF_DAYS)
        age_buckets = list()
        for t in self.__results['tickets_0']:
            if t['severity'] == 4:
                days_open = (self.__generated_time - t['time_opened']).days
                if days_open >= max_age_cutoff:
                    age_buckets.append(max_age_cutoff)
                else:
                    age_buckets.append(days_open)
        if len(age_buckets):
            age_buckets.sort()
            s1 = Series(age_buckets)
            s2 = s1.value_counts().reindex(range(ACTIVE_CRITICAL_AGE_CUTOFF_DAYS+1)).fillna(0)
            region_colors = [(ACTIVE_CRITICAL_AGE_BUCKETS[0][1],'#ffffb2'), (ACTIVE_CRITICAL_AGE_BUCKETS[1][1],'#fecc5c'), (ACTIVE_CRITICAL_AGE_BUCKETS[2][1],'#fd8d3c'), (ACTIVE_CRITICAL_AGE_BUCKETS[3][1],'#f03b20'), (ACTIVE_CRITICAL_AGE_BUCKETS[4][1],'#bd0026')] # Colorize regions
            bar = graphs.MyDistributionBar(s2, xlabel='Age (Days)', ylabel='Critical Vulnerabilities', final_bucket_accumulate=True, x_major_tick_count=10, region_colors=region_colors, x_limit_extra=2)
            bar.plot('active-critical-age-distribution', size=1.0)
            self.__results['active_critical_age_counts'] = s2
        else:
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_CRITICALS)
            message.plot('active-critical-age-distribution', size=0.7)
            self.__results['active_critical_age_counts'] = Series().reindex(range(ACTIVE_CRITICAL_AGE_CUTOFF_DAYS+1)).fillna(0)

    def __figure_network_map(self):
        results = self.__results['ip_geoloc']
        locs = [i['loc'] for i in results]
        host_map = graphs.MyMap(locs)
        host_map.plot('network-map')

    def __figure_vulnerability_count_per_host(self):
        if len(self.__results['tickets_0']):
            s = self.__vulnerability_density(self.__results['tickets_0'])
            bar = graphs.MyBar(s)
            bar.plot('vulnerability-count-per-host', size=0.3)
        else:
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
            message.plot('vulnerability-count-per-host', size=0.4)

    def __figure_active_vulns_cvss_histogram(self):
        df = DataFrame(self.__results['tickets_0'])
        if len(df):
            cvss_histogram_data = np.histogram(df['cvss_base_score'], range=(0.0, 10.0), bins=20)
            bar_colors = [BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, YELLOW, YELLOW, YELLOW, YELLOW, YELLOW, YELLOW, ORANGE, ORANGE, ORANGE, ORANGE, ORANGE, RED]
            tick_colors = [BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, BLUE, YELLOW, YELLOW, YELLOW, YELLOW, YELLOW, YELLOW, ORANGE, ORANGE, ORANGE, ORANGE, ORANGE, ORANGE, RED]
            hist = graphs.Histogram2(cvss_histogram_data, bar_colors, tick_colors, x_label='CVSS', y_label='Active Vulnerabilities')
            hist.plot('active-vulns-cvss-histogram')
        else:
            message = graphs.MyMessage(OMITTED_MESSAGE_NO_VULNS)
            message.plot('active-vulns-cvss-histogram', size=0.5)

    def __figure_total_vulnerabilities_over_time(self):
        d1 = dict([(i['end_time'],i['vulnerabilities']) for i in self.__snapshots])
        data = DataFrame(d1).T.reindex_axis(['total'], axis=1) #reorder and filter
        data.columns = [i.title() for i in data.columns]
        line = graphs.MyLine(data, linecolors=(BLACK, BLACK), yscale=self.__best_scale(data), ylabel='Vulnerabilities')
        line.plot('total-vulnerabilities-over-time', figsize=(8,2.7))

    def __figure_critical_high_vulns_over_time(self):
        d1 = dict([(i['end_time'],i['vulnerabilities']) for i in self.__snapshots])
        data = DataFrame(d1).T.reindex_axis(['critical','high'], axis=1) #reorder and filter
        data.columns = [i.title() for i in data.columns]
        line = graphs.MyLine(data, linecolors=(RED, ORANGE), yscale=self.__best_scale(data), ylabel='Vulnerabilities')
        line.plot('vulns-over-time-critical-high', figsize=(8,2.7))

    def __figure_medium_low_vulns_over_time(self):
        d1 = dict([(i['end_time'],i['vulnerabilities']) for i in self.__snapshots])
        data = DataFrame(d1).T.reindex_axis(['medium','low'], axis=1) #reorder and filter
        data.columns = [i.title() for i in data.columns]
        line = graphs.MyLine(data, linecolors=(YELLOW, BLUE), yscale=self.__best_scale(data), ylabel='Vulnerabilities')
        line.plot('vulns-over-time-medium-low', figsize=(8,2.7))

    def __figure_vulnerable_hosts_over_time(self):
        source_dict = dict()
        for ss in self.__snapshots:
            d = dict()
            d['Hosts'] = ss['host_count']
            d['Vulnerable Hosts'] = ss['vulnerable_host_count']
            source_dict[ss['end_time']] = d
        df = DataFrame(source_dict).T
        line = graphs.MyLine(df, linecolors=(BLUE, RED), yscale=self.__best_scale(df), ylabel='Hosts')
        line.plot('vulnerable-hosts-over-time', figsize=(8,2.7))

    def __figure_distinct_services_over_time(self):
        source_dict = dict()
        for ss in self.__snapshots:
            d = dict()
            d['Distinct Services'] = len(ss['services'])
            source_dict[ss['end_time']] = d
        df = DataFrame(source_dict).T
        line = graphs.MyLine(df, linecolors=(BLUE, BLUE), yscale=self.__best_scale(df), ylabel='Services')
        line.plot('distinct-services-over-time', figsize=(8,2.7))

    def __figure_distinct_vulns_over_time(self):
        source_dict = dict()
        for ss in self.__snapshots:
            d = dict()
            d['Distinct Vulnerabilities'] = ss['unique_vulnerabilities']['total']
            source_dict[ss['end_time']] = d
        df = DataFrame(source_dict).T
        line = graphs.MyLine(df, linecolors=(BLACK, BLACK), yscale=self.__best_scale(df), ylabel='Vulnerabilities')
        line.plot('distinct-vulns-over-time', figsize=(8,2.7))


    ###############################################################################
    # Utilities
    ###############################################################################

    def __anonymize_structure(self, data):
        if isinstance(data, basestring):
            return re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, data)
        elif isinstance(data, IPAddress):
            return re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, str(data))
        elif isinstance(data, dict):
            new_dict = dict()
            for k,v in data.items():
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
        return ''.join([LATEX_ESCAPE_MAP.get(i,i) for i in to_escape])

    def __latex_escape_structure_make_cve_urls(self, data):
        '''assumes that all sequences contain dicts'''
        if isinstance(data, dict):
            for k,v in data.items():
                if k.endswith('_tex'): # skip special tex values
                    continue
                if isinstance(v, basestring):
                    data[k] = self.__latex_escape(v)
                    cve_ids = set(re.findall(CVE_ID_RE, v))     # Search for strings like 'CVE-####-#######'
                    if cve_ids:
                        for cve in cve_ids:                     # LaTeX href format:  \href{<URL>}{<Link text>}
                            data[k] = data[k].replace(cve, '\href{'+CVE_URL.format(cve)+'}{'+cve+'}')
                else:
                    self.__latex_escape_structure_make_cve_urls(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure_make_cve_urls(i)

    def __latex_convert_cve_to_url(self, data):
        '''assumes that all sequences contain dicts'''
        if isinstance(data, dict):
            for k,v in data.items():
                if k.endswith('_tex'): # skip special tex values
                    continue
                if isinstance(v, basestring):
                    cve_ids = set(re.findall(CVE_ID_RE, v))
                    if cve_ids:
                        for cve in cve_ids:     # LaTeX href format:  \href{https://www.dhs.gov}{https://www.dhs.gov}
                            data[k] = data[k].replace(cve, '\href{'+CVE_URL.format(cve)+'}{'+cve+'}')
                else:
                    self.__latex_convert_cve_to_url(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_convert_cve_to_url(i)

    def led(self, data):
        self.__latex_escape_dict(data)

    def __convert_levels_to_text(self, data, field):
        for row in data:
            row[field] = SEVERITY_LEVELS[int(row[field])]

    def __level_keys_to_text(self, data, lowercase=False):
        result = {}
        for k,v in data.items():
            if lowercase:
                new_key = SEVERITY_LEVELS[k].lower()
            else:
                new_key = SEVERITY_LEVELS[k]
            result[new_key] = v
        return result

    def __join_lists(self, data, field, joiner, sort):
        for row in data:
            if type(row[field]) == set:         # handle sets
                row[field] = list(row[field])
            if sort:
                row[field].sort()
            row[field] = joiner.join([str(i) for i in row[field]])

    def __replace_infinities(self, data, field, replacement):
        for row in data:
            if np.isinf(row[field]):
                row[field] = replacement

    def __dataframe_to_dicts(self, df, keep_index=False):
        df2 = df.reset_index().T.to_dict()
        result = df2.values()
        if not keep_index:
            for i in result:
                del(i['index'])
        return result

    def __percent_change(self, previous, current):
        if previous == 0:
            return '-'
        change = 100 * current / previous - 100
        change = round(change, 1)
        return change

    def __to_oxford_list(self, items, verb_single='', verb_muliple=''):
        if len(items) == 0:
            return None
        if len(items) == 1:
            return items[0] + verb_single
        if len(items) == 2:
            return '%s and %s%s' % (items[0], items[-1], verb_muliple)
        return ', '.join(items[:-1]) + ', and ' + items[-1] + verb_muliple

    def __udf_calc(self, preposition, v1, v2):
        if v2 > v1:
            return {'%s_up' % preposition : (v2-v1), '%s_up_flag' % preposition : True}
        if v1 > v2:
            return {'%s_down' % preposition : (v1-v2), '%s_down_flag' % preposition : True}
        assert v1 == v2, 'Glitch in the matrix!  Expected values to be equal.  Something has changed!'
        return {'%s_flat' % preposition : v1, '%s_flat_flag' % preposition : True}

    def __best_scale(self, df):
        '''determine of a line chart scale should be log or linear'''
        de = df.describe().T
        diff = de['mean'] - de['50%']
        max_diff = max(abs(diff))
        if max_diff > 1000:
            return 'log'
        else:
            return 'linear'

    def __brief(self, labels):
        '''shrink labels for a pie chart'''
        results = list()
        for label in labels:
            label = label.replace('_',' ').strip()
            results.append(' '.join(label.split()[:5]))
        return results

    ###############################################################################
    # Table Generation
    ###############################################################################
    def __generate_table_data(self):
        self.__calc_vuln_mitigation_perf_for_all_snapshots()
        self.__table_vulnerabilities_by_severity()
        self.__table_top_operating_systems()
        self.__table_top_services()
        self.__table_vulnerability_occurrence()
        self.__table_vulnerability_deltas()
        self.__table_new_and_redetected_vulns()
        self.__table_recently_detected_vulns()
        self.__table_top_common_services()
        self.__table_vulnerability_history()
        self.__table_detailed_findings()
        self.__table_mitigations()
        self.__risk_rating_system()

    def __vulnerability_mitigation_performance(self, snapshot):
        MSEC_IN_A_DAY = 1000 * 60 * 60 * 24
        tix_days_to_close = OrderedDict()
        tix_days_open = OrderedDict()
        for severity in ['critical', 'high', 'medium', 'low']:
            tix_days_to_close[severity] = dict()
            tix_days_open[severity] = dict()
        tix_msec_to_close = snapshot.get('tix_msec_to_close')
        tix_msec_open = snapshot.get('tix_msec_open')
        if tix_msec_to_close:
            tix_days_open['tix_open_as_of_date'] = tix_msec_open['tix_open_as_of_date']
            if self.__results['earliest_snapshot_start_time'] > tix_msec_to_close['tix_closed_after_date']:
                tix_days_to_close['tix_closed_after_date'] = self.__results['earliest_snapshot_start_time']
            else:
                tix_days_to_close['tix_closed_after_date'] = tix_msec_to_close['tix_closed_after_date']
            for severity in ['critical', 'high', 'medium', 'low']:
                for metric in ['median', 'max']:
                    if tix_msec_to_close[severity][metric]:
                        tix_days_to_close[severity][metric] = int(safe_divide(tix_msec_to_close[severity][metric], MSEC_IN_A_DAY, precision=0))
                    else:
                        tix_days_to_close[severity][metric] = 0

                    if tix_msec_open[severity][metric]:
                        tix_days_open[severity][metric] = int(safe_divide(tix_msec_open[severity][metric], MSEC_IN_A_DAY, precision=0))
                    else:
                        tix_days_open[severity][metric] = 0
        else:   # Older snapshots (before CYHY-145) don't have 'tix_msec_to_close' or 'tix_msec_open'
            tix_days_to_close = None
            tix_days_open = None
        return tix_days_to_close, tix_days_open

    def __calc_vuln_mitigation_perf_for_all_snapshots(self):
        for snap in self.__snapshots:
            snap['tix_days_to_close'], snap['tix_days_open'] = self.__vulnerability_mitigation_performance(snap)
        self.__results['ss0_tix_days_to_close'] = self.__snapshots[0]['tix_days_to_close']
        self.__results['ss0_tix_days_open'] = self.__snapshots[0]['tix_days_open']

    def __table_vulnerabilities_by_severity(self):
        ss0 = self.__snapshots[0]
        for sev,count in dict(ss0['unique_vulnerabilities']).iteritems():
            ss0['unique_vulnerabilities'][sev+'_pct'] = int(safe_percent(ss0['unique_vulnerabilities'][sev], ss0['unique_vulnerabilities']['total'], precision=0))
        for sev,count in dict(ss0['vulnerabilities']).iteritems():
            ss0['vulnerabilities'][sev+'_pct'] = int(safe_percent(ss0['vulnerabilities'][sev], ss0['vulnerabilities']['total'], precision=0))

    def __table_top_operating_systems(self):
        # Hard-coded to output top 5
        results = self.__results['operating_system_count']
        df = DataFrame(results)
        if len(df) > 0:
            df['percent'] = df['count'] / float(np.sum(df['count'])) * 100
            other_count = np.sum(df[5:]['count'])
            other_percent = np.sum(df[5:]['percent'])
            df = df[:5] # trim to top 5
            if other_count > 0:
                df_other = DataFrame({'count':other_count, 'operating_system':'Other', 'percent':other_percent}, index=[0])
                df = df.append(df_other, ignore_index=True)
            df['percent'] = df['percent'].round(1)      # round to 1 decimal place
            self.__results['top_operating_systems'] = self.__dataframe_to_dicts(df)
        else:
            self.__results['top_operating_systems'] = None

    def __table_top_services(self):
        # Hard-coded to output top 5
        ss0 = self.__snapshots[0]
        df = DataFrame.from_dict(ss0['services'], orient='index')
        if len(df) > 0:
            df = df.reset_index().rename(columns={'index':'service_name',0:'count'})
            df['percent'] = df['count'] / float(np.sum(df['count'])) * 100
            other_count = np.sum(df[5:]['count'])
            other_percent = np.sum(df[5:]['percent'])
            df = df[:5] # trim to top 5
            df.sort_values(by='count', ascending=False, inplace=True)
            if other_count > 0:
                df_other = DataFrame({'count':other_count, 'service_name':'Other', 'percent':other_percent}, index=[0])
                df = df.append(df_other, ignore_index=True)
            df['percent'] = df['percent'].round(1)      # round to 1 decimal place
            self.__results['top_services'] = self.__dataframe_to_dicts(df)
        else:
            self.__results['top_services'] = None

    def __table_vulnerability_occurrence(self):
        df = self.__vulnerability_occurrence(self.__results['tickets_0'])
        if len(df): # handle no vulnerabilties
            df.sort_values(by=['cvss_base_score','count','plugin_name'], ascending=[0,0,1], inplace=True)
        d = self.__dataframe_to_dicts(df)
        d = d[:10]
        self.__convert_levels_to_text(d, 'severity')
        self.__results['top_10_vulnerability_occurrence'] = d

    def __table_top_common_services(self):
        s0 = Series(self.__snapshots[0]['services'])
        if self.__no_history:
            s1 = Series()  # no history, create an empty Series
        else:
            s1 = Series(self.__snapshots[1]['services'])
        static = DataFrame({'static':1}, index=STATIC_SERVICES)
        all_ch = DataFrame([i['services'] for i in self.__latest_snapshots])
        all_ch_sum = all_ch.apply(np.sum) # services:count
        all_ch_total = all_ch_sum.sum() # total services
        all_ch_average_percent = all_ch_sum / float(all_ch_total) * 100
        dfservices = DataFrame({'s0':s0, 's1':s1, 'ch':all_ch_sum})
        dfservices = pd.merge(static, dfservices, left_index=True, right_index=True, how='outer')
        dfservices = dfservices.fillna(0).astype(np.int)
        dfservices_sum = dfservices.sum()
        #TODO make sure this isn't breaking anything, and make more general
        #this prevents divisions by zero
        if dfservices_sum['s1'] == 0:
            dfservices_sum['s1'] += 1
        percents = dfservices.astype(np.float) / dfservices_sum.astype(np.float) * 100
        percents = np.round(percents, 1)
        df = pd.merge(dfservices, percents, left_index=True, right_index=True, how='outer', suffixes=['','_percent'])
        df.sort_values(by=['static','s0'], ascending=False, inplace=True)
        df_static = df[df['static'] == 1]
        df_other = df[(df['static'] == 0) & (df['s0'] > 0)][:3]
        d_static = self.__dataframe_to_dicts(df_static, keep_index=True)
        d_other = self.__dataframe_to_dicts(df_other, keep_index=True)
        self.__results['top_common_services_static'] = d_static
        self.__results['top_common_services_other'] = d_other

    def __table_vulnerability_history(self):
        df0 = self.__vulnerability_occurrence(self.__results['tickets_0'])
        df1 = self.__vulnerability_occurrence(self.__results['tickets_1'])
        df = pd.merge(df0, df1, how='outer', on=['plugin_name','cvss_base_score', 'severity'], suffixes=('_0','_1'))
        df['count_0'] = df['count_0'].apply(np.float64)
        df['count_1'] = df['count_1'].apply(np.float64)
        df = df.fillna(0)
        df['percent_change'] = (df['count_0'] - df['count_1']) / df['count_1'] * 100
        df['percent_change'] = np.round(df['percent_change'], 1)
        df['count_0'] = df['count_0'].apply(np.int)
        df['count_1'] = df['count_1'].apply(np.int)
        df['severity'] = df['severity'].apply(np.int)
        df.sort_values(by=['severity','percent_change'], ascending=[0,0], inplace=True)
        d = self.__dataframe_to_dicts(df)
        self.__convert_levels_to_text(d, 'severity')
        self.__replace_infinities(d, 'percent_change', '-')
        self.__results['vulnerability_history'] = d

    def __table_vulnerability_deltas(self):
        df0 = SafeDataFrame(self.__results['tickets_0'], columns=['owner', 'cvss_base_score', 'ip', 'name', 'port', 'severity', 'time_opened', 'time_closed', 'last_detected', 'age'])
        df0.rename(columns={'name':'plugin_name'}, inplace=True)
        df0.sort_values(by='cvss_base_score', ascending=False, inplace=True)
        if self.__results['tickets_1']:
            df1 = DataFrame(self.__results['tickets_1'], columns=['owner', 'cvss_base_score', 'ip', 'name', 'port', 'severity', 'time_opened', 'time_closed', 'last_detected', 'age'])
        else:
            df1 = DataFrame(None, columns=['owner', 'cvss_base_score', 'ip', 'name', 'port', 'severity', 'time_opened', 'time_closed', 'last_detected', 'age'])

        df1.rename(columns={'name':'plugin_name'}, inplace=True)
        df1.sort_values(by='cvss_base_score', ascending=False, inplace=True)

        # NOTE: Issues arise if tickets that were closed (i.e. aren't in df1) have re-opened at the time of report generation
        #  This can result in incorrect counts of Resolved vulns (not handled) and missing 'time_closed' dates (handled with 'NA' in output)
        # WORKAROUND: Ensure all reports are generated shortly after their snapshots are taken.

        # Ideally, we would want to create df0, df1 with dtype 'datetime64[ns, UTC]'
        #  for the 3 time columns, but there's a pandas bug...
        #  See https://github.com/pandas-dev/pandas/issues/12513

        NULL_TIMESTAMP = pd.Timestamp('1970-01-01 00:00:00.000+0000')
        for df in (df0, df1):
            # Without the fillna below, the groupby will drop rows where time_closed is None (NaT)
            df['time_closed'].fillna(NULL_TIMESTAMP, inplace=True, downcast='infer')    # This changes 'time_closed' dtype to object; downcast='infer' needed to avoid "NotImplementedError: reshaping is not supported for Index objects" (pandas 0.19.1)
            for col in ('time_opened', 'time_closed', 'last_detected'):
                df[col] = pd.to_datetime(df[col], utc=True)     # Convert column to pandas Timestamp (datetime64[ns, UTC] or datetime64[ns])
                if str(df[col].dtype) != 'datetime64[ns, UTC]': # In some cases, 'time_closed' will already be localized to UTC (i.e. when initial df['time_closed'] had no 'None' values)
                    df[col] = df[col].dt.tz_localize('UTC')     # Localize to UTC time zone (dtype: 'datetime64[ns, UTC]'), since fillna above removed tz info

        counts_0 = Series()
        if len(df0):
            counts_0 = df0.groupby(['owner', 'plugin_name', 'ip', 'port', 'severity', 'time_opened', 'time_closed', 'last_detected', 'age']).size()

        counts_1 = Series()
        if len(df1):
            counts_1 = df1.groupby(['owner', 'plugin_name', 'ip', 'port', 'severity', 'time_opened', 'time_closed', 'last_detected', 'age']).size()

        # Calculate New Vulnerabilities (tickets present in current snapshot that weren't present in last snapshot)
        s_new = counts_1.reindex_like(counts_0)
        s_new = s_new[np.isnan(s_new)]
        if len(s_new) == 0:
            index_natives = None # DataFrame interprets [] as (0,0) dimensions which will conflict with columns
        else:
            index_natives = s_new.index.tolist()
        df_new = DataFrame(index_natives, columns=['owner','plugin_name','ip','port','severity','time_opened','time_closed','last_detected', 'age'])
        df_new.drop('time_closed',axis=1,inplace=True)      # New tickets don't have time_closed, so drop it
        df_new.sort_values(by=['severity','plugin_name'], ascending=[False, True], inplace=True)
        d_new_vulns = self.__dataframe_to_dicts(df_new)
        self.__convert_levels_to_text(d_new_vulns, 'severity')

        # Calculate Resolved Vulnerabilities (tickets present in last snapshot that aren't present in current snapshot)
        s_resolved = counts_0.reindex_like(counts_1)
        s_resolved = s_resolved[np.isnan(s_resolved)]
        if len(s_resolved) == 0:
            index_natives = None # DataFrame interprets [] as (0,0) dimensions which will conflict with columns
        else:
            index_natives = s_resolved.index.tolist()
        df_resolved = DataFrame(index_natives, columns=['owner','plugin_name','ip','port','severity','time_opened','time_closed','last_detected', 'age'])

        # Handle (hopefully rare) case where vulns are resolved (according to snapshot), but have since re-opened, so time_closed is None
        no_time_closed_mask = df_resolved['time_closed'] != NULL_TIMESTAMP  # Mask for NULL_TIMESTAMP values set by fillna above
        df_resolved['time_closed'].where(no_time_closed_mask, None, inplace=True)   # NULL_TIMESTAMPs changed back to NaT (Not a Time)
        df_resolved.sort_values(by=['severity','plugin_name'], ascending=[False, True], inplace=True)

        if len(df_resolved):
            df_resolved['days_to_close'] = (df_resolved['time_closed'] - df_resolved['time_opened']) / pd.Timedelta(days=1)
        d_resolved_vulns = self.__dataframe_to_dicts(df_resolved)
        self.__convert_levels_to_text(d_resolved_vulns, 'severity')

        # Calculate New Vulnerability Counts
        new_counts = Series([0,0,0,0])
        if len(df_new):
            new_counts = df_new.groupby('severity').size() # get counts of each severity
        new_counts = new_counts.reindex_axis([4,3,2,1]).fillna(0)
        new_counts = new_counts.apply(np.int)
        d_new_counts = new_counts.to_dict()
        d_new_counts = self.__level_keys_to_text(d_new_counts, lowercase=True)

        # Calculate Resolved Vulnerability Counts
        resolved_counts = Series([0,0,0,0])
        if len(df_resolved):
            resolved_counts = df_resolved.groupby('severity').size() # get counts of each severity
        resolved_counts = resolved_counts.reindex_axis([4,3,2,1]).fillna(0)
        resolved_counts = resolved_counts.apply(np.int)
        d_resolved_counts = resolved_counts.to_dict()
        d_resolved_counts = self.__level_keys_to_text(d_resolved_counts, lowercase=True)

        self.__results['new_vulnerabilities'] = d_new_vulns
        self.__results['new_vulnerability_counts'] = d_new_counts
        self.__results['resolved_vulnerabilities'] = d_resolved_vulns
        self.__results['resolved_vulnerability_counts'] = d_resolved_counts

    def __table_new_and_redetected_vulns(self):
        '''Split up 'new_vulnerabilities' (tickets in current snapshot that weren't in previous snapshot) into
           'brand_new_vulnerabilities' (first detected after previous snapshot end_time) and
           'redetected_vulnerabilities' (first detected before previous snapshot end_time) '''
        self.__results['brand_new_vulnerabilities'] = list()
        self.__results['redetected_vulnerabilities'] = list()
        if self.__no_history:
            self.__results['brand_new_vulnerabilities'] = self.__results['new_vulnerabilities'] # Everything must be "brand new" in this case
        else:
            for t in self.__results['new_vulnerabilities']:
                # Only "brand new" if opened after the previous snapshot end_time
                if t['time_opened'] > self.__snapshots[1]['end_time'].replace(tzinfo=tz.tzutc()):   # Explicitly set time zone to UTC
                    self.__results['brand_new_vulnerabilities'].append(t)
                else:
                    self.__results['redetected_vulnerabilities'].append(t)

    def __table_recently_detected_vulns(self):
        df = SafeDataFrame(self.__results['recently_detected_closed_tickets'], columns=['owner', 'name', 'cve', 'severity', 'ip', 'port', 'time_opened', 'last_detected', 'age'])
        for col in ('time_opened', 'last_detected'):
            df[col] = pd.to_datetime(df[col], utc=True)
        df.sort_values(by=['severity', 'time_opened'], ascending=[0,1], inplace=True)
        d = self.__dataframe_to_dicts(df)
        self.__convert_levels_to_text(d, 'severity')
        self.__results['recently_detected_closed_tickets'] = d

    def __table_detailed_findings(self):
        df = SafeDataFrame(self.__results['tickets_0'], columns=['name', 'description', 'severity', 'cvss_base_score', 'solution', 'ip', 'time_opened', 'last_detected'])
        if df.empty:
            self.__results['detailed_findings'] = []
            return
        for col in ('time_opened', 'last_detected'):
            df[col] = pd.to_datetime(df[col], utc=True)
        grouper = df.groupby(['name', 'description', 'severity', 'cvss_base_score', 'solution'])
        grouped_series = grouper['ip'].apply(set)               # create sets of IPs (avoids duplicate IPs)
        initial_detection = grouper['time_opened'].min()     # get earliest initial detection
        latest_detection = grouper['last_detected'].max()   # get most-recent detection
        df2 = grouped_series.reset_index() # convert series back to a DataFrame
        df2['first_detected'] = initial_detection.reset_index()['time_opened']
        df2['last_detected'] = latest_detection.reset_index()['last_detected']
        df2.sort_values(by=['severity', 'cvss_base_score'], ascending=[0,0], inplace=True)
        df2.rename(columns={'ip':'addresses', 'name':'plugin_name'}, inplace=True)
        df2['addresses_count'] = df2['addresses'].apply(lambda x: len(x))
        d = self.__dataframe_to_dicts(df2)
        self.__convert_levels_to_text(d, 'severity')
        self.__join_lists(d, 'addresses', ', ', True)
        self.__results['detailed_findings'] = d

    def __table_mitigations(self):
        df = SafeDataFrame(self.__results['tickets_0'], columns=['owner', 'name', 'severity', 'solution', 'ip', 'port', 'age'])
        df = df[df['severity'] >= 3]
        if df.empty:
            self.__results['mitigations'] = []
            return
        grouper = df.groupby(['owner', 'name', 'severity', 'solution', 'ip', 'age'])
        grouped_series = grouper['port'].apply(list) # create lists of ports
        df2 = grouped_series.reset_index() # convert series back to a DataFrame
        df2.rename(columns={'port':'ports', 'name':'plugin_name'}, inplace=True)
        df2.sort_values(by=['severity', 'plugin_name', 'ip'], ascending=[0,1,1], inplace=True)
        d = self.__dataframe_to_dicts(df2)
        self.__convert_levels_to_text(d, 'severity')
        self.__join_lists(d, 'ports', ', ', True)
        self.__results['mitigations'] = d

    def __risk_rating_system(self):
        df = DataFrame(index=range(1,11), columns=['weighted', 'equivalent'])
        df['weighted'] = np.power(df.index, 7).astype(float) / np.power(10,6)
        df['equivalent'] = 10 / df['weighted']
        df['equivalent']= df['equivalent'].apply(np.round,decimals=2)
        d = self.__dataframe_to_dicts(df, keep_index=True)
        self.__results['risk_rating_system'] =  d


    ###############################################################################
    #  Attachment Generation
    ###############################################################################
    def __generate_attachments(self):
        self.__generate_certificate_attachment()
        self.__generate_domains_attachment()
        self.__generate_findings_attachment()
        self.__generate_mitigated_vulns_attachment()
        self.__generate_recently_detected_vulns_attachment()
        self.__generate_services_attachment()
        self.__generate_risky_services_attachment()
        self.__generate_hosts_attachment()
        self.__generate_scope_attachment()
        self.__generate_false_positives_attachment()
        self.__generate_sub_org_summary_attachment()
        self.__generate_days_to_mitigate_attachment()
        self.__generate_days_currently_active_attachment()

    def __generate_certificate_attachment(self):
        # No need to do anything if no certs data was collected.  In
        # that case this either isn't a federal executive agency or is
        # a suborg of a federal agency, and hence the attachment won't
        # be used
        if 'certs' in self.__results:
            fields = (
                'Date Cert Appeared in Logs',
                'Subjects',
                'Issuer',
                'Not Valid Before',
                'Not Valid After',
                'Expired',
                'Expiring in Next 7 Days',
                'Expiring in Next 30 Days',
                'Days Until Expiration',
                'Certificate Lifetime in Days',
                'Serial Number',
                'Issued in Last 7 Days',
                'Issued in Last 30 Days',
                'Issued Current Fiscal Year',
                'Certificate'
            )

            today = self.__generated_time
            seven_days = datetime.timedelta(days=7)
            seven_days_ago = today - seven_days
            seven_days_from_today = today + seven_days
            thirty_days = datetime.timedelta(days=30)
            thirty_days_ago = today - thirty_days
            thirty_days_from_today = today + thirty_days
            start_of_current_fy = report_dates(now=self.__generated_time)['fy_start']
            data = self.__results['certs']['unexpired_and_recently_expired_certs']

            with open('certificates.csv', 'wb') as f:
                # We're carefully controlling the fields, so if an
                # unknown field appears it indicates an error
                # (probably a typo).  That's why we're using
                # extrasaction='raise' here.
                writer = DictWriter(f, fields, extrasaction='raise')
                writer.writeheader()
                for d in data:
                    not_after = d['not_after'].replace(tzinfo=today.tzinfo)
                    expired = not_after <= today
                    expiring_in_next_seven_days = (not expired) and (not_after <= seven_days_from_today)
                    expiring_in_next_thirty_days = (not expired) and (not_after <= thirty_days_from_today)
                    issued = d['sct_or_not_before'].replace(tzinfo=today.tzinfo)
                    issued_this_fy = issued >= start_of_current_fy
                    issued_last_thirty_days = issued >= thirty_days_ago
                    issued_last_seven_days = issued >= seven_days_ago

                    row = {
                        'Date Cert Appeared in Logs': issued,
                        'Subjects': ','.join(d['subjects']),
                        'Issuer': d['issuer'],
                        'Not Valid Before': d['not_before'].replace(tzinfo=today.tzinfo),
                        'Not Valid After': not_after,
                        'Expired': expired,
                        'Expiring in Next 7 Days': expiring_in_next_seven_days,
                        'Expiring in Next 30 Days': expiring_in_next_thirty_days,
                        'Days Until Expiration': (not_after - today).days,
                        'Certificate Lifetime in Days': (not_after - d['not_before']).days,
                        'Issued Current Fiscal Year': issued_this_fy,
                        'Serial Number': d['serial'],
                        'Issued in Last 30 Days': issued_last_thirty_days,
                        'Issued in Last 7 Days': issued_last_seven_days,
                        'Certificate': d['pem']
                    }
                    writer.writerow(row)

    def __generate_domains_attachment(self):
        # No need to do anything if no second level domains data was
        # collected.  In that case this either isn't a federal
        # executive agency or is a suborg of a federal agency, and
        # hence the attachment won't be used.
        if 'second_level_domains' in self.__results:
            data = self.__results['second_level_domains']

            with open('domains.csv', 'wb') as f:
                writer = csv.writer(f)
                for d in data:
                    writer.writerow([d])

    def __generate_findings_attachment(self):
        # remove ip_int column if we are trying to be anonymous
        if self.__anonymize:
            header_fields = ('ip', 'port', 'severity', 'initial_detection', 'latest_detection', 'age_days',
                             'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'plugin_id')
            data_fields = ('ip', 'port', 'severity', 'time_opened', 'last_detected', 'age',
                           'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'source_id')
        else:
            if self.__snapshots[0].get('descendants_included'):
                header_fields = ('owner', 'ip_int', 'ip', 'port', 'severity', 'initial_detection', 'latest_detection', 'age_days',
                                 'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'plugin_id')
                data_fields = ('owner', 'ip_int', 'ip', 'port', 'severity', 'time_opened', 'last_detected', 'age',
                               'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'source_id')
            else:
                header_fields = ('ip_int', 'ip', 'port', 'severity', 'initial_detection', 'latest_detection', 'age_days',
                                 'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'plugin_id')
                data_fields = ('ip_int', 'ip', 'port', 'severity', 'time_opened', 'last_detected', 'age',
                               'cvss_base_score', 'cve', 'name', 'description', 'solution', 'source', 'source_id')
        data = self.__results['tickets_0']
        with open('findings.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for row in data:
                data_writer.writerow(row)

    def __generate_mitigated_vulns_attachment(self):
        if self.__snapshots[0].get('descendants_included'):
            header_fields = ('owner', 'vulnerability', 'severity', 'ip', 'port', 'initial_detection', 'mitigation_detected', 'days_to_mitigate')
            data_fields = ('owner', 'plugin_name', 'severity', 'ip', 'port', 'time_opened', 'time_closed', 'days_to_close')
        else:
            header_fields = ('vulnerability', 'severity', 'ip', 'port', 'initial_detection', 'mitigation_detected', 'days_to_mitigate')
            data_fields = ('plugin_name', 'severity', 'ip', 'port', 'time_opened', 'time_closed', 'days_to_close')
        data = self.__results['resolved_vulnerabilities']
        with open('mitigated-vulnerabilities.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for row in data:
                # If enough time has passed between snapshot creation and report generation,
                # we may see tickets that were closed when the snapshot was created, but
                # re-opened now. In these cases, 'time_closed' comes in as NaT (Not a Time),
                # which has a type of pd.NaTType, as opposed to pd.Timestamp.
                # Until a better solution is implemented, set time_closed and days_to_close
                # fields to ''. Also set t['time_closed'] to '' due to: "ValueError: NaTType
                # does not support isoformat" when writing json to file in __generate_mustache_json()
                if type(row['time_closed']) == pd.Timestamp:
                    row['days_to_close'] = int(round(row['days_to_close']))
                else:
                    row['time_closed'] = row['days_to_close'] = ''
                data_writer.writerow(row)

    def __generate_recently_detected_vulns_attachment(self):
        if self.__snapshots[0].get('descendants_included'):
            header_fields = ('owner', 'name', 'cve', 'severity', 'ip', 'port', 'initial_detection', 'latest_detection', 'age_days')
            data_fields = ('owner', 'name', 'cve', 'severity', 'ip', 'port', 'time_opened', 'last_detected', 'age')
        else:
            header_fields = ('name', 'cve', 'severity', 'ip', 'port', 'initial_detection', 'latest_detection', 'age_days')
            data_fields = ('name', 'cve', 'severity', 'ip', 'port', 'time_opened', 'last_detected', 'age')
        data = self.__results['recently_detected_closed_tickets']
        with open('recently-detected.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for row in data:
                data_writer.writerow(row)

    def __generate_services_attachment(self):
        # remove ip_int column if we are trying to be anonymous
        if self.__anonymize:
            fields = ('ip', 'port', 'service')
        else:
            if self.__snapshots[0].get('descendants_included'):
                fields = ('owner', 'ip_int', 'ip', 'port', 'service')
            else:
                fields = ('ip_int', 'ip', 'port', 'service')
        data = self.__results['services_attachment']
        with open('services.csv', 'wb') as out_file:
            writer = DictWriter(out_file, fields, extrasaction='ignore')
            writer.writeheader()
            for row in data:
                writer.writerow(row)

    def __generate_risky_services_attachment(self):
        # remove ip_int column if we are trying to be anonymous
        if self.__anonymize:
            fields = ('ip', 'port', 'service', 'category',
                      'newly_opened_since_last_report')
        else:
            if self.__snapshots[0].get('descendants_included'):
                fields = ('owner', 'ip_int', 'ip', 'port', 'service',
                          'category', 'newly_opened_since_last_report')
            else:
                fields = ('ip_int', 'ip', 'port', 'service',
                          'category', 'newly_opened_since_last_report')
        data = self.__results['risky_services_tickets']
        with open('potentially-risky-services.csv', 'wb') as out_file:
            writer = DictWriter(out_file, fields, extrasaction='ignore')
            writer.writeheader()
            for row in data:
                writer.writerow(row)

    def __generate_hosts_attachment(self):
        # remove ip_int and hostname column if we are trying to be anonymous
        if self.__anonymize:
            header_fields = ('ip', 'os')
            data_fields = ('ip', 'name')
        else:
            if self.__snapshots[0].get('descendants_included'):
                header_fields = ('owner', 'ip_int', 'ip', 'os', 'hostname')
                data_fields = ('owner', 'ip_int', 'ip', 'name', 'hostname')
            else:
                header_fields = ('ip_int', 'ip', 'os', 'hostname')
                data_fields = ('ip_int', 'ip', 'name', 'hostname')
        data = self.__results['hosts_attachment']
        with open('hosts.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            header_writer.writeheader()
            for row in data:
                data_writer.writerow(row)

    def __generate_scope_attachment(self):
        if self.__snapshots[0].get('descendants_included') and not self.__anonymize:
            header_fields = ('owner', 'cidr', 'first', 'last', 'count')
            snapshot_family = self.__results['ss0_descendant_snapshots'] + [self.__snapshots[0]]
        else:
            header_fields = ('cidr', 'first', 'last', 'count')
        data = self.__snapshots[0]['networks']
        with open('scope.csv', 'wb') as out_file:
            writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            writer.writeheader()
            for net in data:
                if self.__anonymize:
                    row = {'cidr':re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, str(net.cidr)), 'first':re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, str(IPAddress(net.first))), 'last':re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, str(IPAddress(net.last))), 'count':net.size}
                elif self.__snapshots[0].get('descendants_included'):
                    for snap in snapshot_family:
                        if net in snap['networks']:
                            break
                    row = {'owner':snap['owner'], 'cidr':net.cidr, 'first':IPAddress(net.first), 'last':IPAddress(net.last), 'count':net.size}
                else:
                    row = {'cidr':net.cidr, 'first':IPAddress(net.first), 'last':IPAddress(net.last), 'count':net.size}
                writer.writerow(row)

    def __generate_false_positives_attachment(self):
        # remove ip_int column if we are trying to be anonymous
        if self.__anonymize:
            header_fields = ('ip', 'port', 'severity', 'initial_detection', 'latest_detection',
                             'name', 'false_positive_effective', 'false_positive_expiration')
            data_fields = ('ip', 'port', 'severity', 'time_opened', 'last_detected',
                           'name', 'fp_effective_date', 'fp_expiration_date')
        else:   # if there are any descendants in current snapshot, output 'owner' field also
            if self.__snapshots[0].get('descendants_included'):
                header_fields = ('owner', 'ip_int', 'ip', 'port', 'severity', 'initial_detection', 'latest_detection',
                                 'name', 'false_positive_effective', 'false_positive_expiration')
                data_fields = ('owner', 'ip_int', 'ip', 'port', 'severity', 'time_opened', 'last_detected',
                               'name', 'fp_effective_date', 'fp_expiration_date')
            else:
                header_fields = ('ip_int', 'ip', 'port', 'severity', 'initial_detection', 'latest_detection',
                                 'name', 'false_positive_effective', 'false_positive_expiration')
                data_fields = ('ip_int', 'ip', 'port', 'severity', 'time_opened', 'last_detected',
                               'name', 'fp_effective_date', 'fp_expiration_date')
        data = self.__results['false_positive_tickets']
        with open('false-positive-findings.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for row in data:
                data_writer.writerow(row)

    def __generate_sub_org_summary_attachment(self):
        if self.__snapshots[0].get('descendants_included'):
            header_fields = ('org_name', 'addresses_owned', 'addresses_scanned', 'addresses_scanned_percent', 'hosts_detected', 'hosts_vulnerable', 'hosts_vulnerable_percent', 'critical_vulns_detected', 'high_vulns_detected', 'medium_vulns_detected', 'low_vulns_detected', 'services_detected', 'median_days_to_mitigate_criticals', 'median_days_to_mitigate_highs', 'median_days_to_mitigate_mediums', 'median_days_to_mitigate_lows', 'median_days_currently_active_criticals', 'median_days_currently_active_highs', 'median_days_currently_active_mediums', 'median_days_currently_active_lows')
            data_fields = ('owner', 'address_count', 'addresses_scanned', 'addresses_scanned_percent', 'host_count', 'vulnerable_host_count', 'vuln_host_percent', 'vulnerabilities.critical', 'vulnerabilities.high', 'vulnerabilities.medium', 'vulnerabilities.low', 'port_count', 'tix_days_to_close.critical.median', 'tix_days_to_close.high.median', 'tix_days_to_close.medium.median', 'tix_days_to_close.low.median', 'tix_days_open.critical.median', 'tix_days_open.high.median', 'tix_days_open.medium.median', 'tix_days_open.low.median')
            with open('sub-org-summary.csv', 'wb') as out_file:
                header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
                header_writer.writeheader()
                data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
                # Output data from descendant orgs
                for row in self.__results['ss0_descendant_data']:
                    for severity in ('critical', 'high', 'medium', 'low'):
                        row['vulnerabilities.' + severity] = row['vulnerabilities'][severity]
                        row['tix_days_to_close.' + severity + '.median'] = row['tix_days_to_close'][severity]['median']
                        row['tix_days_open.' + severity + '.median'] = row['tix_days_open'][severity]['median']
                    data_writer.writerow(row)
                # Output data from parent org
                ss0 = self.__snapshots[0].copy()
                ss0['owner'] = ss0['owner'] + ' Total'
                ss0['address_count'] = len(self.__snapshots[0].networks)
                ss0['addresses_scanned_percent'] = int(safe_percent(ss0['addresses_scanned'], ss0['address_count'], 0))
                ss0['vuln_host_percent'] = int(safe_percent(ss0['vulnerable_host_count'], ss0['host_count'], 0))
                for severity in ('critical', 'high', 'medium', 'low'):
                    ss0['vulnerabilities.' + severity] = ss0['vulnerabilities'][severity]
                    ss0['tix_days_to_close.' + severity + '.median'] = self.__results['ss0_tix_days_to_close'][severity]['median']
                    ss0['tix_days_open.' + severity + '.median'] = self.__results['ss0_tix_days_open'][severity]['median']
                data_writer.writerow(ss0)

    def __generate_days_to_mitigate_attachment(self):
        header_fields = ('report_date', 'median_days_to_mitigate_criticals', 'max_days_to_mitigate_criticals', 'median_days_to_mitigate_highs', 'max_days_to_mitigate_highs', 'median_days_to_mitigate_mediums', 'max_days_to_mitigate_mediums', 'median_days_to_mitigate_lows', 'max_days_to_mitigate_lows', 'calculated_with_vulns_mitigated_since')
        data_fields = ('report_date', 'tix_days_to_close.critical.median', 'tix_days_to_close.critical.max', 'tix_days_to_close.high.median', 'tix_days_to_close.high.max', 'tix_days_to_close.medium.median', 'tix_days_to_close.medium.max', 'tix_days_to_close.low.median', 'tix_days_to_close.low.max', 'tix_closed_after_date')
        with open('days-to-mitigate.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for snap in self.__snapshots:
                snap['report_date'] = snap['tix_msec_open']['tix_open_as_of_date'].strftime('%Y-%m-%d')
                snap['tix_closed_after_date'] = snap['tix_msec_to_close']['tix_closed_after_date'].strftime('%Y-%m-%d')
                for severity in ('critical', 'high', 'medium', 'low'):
                    snap['tix_days_to_close.' + severity + '.median'] = snap['tix_days_to_close'][severity]['median']
                    snap['tix_days_to_close.' + severity + '.max'] = snap['tix_days_to_close'][severity]['max']
                data_writer.writerow(snap)

    def __generate_days_currently_active_attachment(self):
        header_fields = ('report_date', 'median_days_currently_active_criticals', 'max_days_currently_active_criticals', 'median_days_currently_active_highs', 'max_days_currently_active_highs', 'median_days_currently_active_mediums', 'max_days_currently_active_mediums', 'median_days_currently_active_lows', 'max_days_currently_active_lows')
        data_fields = ('report_date', 'tix_days_open.critical.median', 'tix_days_open.critical.max', 'tix_days_open.high.median', 'tix_days_open.high.max', 'tix_days_open.medium.median', 'tix_days_open.medium.max', 'tix_days_open.low.median', 'tix_days_open.low.max')
        with open('days-currently-active.csv', 'wb') as out_file:
            header_writer = DictWriter(out_file, header_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer = DictWriter(out_file, data_fields, extrasaction='ignore')
            for snap in self.__snapshots:
                snap['report_date'] = snap['tix_msec_open']['tix_open_as_of_date'].strftime('%Y-%m-%d')
                for severity in ('critical', 'high', 'medium', 'low'):
                    snap['tix_days_open.' + severity + '.median'] = snap['tix_days_open'][severity]['median']
                    snap['tix_days_open.' + severity + '.max'] = snap['tix_days_open'][severity]['max']
                data_writer.writerow(snap)

    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        ss0 = self.__snapshots[0]
        result = {
            'ss0': ss0,
            'is_suborg': self.__results['is_suborg']
        }

        if 'certs' in self.__results:
            result['certs'] = self.__results['certs']

        result['draft'] = self.__draft
        calc = dict() # calculated vaules for report

        calc['vuln_host_count_pct_increase_flag'] = False
        calc['vuln_host_count_pct_decrease_flag'] = False
        calc['vuln_host_count_pct_flat_flag'] = False

        calc['no_history'] = self.__no_history
        if self.__no_history:
            ss1 = ss0
            calc['host_count_percent'] =\
                calc['vulnerable_host_count_percent'] =\
                calc['unique_operating_systems_percent'] =\
                calc['unique_services_percent'] =\
                calc['unique_vulnerabilities_percent'] = '-'
            calc['vuln_host_count_pct_flat_flag'] = True
            calc['vuln_host_count_pct_change_int'] = 0
        else:
            ss1 = self.__snapshots[1]
            calc['host_count_percent'] = self.__percent_change(ss1['host_count'], ss0['host_count'])
            calc['vulnerable_host_count_percent'] = self.__percent_change(ss1['vulnerable_host_count'], ss0['vulnerable_host_count'])

            if calc['vulnerable_host_count_percent'] == '-':
                # See __percent_change() for how/why this can happen
                calc['vuln_host_count_pct_flat_flag'] = True
            elif calc['vulnerable_host_count_percent'] > 0.0:
                calc['vuln_host_count_pct_increase_flag'] = True
            elif calc['vulnerable_host_count_percent'] < 0.0:
                calc['vuln_host_count_pct_decrease_flag'] = True
            else:
                calc['vuln_host_count_pct_flat_flag'] = True

            if calc['vuln_host_count_pct_flat_flag']:
                calc['vuln_host_count_pct_change_int'] = 0
            else:
                calc['vuln_host_count_pct_change_int'] = \
                    abs(int(round(calc['vulnerable_host_count_percent'], 0)))

            calc['unique_operating_systems_percent'] = self.__percent_change(ss1['unique_operating_systems'], ss0['unique_operating_systems'])
            calc['unique_services_percent'] = self.__percent_change(len(ss1['services']), len(ss0['services']))
            calc['unique_vulnerabilities_percent'] =\
                self.__percent_change(ss1['unique_vulnerabilities']['total'], ss0['unique_vulnerabilities']['total'])
        result['ss1'] = ss1
        # create items for _up, _down, or _flat (used in mustache conditionals)
        calc.update(self.__udf_calc('address_count', len(ss1.networks), len(ss0.networks)))
        calc.update(self.__udf_calc('addresses_scanned', ss1['addresses_scanned'], ss0['addresses_scanned']))
        calc.update(self.__udf_calc('host_count', ss1['host_count'], ss0['host_count']))
        calc.update(self.__udf_calc('vuln_host_count', ss1['vulnerable_host_count'], ss0['vulnerable_host_count']))
        calc.update(self.__udf_calc('port_count', ss1['port_count'], ss0['port_count']))
        calc.update(self.__udf_calc('vuln_critical', ss1['vulnerabilities']['critical'], ss0['vulnerabilities']['critical']))
        calc.update(self.__udf_calc('vuln_high', ss1['vulnerabilities']['high'], ss0['vulnerabilities']['high']))
        calc.update(self.__udf_calc('vuln_medium', ss1['vulnerabilities']['medium'], ss0['vulnerabilities']['medium']))
        calc.update(self.__udf_calc('vuln_low', ss1['vulnerabilities']['low'], ss0['vulnerabilities']['low']))
        calc.update(self.__udf_calc('vuln_total', ss1['vulnerabilities']['total'], ss0['vulnerabilities']['total']))
        calc['start_date_tex'] = ss0['start_time'].strftime('{%d}{%m}{%Y}')
        calc['start_time_tex'] = ss0['start_time'].strftime('{%H}{%M}{%S}')
        calc['end_date_tex'] = ss0['end_time'].strftime('{%d}{%m}{%Y}')
        calc['end_time_tex'] = ss0['end_time'].strftime('{%H}{%M}{%S}')
        if self.__title_date: # date for title page
            calc['title_date_tex'] = self.__title_date.strftime('{%d}{%m}{%Y}')
        else:
            calc['title_date_tex'] = calc['end_date_tex']
        calc['address_count'] = len(ss0.networks)
        calc['addresses_scanned'] = ss0['addresses_scanned']
        calc['addresses_scanned_percent'] = int(safe_percent(ss0['addresses_scanned'], calc['address_count'], 0))
        if self.__results['address_scan_start_date']:
            calc['address_scan_start_date_tex'] = self.__results['address_scan_start_date'].strftime('{%d}{%m}{%Y}')
            calc['address_scan_end_date_tex'] = self.__results['address_scan_end_date'].strftime('{%d}{%m}{%Y}')
        if self.__results['vuln_scan_start_date']:
            calc['vuln_scan_start_date_tex'] = self.__results['vuln_scan_start_date'].strftime('{%d}{%m}{%Y}')
            calc['vuln_scan_end_date_tex'] = self.__results['vuln_scan_end_date'].strftime('{%d}{%m}{%Y}')
        if self.__results['ss0_tix_days_to_close']:
            calc['ss0_tix_closed_after_date_tex'] = self.__results['ss0_tix_days_to_close']['tix_closed_after_date'].strftime('{%d}{%m}{%Y}')
            calc['ss0_tix_days_to_close'] = self.__results['ss0_tix_days_to_close']
            calc['ss0_tix_days_open'] = self.__results['ss0_tix_days_open']
        calc['vuln_host_percent'] = int(safe_percent(ss0['vulnerable_host_count'], ss0['host_count'], 0))
        calc['ss0_unique_services_count'] = len(ss0['services'])
        calc['ss1_unique_services_count'] = len(ss1['services'])
        calc['average_vulnerabilities_per_host'] = safe_divide(ss0['vulnerabilities']['total'], ss0['host_count'], 2)

        avpvh = calc['average_vulnerabilities_per_vulnerable_host'] = dict()
        for k,v in ss0['vulnerabilities'].items():
            avpvh[k] = safe_divide(v, ss0['vulnerable_host_count'], 2)

        result['calc'] = calc

        # Calculate count of "hosts with unsupported software"
        hosts_with_unsupported_sw = set()
        for t in self.__results['tickets_0']:
            if "Unsupported" in t['details'].get('name'):
                hosts_with_unsupported_sw.add(t['ip'])
        result['unsupported_sw_host_count'] = len(hosts_with_unsupported_sw)

        result['risky_services'] = self.__results['risky_services_metrics']

        if self.__results.get('ss0_descendant_snapshots'):
            result['ss0_descendant_data'] = self.__results['ss0_descendant_data']

        result['density'] = self.__vulnerability_density(self.__results['tickets_0']).to_dict()
        result['top_operating_systems'] = self.__results['top_operating_systems']
        result['top_services'] = self.__results['top_services']
        result['top_10_vulnerability_occurrence'] = self.__results['top_10_vulnerability_occurrence']

        result['top_common_services_static'] = self.__results['top_common_services_static']
        result['top_common_services_other'] = self.__results['top_common_services_other']
        other_services = [i['index'] for i in result['top_common_services_other']]
        result['top_common_services_other_english'] = self.__to_oxford_list(other_services, ' was', ' were')
        result['top_10_risky_hosts'] = self.__dataframe_to_dicts(self.__top_risky_hosts(self.__results['tickets_0'])[:10])
        result['owner'] = self.__results['owner']
        for contact in result['owner']['agency']['contacts']:
            if contact['type'] == POC_TYPE.TECHNICAL:
                contact['type'] = 'Technical'
            elif contact['type'] == POC_TYPE.DISTRO:
                contact['type'] = 'Distribution List'
        result['owner_is_federal_executive'] = self.__results['owner_is_federal_executive']

        if ss0.get('descendants_included'):     # When the snapshot has descendants, we want to show 'owner' field throughout report
            result['display_owner'] = True

        result['active_critical_age_counts'] = list()
        for (bucket_start, bucket_end) in ACTIVE_CRITICAL_AGE_BUCKETS:
            bucket_count = int(self.__results['active_critical_age_counts'][bucket_start:bucket_end].sum())
            result['active_critical_age_counts'].append({'bucket_range':'{}-{}'.format(bucket_start, bucket_end), 'count':bucket_count})
        last_bucket_start = ACTIVE_CRITICAL_AGE_BUCKETS[-1][1]
        last_bucket_count = int(self.__results['active_critical_age_counts'][last_bucket_start:].sum())
        result['active_critical_age_counts'].append({'bucket_range':'{}+'.format(last_bucket_start), 'count':last_bucket_count})

        result['vulnerability_history'] = self.__results['vulnerability_history']
        result['detailed_findings'] = self.__results['detailed_findings']
        for t in result['detailed_findings']:
            t['first_detected_date_tex'] = t['first_detected'].strftime('{%d}{%m}{%Y}')
            t['first_detected_time_tex'] = t['first_detected'].strftime('{%H}{%M}{%S}')
            t['last_detected_date_tex'] = t['last_detected'].strftime('{%d}{%m}{%Y}')
            t['last_detected_time_tex'] = t['last_detected'].strftime('{%H}{%M}{%S}')

        result['mitigations'] = self.__results['mitigations']
        for t in result['mitigations']:
            if t['ports'] == '0':
                t['ports'] = 'NA'

        result['risk_rating_system'] = self.__results['risk_rating_system']
        result['brand_new_vulnerabilities'] = self.__results['brand_new_vulnerabilities']
        for t in result['brand_new_vulnerabilities']:
            if t['port'] == 0:
                t['port'] = 'NA'
            t['time_opened_date_tex'] = t['time_opened'].strftime('{%d}{%m}{%Y}')
            t['time_opened_time_tex'] = t['time_opened'].strftime('{%H}{%M}{%S}')
            t['last_detected_date_tex'] = t['last_detected'].strftime('{%d}{%m}{%Y}')
            t['last_detected_time_tex'] = t['last_detected'].strftime('{%H}{%M}{%S}')

        result['redetected_vulnerabilities'] = self.__results['redetected_vulnerabilities']
        for t in result['redetected_vulnerabilities']:
            if t['port'] == 0:
                t['port'] = 'NA'
            t['time_opened_date_tex'] = t['time_opened'].strftime('{%d}{%m}{%Y}')
            t['time_opened_time_tex'] = t['time_opened'].strftime('{%H}{%M}{%S}')
            t['last_detected_date_tex'] = t['last_detected'].strftime('{%d}{%m}{%Y}')
            t['last_detected_time_tex'] = t['last_detected'].strftime('{%H}{%M}{%S}')

        result['resolved_vulnerabilities'] = self.__results['resolved_vulnerabilities']
        for t in result['resolved_vulnerabilities']:
            if t['port'] == 0:
                t['port'] = 'NA'
            t['time_opened_date_tex'] = t['time_opened'].strftime('{%d}{%m}{%Y}')

            if t['time_closed'] != '':
                t['time_closed_date_tex'] = t['time_closed'].strftime('{%d}{%m}{%Y}')
                t['time_closed_time_tex'] = t['time_closed'].strftime('{%H}{%M}{%S}')
            else:
                t['time_closed_date_tex'] = t['time_closed_time_tex'] = ''

        result['new_vulnerability_counts'] = self.__results['new_vulnerability_counts']
        result['resolved_vulnerability_counts'] = self.__results['resolved_vulnerability_counts']

        result['recently_detected_closed_tickets'] = self.__results['recently_detected_closed_tickets']
        for t in result['recently_detected_closed_tickets']:
            if t['port'] == 0:
                t['port'] = 'NA'
            t['time_opened_date_tex'] = t['time_opened'].strftime('{%d}{%m}{%Y}')
            t['time_opened_time_tex'] = t['time_opened'].strftime('{%H}{%M}{%S}')
            t['last_detected_date_tex'] = t['last_detected'].strftime('{%d}{%m}{%Y}')
            t['last_detected_time_tex'] = t['last_detected'].strftime('{%H}{%M}{%S}')

        result['false_positive_tickets'] = self.__results['false_positive_tickets']
        result['false_positive_tickets_count'] = len(result['false_positive_tickets'])
        result['expiring_soon_false_positive_tickets'] = list()
        for t in result['false_positive_tickets']:
            if t['port'] == 0:
                t['port'] = 'NA'
            t['time_opened_date_tex'] = t['time_opened'].strftime('{%d}{%m}{%Y}')
            t['time_opened_time_tex'] = t['time_opened'].strftime('{%H}{%M}{%S}')
            t['last_detected_date_tex'] = t['last_detected'].strftime('{%d}{%m}{%Y}')
            t['last_detected_time_tex'] = t['last_detected'].strftime('{%H}{%M}{%S}')
            t['fp_effective_date_tex'] = t['fp_effective_date'].strftime('{%d}{%m}{%Y}')
            t['fp_expiration_date_tex'] = t['fp_expiration_date'].strftime('{%d}{%m}{%Y}')
            if t['expiring_soon']:
                result['expiring_soon_false_positive_tickets'].append(t.copy()) # append a copy otherwise chars get escaped twice in latex_escape_structure_make_cve_urls()
        result['false_positive_expiring_soon_days'] = FALSE_POSITIVE_EXPIRING_SOON_DAYS
        result['expiring_soon_false_positive_tickets_count'] = len(result['expiring_soon_false_positive_tickets'])

        if self.__log_report_to_db:
            result['report_oid'] = str(self.__report_oid)
        else:
            result['report_oid'] = None     # If report_oid is None, it will not be included in the PDF metadata

        # escape latex special characters in all values and convert any instances of CVE IDs into hyperlinks to the NVD (NIST)
        self.__latex_escape_structure_make_cve_urls(result)

        # anonymize data if requested
        # if self.__anonymize:
        #     result = self.__anonymize_structure(result)

        with open(filename, 'wb') as out:
            out.write(to_json(result))

    def __generate_latex(self, mustache_file, json_file, latex_file):
        renderer = pystache.Renderer()
        template = codecs.open(mustache_file,'r', encoding='utf-8').read()

        with codecs.open(json_file,'r', encoding='utf-8') as data_file:
            data = json.load(data_file)

        r = pystache.render(template, data)
        with codecs.open(latex_file,'w', encoding='utf-8') as output:
            output.write(r)

    def __generate_final_pdf(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')

        return_code = subprocess.call(['xelatex','report.tex'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 1 of 3 return code was %s' % return_code

        return_code = subprocess.call(['makeglossaries','report'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'makeglossaries pass 1 of 2 return code was %s' % return_code

        return_code = subprocess.call(['xelatex','report.tex'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 3 return code was %s' % return_code

        # Both TOC and Glossary run longer than 1 page each, so we need to run them both again to get our numbering correct
        # See http://tex.stackexchange.com/questions/74163/glossaries-issue-wrong-pagenumber-for-book-and-memoir
        return_code = subprocess.call(['makeglossaries','report'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'makeglossaries pass 2 of 2 return code was %s' % return_code

        return_code = subprocess.call(['xelatex','report.tex'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 3 of 3 return code was %s' % return_code

    def __encrypt_pdf(self, name_in, name_out, user_key, owner_key):
        pdf_writer = PdfFileWriter()
        pdf_reader = PdfFileReader(open(name_in, 'rb'))

        # metadata copy hack see: http://stackoverflow.com/questions/2574676/change-metadata-of-pdf-file-with-pypdf
        metadata = pdf_reader.getDocumentInfo()
        pdf_writer._info.getObject().update(metadata) # copy metadata to dest

        for i in xrange(pdf_reader.getNumPages()):
            pdf_writer.addPage(pdf_reader.getPage(i))

        pdf_writer.encrypt(user_pwd=user_key, owner_pwd=owner_key.encode('ascii'))

        with file(name_out, 'wb') as f:
            pdf_writer.write(f)

    def __log_report(self):
        report = self.__cyhy_db.ReportDoc()
        report['_id'] = self.__report_oid
        report['owner'] = self.__owner
        report['generated_time'] = self.__generated_time
        report['snapshot_oid'] = [self.__snapshots[0]['_id']]   # This is a list for backwards-compatibility; see changes in CYHY-258
        report['report_types'] = [REPORT_TYPE.CYHY]
        report.save()

def main():
    args = docopt(__doc__, version='v0.0.1')
    cyhy_db = database.db_from_config(args['--cyhy-section'])
    scan_db = database.db_from_config(args['--scan-section'])

    overview_data = []

    for owner in args['OWNER']:
        if args['--previous']:
            snapshot_id = ObjectId(args['--previous'])
        else:
            snapshot_id = None

        if args['--title-date']:
            title_date = dateutil.parser.parse(args['--title-date'])
        else:
            title_date = None

        if args['--encrypt']:
            report_key = Config(args['--cyhy-section']).report_key
        else:
            report_key = None

        print 'Generating report for %s ...' % (owner),
        generator = ReportGenerator(cyhy_db, scan_db, owner,
                                    debug=args['--debug'],
                                    snapshot_id=snapshot_id,
                                    title_date=title_date, final=args['--final'],
                                    anonymize=args['--anonymize'],
                                    encrypt_key=report_key,
                                    log_report=not args['--nolog'])
        was_encrypted, results = generator.generate_report()

        overview_row = OrderedDict()
        overview_row['acronym'] = results['owner']['agency']['acronym']
        overview_row['organization_name'] = results['owner']['agency']['name']
        overview_row['was_encrypted'] = was_encrypted
        overview_row['email'] = results['owner']['agency']['contacts'][0]['email']
        overview_row['name'] = results['owner']['agency']['contacts'][0]['name']
        overview_row['phone'] = results['owner']['agency']['contacts'][0].get('phone')
        overview_row['new_low'] = results['new_vulnerability_counts']['low']
        overview_row['new_medium'] = results['new_vulnerability_counts']['medium']
        overview_row['new_high'] = results['new_vulnerability_counts']['high']
        overview_row['new_critical'] = results['new_vulnerability_counts']['critical']
        overview_data.append(overview_row)

        if was_encrypted:
            print 'Done (encrypted)'
        else:
            print 'Done'

    if args['--overview']:
        print 'Generating overview CSV ...',
        fields = overview_data[0].keys()
        with open(args['--overview'], 'w') as csv_out:
            csv_writer = DictWriter(csv_out, fields, extrasaction='ignore')
            csv_writer.writeheader()
            for row in overview_data:
                csv_writer.writerow(row)
        print 'Done'

        # import IPython; IPython.embed() #<<< BREAKPOINT >>>
        # sys.exit(0)

if __name__=='__main__':
    main()
