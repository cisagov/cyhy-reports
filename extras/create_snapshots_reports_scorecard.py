#!/usr/bin/env python
"""Generate the weekly Cyber Exposure scorecard and all CyHy reports.

Usage:
  create_snapshots_reports_scorecard.py [options] CYHY_DB_SECTION SCAN_DB_SECTION

Options:
  -h, --help            show this help message and exit
  --no-dock             do not use docker for scorecard and reports
  --no-snapshots        do not create a scorecard or snapshots, jump straight to reports
  --no-log              do not log that this scorecard and these reports were created
  --no-pause            do not pause the commander when generating reports
"""

import distutils.dir_util
import glob
import logging
import math
import os
import shutil
import subprocess
import sys
import threading
import time

from bson import ObjectId
from collections import defaultdict
from docopt import docopt

from cyhy.core import SCAN_TYPE
from cyhy.core.common import REPORT_TYPE, REPORT_PERIOD
from cyhy.db import database, CHDatabase
from cyhy.util import util
from ncats_webd import cybex_queries

current_time = util.utcnow()

LOGGING_LEVEL = logging.INFO
LOG_FILE = "snapshots_reports_scorecard_automation.log"
REPORT_THREADS = 16
SNAPSHOT_THREADS = 16

NCATS_DHUB_URL = "dhub.ncats.cyber.dhs.gov:5001"
NCATS_WEB_URL = "web.data.ncats.cyber.dhs.gov"

WEEKLY_REPORT_BASE_DIR = "/var/cyhy/reports/output"
SCORECARD_OUTPUT_DIR = "scorecards"
SCORECARD_JSON_OUTPUT_DIR = "JSONfiles"
CYBEX_CSV_DIR = "cybex_csvs"
CYHY_REPORT_DIR = os.path.join(
    "report_archive", "reports{}".format(current_time.strftime("%Y%m%d"))
)

CRITICAL_SEVERITY = 4
HIGH_SEVERITY = 3

# Global variables and their associated thread locks
successful_snapshots = list()
ss_lock = threading.Lock()

failed_snapshots = list()
fs_lock = threading.Lock()

snapshot_durations = list()
sd_lock = threading.Lock()

successful_reports = list()
sr_lock = threading.Lock()

failed_reports = list()
fr_lock = threading.Lock()

report_durations = list()
rd_lock = threading.Lock()


def create_subdirectories():
    # Create all required subdirectories (if they don't already exist)
    for subdir in [
        SCORECARD_OUTPUT_DIR,
        SCORECARD_JSON_OUTPUT_DIR,
        CYBEX_CSV_DIR,
        CYHY_REPORT_DIR,
    ]:
        distutils.dir_util.mkpath(os.path.join(WEEKLY_REPORT_BASE_DIR, subdir))


def gen_weekly_scorecard(
    previous_scorecard_filename, cyhy_db_section, scan_db_section, use_docker, nolog
):
    response = None
    if use_docker == 1:
        if nolog:
            response = subprocess.call(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--volume",
                    "/etc/cyhy:/etc/cyhy",
                    "--volume",
                    "{}:/home/cyhy".format(SCORECARD_OUTPUT_DIR),
                    "{}/cyhy-reports:stable".format(NCATS_DHUB_URL),
                    "cyhy-cybex-scorecard",
                    "--nolog",
                    "--final",
                    cyhy_db_section,
                    scan_db_section,
                    os.path.join(
                        SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename
                    ),
                ]
            )
        else:
            response = subprocess.call(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--volume",
                    "/etc/cyhy:/etc/cyhy",
                    "--volume",
                    "{}:/home/cyhy".format(SCORECARD_OUTPUT_DIR),
                    "{}/cyhy-reports:stable".format(NCATS_DHUB_URL),
                    "cyhy-cybex-scorecard",
                    "--final",
                    cyhy_db_section,
                    scan_db_section,
                    os.path.join(
                        SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename
                    ),
                ]
            )
    else:
        logging.info("  Not using Docker to create CybEx Scorecard...")
        os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_OUTPUT_DIR))
        if nolog:
            response = subprocess.call(
                [
                    "cyhy-cybex-scorecard",
                    "--nolog",
                    "--final",
                    cyhy_db_section,
                    scan_db_section,
                    os.path.join(
                        WEEKLY_REPORT_BASE_DIR,
                        SCORECARD_JSON_OUTPUT_DIR,
                        previous_scorecard_filename,
                    ),
                ]
            )
        else:
            response = subprocess.call(
                [
                    "cyhy-cybex-scorecard",
                    "--final",
                    cyhy_db_section,
                    scan_db_section,
                    os.path.join(
                        WEEKLY_REPORT_BASE_DIR,
                        SCORECARD_JSON_OUTPUT_DIR,
                        previous_scorecard_filename,
                    ),
                ]
            )

    return response


def sample_report(cyhy_db_section, scan_db_section, nolog):
    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    logging.info("Creating SAMPLE report...")
    if nolog:
        p = subprocess.Popen(
            [
                "cyhy-report",
                "--nolog",
                "--cyhy-section",
                cyhy_db_section,
                "--scan-section",
                scan_db_section,
                "--anonymize",
                "DHS",
            ],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    else:
        p = subprocess.Popen(
            [
                "cyhy-report",
                "--cyhy-section",
                cyhy_db_section,
                "--scan-section",
                scan_db_section,
                "--anonymize",
                "DHS",
            ],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    data, err = p.communicate()
    return_code = p.returncode

    if return_code == 0:
        logging.info("SAMPLE report successfully created")
    else:
        logging.info("Failed to create SAMPLE report")
        logging.info("Stderr report detail: %s%s", data, err)


def create_list_of_reports_to_generate(db):
    """Create list of organizations that need reports generated."""
    return sorted(
        [
            i["_id"]
            for i in db.RequestDoc.collection.find(
                {
                    "report_period": REPORT_PERIOD.WEEKLY,
                    "report_types": REPORT_TYPE.CYHY,
                },
                {"_id": 1},
            )
        ]
    )


def create_list_of_snapshots_to_generate(db, reports_to_generate):
    """Create list of organizations that need snapshots generated."""
    # Find all descendants of orgs that get reports and have children
    report_org_descendants = set()
    for i in db.RequestDoc.collection.find(
        {
            "report_period": REPORT_PERIOD.WEEKLY,
            "report_types": REPORT_TYPE.CYHY,
            "children": {"$exists": True, "$ne": []},
        },
        {"_id": 1},
    ):
        report_org_descendants.update(db.RequestDoc.get_all_descendants(i["_id"]))

    # Create the list of snapshots to generate by removing
    # report_org_descendants (their snapshots will be created when their
    # parent org's snapshot is created)
    return sorted(list(set(reports_to_generate) - report_org_descendants))


def make_list_chunks(my_list, num_chunks):
    """Split a list into a specified number of smaller lists."""
    for i in range(0, num_chunks):
        yield my_list[i::num_chunks]


def create_snapshot(db, cyhy_db_section, org_id, use_only_existing_snapshots):
    """Create a snapshot for a specified organization."""
    snapshot_start_time = time.time()

    snapshot_command = ["cyhy-snapshot", "--section", cyhy_db_section, "create"]

    if use_only_existing_snapshots:
        snapshot_command.append("--use-only-existing-snapshots")

    snapshot_command.append(org_id)

    snapshot_process = subprocess.Popen(
        snapshot_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Confirm the snapshot creation
    data, err = snapshot_process.communicate("yes")

    snapshot_duration = time.time() - snapshot_start_time
    with sd_lock:
        snapshot_durations.append((org_id, snapshot_duration))

    # Determine org's descendants for logging below
    org_descendants = list()
    if not use_only_existing_snapshots:
        if snapshot_process.returncode == 0:
            org_descendants = db.SnapshotDoc.find_one(
                {"latest": True, "owner": org_id}
            )["descendants_included"]
        else:
            # Since snapshot creation failed, we must use this (slower)
            # method of finding all descendants
            org_descendants = db.RequestDoc.get_all_descendants(org_id)

    if snapshot_process.returncode == 0:
        logging.info("Successful snapshot: %s (%.2f s))", org_id, snapshot_duration)
        with ss_lock:
            successful_snapshots.append(org_id)
            if org_descendants and not use_only_existing_snapshots:
                logging.info(
                    " - Includes successful descendant snapshot(s): %s", org_descendants
                )
                successful_snapshots.extend(org_descendants)
    else:
        logging.error("Unsuccessful snapshot: %s", org_id)
        with fs_lock:
            failed_snapshots.append(org_id)
            if org_descendants and not use_only_existing_snapshots:
                logging.error(
                    " - Unsuccessful descendant snapshot(s): %s", org_descendants,
                )
                failed_snapshots.extend(org_descendants)
        logging.error("Stderr failure detail: %s %s", data, err)
    return snapshot_process.returncode


def create_snapshots_from_list(org_list, db, cyhy_db_section):
    """Create a snapshot for each organization in a list."""
    for org_id in org_list:
        logging.info(
            "[%s] Starting snapshot for: %s", threading.current_thread().name, org_id
        )
        create_snapshot(db, cyhy_db_section, org_id, use_only_existing_snapshots=False)


def generate_weekly_snapshots(db, cyhy_db_section):
    """Generate all snapshots needed in order to generate the CyHy reports."""
    start_time = time.time()

    logging.info("Building list of reports to generate...")
    reports_to_generate = create_list_of_reports_to_generate(db)

    logging.info("Building list of snapshots to generate...")
    snapshots_to_generate = create_list_of_snapshots_to_generate(
        db, reports_to_generate
    )

    # List to keep track of our snapshot creation threads
    snapshot_threads = list()

    # Lists of orgs for each snapshot thread to process
    snapshots_to_generate = list(
        make_list_chunks(snapshots_to_generate, SNAPSHOT_THREADS)
    )

    # Start up the threads to create snapshots
    for orgs in snapshots_to_generate:
        try:
            snapshot_thread = threading.Thread(
                target=create_snapshots_from_list, args=(orgs, db, cyhy_db_section),
            )
            snapshot_threads.append(snapshot_thread)
            snapshot_thread.start()
        except Exception:
            print("Error: Unable to start snapshot thread for %s", orgs)

    # Wait until each thread terminates
    for snapshot_thread in snapshot_threads:
        snapshot_thread.join()

    snapshot_durations.sort(key=lambda tup: tup[1], reverse=True)
    logging.info("Longest Snapshots:")
    for i in snapshot_durations[:10]:
        logging.info("%s: %.1f seconds", i[0], i[1])
    logging.info(
        "Time to complete snapshots: %.2f minutes", (time.time() - start_time) / 60
    )

    reports_to_generate = set(reports_to_generate) - set(failed_snapshots)
    return sorted(list(reports_to_generate))


# Create a function called "chunks" with two arguments, l and n:
def chunks(l, n):
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i : i + n]


def create_reports(customer_list, cyhy_db_section, scan_db_section, use_docker, nolog):
    for i in customer_list:
        report_time = time.time()
        logging.info("[%s] Starting report for: %s", threading.current_thread().name, i)
        if use_docker == 1:
            if nolog:
                p = subprocess.Popen(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--volume",
                        "/etc/cyhy:/etc/cyhy",
                        "--volume",
                        "{}:/home/cyhy".format(CYHY_REPORT_DIR),
                        "{}/cyhy-reports:stable".format(NCATS_DHUB_URL),
                        "cyhy-report",
                        "--nolog",
                        "--cyhy-section",
                        cyhy_db_section,
                        "--scan-section",
                        scan_db_section,
                        "--final",
                        "--encrypt",
                        i,
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:
                p = subprocess.Popen(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--volume",
                        "/etc/cyhy:/etc/cyhy",
                        "--volume",
                        "{}:/home/cyhy".format(CYHY_REPORT_DIR),
                        "{}/cyhy-reports:stable".format(NCATS_DHUB_URL),
                        "cyhy-report",
                        "--cyhy-section",
                        cyhy_db_section,
                        "--scan-section",
                        scan_db_section,
                        "--final",
                        "--encrypt",
                        i,
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
        else:
            if nolog:
                p = subprocess.Popen(
                    [
                        "cyhy-report",
                        "--nolog",
                        "--cyhy-section",
                        cyhy_db_section,
                        "--scan-section",
                        scan_db_section,
                        "--final",
                        "--encrypt",
                        i,
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:
                p = subprocess.Popen(
                    [
                        "cyhy-report",
                        "--cyhy-section",
                        cyhy_db_section,
                        "--scan-section",
                        scan_db_section,
                        "--final",
                        "--encrypt",
                        i,
                    ],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
        data, err = p.communicate()
        report_time = time.time() - report_time
        report_durations.append((i, report_time))
        return_code = p.returncode
        if return_code == 0:
            logging.info(
                "[%s] Successful report generated: %s (%.2f s)",
                threading.current_thread().name,
                i,
                round(report_time, 2),
            )
            successful_reports.append(i)
        else:
            logging.info(
                "[%s] Failure to generate report: %s",
                threading.current_thread().name,
                i,
            )
            logging.info(
                "[%s] Stderr report detail: %s%s",
                threading.current_thread().name,
                data,
                err,
            )
            failed_reports.append(i)


def gen_weekly_reports(
    db, successful_snaps, cyhy_db_section, scan_db_section, use_docker, nolog
):
    # TODO Clean this function up and make it similar to generate_weekly_snapshots()
    # See https://github.com/cisagov/cyhy-reports/issues/59
    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    start_time = time.time()
    # Create a list from the results of the function chunks
    threads = []
    thread_list = list(
        chunks(
            successful_snaps,
            int(math.ceil(float(len(successful_snaps)) / float(REPORT_THREADS))),
        )
    )
    for i in thread_list:
        try:
            t = threading.Thread(
                target=create_reports,
                args=(i, cyhy_db_section, scan_db_section, use_docker, nolog),
            )
            threads.append(t)
            t.start()
            time.sleep(0.5)
        except:
            print("Error: Unable to start thread")
    for t in threads:
        t.join()
    report_durations.sort(key=lambda tup: tup[1], reverse=True)
    logging.info("Longest Reports:")
    for i in report_durations[:10]:
        logging.info("%s: %.1f seconds", i[0], i[1])
    logging.info(
        "Time to complete reports: %.2f minutes", (time.time() - start_time) / 60
    )

    # Create a symlink to the latest reports.  This is for the
    # automated sending of reports.
    latest_cyhy_reports = os.path.join(WEEKLY_REPORT_BASE_DIR, "report_archive/latest")
    if os.path.exists(latest_cyhy_reports):
        os.remove(latest_cyhy_reports)
    os.symlink(
        os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR), latest_cyhy_reports
    )


def sync_all_tallies(db):
    owners = []
    for r in db.RequestDoc.find({"scan_types": SCAN_TYPE.CYHY}).sort("_id", 1):
        owners.append(r["_id"])

    logging.info("Syncing all tallies...")
    for owner in owners:
        tally = db.TallyDoc.get_by_owner(owner)
        if tally:
            tally.sync(db)
    logging.info("Done syncing all tallies")


def pause_commander(db):
    # number of iterations to wait before giving up
    PAUSE_ITERATION_LIMIT = 30

    # number of seconds to wait between each check to see
    # if the commander has paused
    PAUSE_ITERATION_WAIT_SECONDS = 60

    pause_iteration_count = 0
    ch = CHDatabase(db)
    doc = ch.pause_commander("create_snapshots_reports_scorecard", "report generation")
    logging.info("Requesting commander pause (control doc id = {_id})".format(**doc))
    while not doc["completed"]:
        pause_iteration_count += 1
        logging.info(
            "  Waiting for commander to pause... (#{})".format(pause_iteration_count)
        )
        time.sleep(PAUSE_ITERATION_WAIT_SECONDS)
        if pause_iteration_count == PAUSE_ITERATION_LIMIT:
            logging.error("Commander failed to pause!")
            doc.delete()
            logging.info(
                "Commander control doc {_id} successfully deleted".format(**doc)
            )
            sys.exit(-1)
            return None
        doc.reload()
    return doc["_id"]


def resume_commander(db, pause_doc_id):
    # if failed_reports > 5; keep the commander paused & notify of failure
    if len(failed_reports) > 5:
        logging.error("Large number of reports failing. Keeping commander paused")
        return False
    doc = db.SystemControlDoc.find_one({"_id": ObjectId(pause_doc_id)})
    if not doc:
        logging.error("Could not find a control doc with id {}".format(pause_doc_id))
        return False
    doc.delete()
    logging.info(
        "Commander control doc {} successfully deleted (commander should resume unless other control docs exist)".format(
            pause_doc_id
        )
    )
    return True


def create_third_party_snapshots(db, cyhy_db_section, third_party_report_ids):
    all_tps_start_time = time.time()
    successful_tp_snaps = list()
    failed_tp_snaps = list()

    all_tp_descendants = set()
    tp_dependence_map = defaultdict(list)
    # Build set of all third-party descendants and a
    # map of each descendant to the third-parties that require them.
    for third_party_id in third_party_report_ids:
        descendants = db.RequestDoc.get_all_descendants(third_party_id)
        all_tp_descendants.update(descendants)
        for d in descendants:
            tp_dependence_map[d].append(third_party_id)

    # Check descendants of all third-party orgs for "grouping nodes",
    # then create snapshots, since they otherwise wouldn't have them.
    grouping_node_ids = [
        org["_id"]
        for org in db.RequestDoc.collection.find(
            {
                "_id": {"$in": list(all_tp_descendants)},
                "stakeholder": False,
                "report_types": [],
                "scan_types": [],
            },
            {"_id": 1},
        )
    ]

    if grouping_node_ids:
        # Create required grouping node snapshots
        logging.info(
            "Creating grouping node snapshots needed for third-party reports..."
        )
        for grouping_node_id in grouping_node_ids:
            snapshot_rc = create_snapshot(
                db, cyhy_db_section, grouping_node_id, use_only_existing_snapshots=True
            )

            if snapshot_rc != 0:
                logging.error(
                    "Grouping node %s snapshot creation failed!", grouping_node_id
                )
                logging.error(
                    "Third-party snapshots (dependent on %s) cannot be created for: %s",
                    grouping_node_id,
                    tp_dependence_map[grouping_node_id],
                )
                # Add dependent third-party snapshot org IDs to failed list and
                # remove them from list of third_party_report_ids so that we
                # don't attempt to create them below.
                for org_id in tp_dependence_map[grouping_node_id]:
                    if org_id not in failed_tp_snaps:
                        failed_tp_snaps.append(org_id)
                    if org_id in third_party_report_ids:
                        third_party_report_ids.remove(org_id)

    # TODO Create third-party snapshots in threads
    # See https://github.com/cisagov/cyhy-reports/issues/60
    logging.info("Creating third-party snapshots...")
    for third_party_id in third_party_report_ids:
        snapshot_rc = create_snapshot(
            db, cyhy_db_section, third_party_id, use_only_existing_snapshots=True
        )

        if snapshot_rc == 0:
            successful_tp_snaps.append(third_party_id)
        else:
            failed_tp_snaps.append(third_party_id)

    logging.info(
        "Time to create all grouping node and third-party snapshots:"
        " {:.2f} minutes".format(round(time.time() - all_tps_start_time, 1) / 60)
    )
    return successful_tp_snaps, failed_tp_snaps


def generate_third_party_reports(
    db, cyhy_db_section, scan_db_section, nolog, successful_tp_snaps
):
    successful_tp_reports = list()
    failed_tp_reports = list()

    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    all_tpr_start_time = time.time()

    for third_party_id in successful_tp_snaps:
        logging.info("Starting third-party report for: {}".format(third_party_id))
        report_start_time = time.time()
        if nolog:
            report_process = subprocess.Popen(
                [
                    "cyhy-report",
                    "--encrypt",
                    "--final",
                    "--nolog",
                    "--cyhy-section",
                    cyhy_db_section,
                    "--scan-section",
                    scan_db_section,
                    third_party_id,
                ],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            report_process = subprocess.Popen(
                [
                    "cyhy-report",
                    "--encrypt",
                    "--final",
                    "--cyhy-section",
                    cyhy_db_section,
                    "--scan-section",
                    scan_db_section,
                    third_party_id,
                ],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        data, err = report_process.communicate()

        report_duration = time.time() - report_start_time

        if report_process.returncode == 0:
            logging.info(
                "Successful third-party report generated:"
                " {} ({:.2f} s)".format(third_party_id, round(report_duration, 2))
            )
            successful_tp_reports.append(third_party_id)
        else:
            logging.error("Third-party report failed: {}".format(third_party_id))
            logging.error("Stderr failure detail: {} {}".format(data, err))
            failed_tp_reports.append(third_party_id)

    logging.info(
        "Time to create all third-party reports:"
        " {:.2f} minutes".format(round(time.time() - all_tpr_start_time, 1) / 60)
    )
    return successful_tp_reports, failed_tp_reports


def pull_cybex_ticket_csvs(db):
    today = current_time.strftime("%Y%m%d")

    def save_csv(filename, data):
        path = os.path.join(WEEKLY_REPORT_BASE_DIR, CYBEX_CSV_DIR, filename)
        logging.info("Creating CSV {}".format(filename))
        with open(path, "w") as csv_file:
            csv_file.write(data)
        # Copy the CSVs into the "latest" scorecard directory.  This is for the
        # automated report sending.
        latest_path = os.path.join(
            WEEKLY_REPORT_BASE_DIR, SCORECARD_OUTPUT_DIR, "latest", filename
        )
        shutil.copy(path, latest_path)

    save_csv(
        "cybex_open_tickets_critical_{}.csv".format(today),
        cybex_queries.csv_get_open_tickets(db, CRITICAL_SEVERITY),
    )
    save_csv(
        "cybex_closed_tickets_critical_{}.csv".format(today),
        cybex_queries.csv_get_closed_tickets(db, CRITICAL_SEVERITY),
    )
    save_csv(
        "cybex_open_tickets_high_{}.csv".format(today),
        cybex_queries.csv_get_open_tickets(db, HIGH_SEVERITY),
    )
    save_csv(
        "cybex_closed_tickets_high_{}.csv".format(today),
        cybex_queries.csv_get_closed_tickets(db, HIGH_SEVERITY),
    )


def main():
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["CYHY_DB_SECTION"])
    logging.basicConfig(
        filename=os.path.join(WEEKLY_REPORT_BASE_DIR, LOG_FILE),
        format="%(asctime)-15s %(levelname)s - %(message)s",
        level=LOGGING_LEVEL,
    )
    start_time = time.time()
    logging.info("BEGIN")

    cyhy_db_section = args["CYHY_DB_SECTION"]
    scan_db_section = args["SCAN_DB_SECTION"]
    use_docker = 1
    # To track third-party snapshot and report status
    successful_tp_snaps = list()
    failed_tp_snaps = list()
    successful_tp_reports = list()
    failed_tp_reports = list()

    create_subdirectories()
    if args["--no-dock"]:
        # take action to run scorecard and reports without docker
        use_docker = 0

    nolog = False
    if args["--no-log"]:
        nolog = True

    if not args["--no-pause"]:
        control_id = pause_commander(db)
        logging.info("Pausing Commander...")
        logging.info("Control ID: %s", control_id)

    # Check for cyhy-reports container running
    if use_docker == 1:
        if (
            subprocess.call(
                "docker run --rm --volume /etc/cyhy:/etc/cyhy --volume {}:/home/cyhy {}/cyhy-reports:stable cyhy-report -h".format(
                    WEEKLY_REPORT_BASE_DIR, NCATS_DHUB_URL
                ),
                shell=True,
            )
            != 0
        ):
            # Output of stderr & out if fail
            logging.critical("Docker: cyhy-reports container failed")
            sys.exit(-1)

    try:
        logging.info("Generating CybEx Scorecard...")

        # list all cybex json files and grab latest filename
        os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_JSON_OUTPUT_DIR))
        old_json_files = filter(os.path.isfile, glob.glob("cybex_scorecard_*.json"))
        old_json_files.sort(key=lambda x: os.path.getmtime(x))
        if old_json_files:
            previous_scorecard_filename = old_json_files[-1]
            logging.info(
                "  Using previous CybEx Scorecard JSON: {}".format(
                    previous_scorecard_filename
                )
            )
            scorecard_success = gen_weekly_scorecard(
                previous_scorecard_filename,
                cyhy_db_section,
                scan_db_section,
                use_docker,
                nolog,
            )
            if scorecard_success == 0:
                logging.info("Successfully generated CybEx Scorecard")
                # Create latest directory where we can stash a copy of the
                # latest CybEx scorecard.  This is for the automated sending of
                # reports.
                latest = os.path.join(
                    WEEKLY_REPORT_BASE_DIR, SCORECARD_OUTPUT_DIR, "latest"
                )
                if os.path.exists(latest):
                    shutil.rmtree(latest)
                os.mkdir(latest)
                # Find the CybEx scorecard that was just created in the
                # scorecard output directory and copy it to the latest
                # directory.
                cybex_scorecards = filter(
                    os.path.isfile,
                    glob.glob(
                        "../{}/Federal_Cyber_Exposure_Scorecard-*.pdf".format(
                            SCORECARD_OUTPUT_DIR
                        )
                    ),
                )
                cybex_scorecards.sort(key=lambda x: os.path.getmtime(x))
                shutil.copy(cybex_scorecards[-1], latest)

                # Move newly-created cybex_scorecard.json to SCORECARD_JSON_OUTPUT_DIR
                new_json_files = filter(
                    os.path.isfile, glob.glob("cybex_scorecard_*.json")
                )
                new_json_files.sort(key=lambda x: os.path.getmtime(x))
                shutil.move(
                    new_json_files[-1],
                    os.path.join(
                        WEEKLY_REPORT_BASE_DIR,
                        SCORECARD_JSON_OUTPUT_DIR,
                        new_json_files[-1],
                    ),
                )
            else:
                logging.warning("Failed to generate CybEx Scorecard")
        else:
            logging.critical(
                "No previous CybEx Scorecard JSON file found - continuing without creating CybEx Scorecard"
            )

        if args["--no-snapshots"]:
            # Skip creation of snapshots
            logging.info("Skipping snapshot creation due to --no-snapshots parameter")
            reports_to_generate = create_list_of_reports_to_generate(db)
        else:
            reports_to_generate = generate_weekly_snapshots(db, cyhy_db_section)

        sample_report(
            cyhy_db_section, scan_db_section, nolog
        )  # Create the sample (anonymized) report
        gen_weekly_reports(
            db, reports_to_generate, cyhy_db_section, scan_db_section, use_docker, nolog
        )

        # Fetch list of third-party report IDs with children; if a third-party
        # report has no children, there is no point in generating a report
        # for it
        third_party_report_ids = [
            i["_id"]
            for i in db.RequestDoc.collection.find(
                {
                    "report_types": REPORT_TYPE.CYHY_THIRD_PARTY,
                    "children": {"$exists": True, "$ne": []},
                },
                {"_id": 1},
            )
        ]

        if third_party_report_ids:
            if args["--no-snapshots"]:
                # Skip creation of third-party snapshots
                logging.info(
                    "Skipping third-party snapshot creation "
                    "due to --no-snapshots parameter"
                )
                successful_tp_snaps = third_party_report_ids
            else:
                # Create snapshots needed for third-party reports
                successful_tp_snaps, failed_tp_snaps = create_third_party_snapshots(
                    db, cyhy_db_section, third_party_report_ids
                )

            # Generate third-party reports
            successful_tp_reports, failed_tp_reports = generate_third_party_reports(
                db, cyhy_db_section, scan_db_section, nolog, successful_tp_snaps
            )
        else:
            logging.info("No third-party reports to generate; skipping this step")

        pull_cybex_ticket_csvs(db)
    finally:
        sync_all_tallies(db)
        if not args["--no-pause"]:
            resume_commander(db, control_id)

        if args["--no-snapshots"]:
            logging.info("Number of snapshots generated: 0")
            logging.info("Number of snapshots failed: 0")
        else:
            logging.info(
                "Number of snapshots generated: %d", len(successful_snapshots),
            )
            logging.info(
                "  Third-party snapshots generated: %d", len(successful_tp_snaps),
            )
            logging.info(
                "Number of snapshots failed: %d", len(failed_snapshots),
            )
            logging.info(
                "  Third-party snapshots failed: %d", len(failed_tp_snaps),
            )
            if failed_snapshots:
                logging.error("Failed snapshots:")
                for i in failed_snapshots:
                    if i in failed_tp_snaps:
                        logging.error("%s (third-party)", i)
                    else:
                        logging.error(i)

        logging.info(
            "Number of reports generated: %d",
            len(successful_reports + successful_tp_reports),
        )
        logging.info(
            "  Third-party reports generated: %d", len(successful_tp_reports),
        )
        logging.info(
            "Number of reports failed: %d", len(failed_reports + failed_tp_reports)
        )
        logging.info(
            "  Third-party reports failed: %d", len(failed_tp_reports),
        )
        if failed_reports or failed_tp_reports:
            logging.info("Failed reports:")
            for i in failed_reports + failed_tp_reports:
                if i in failed_tp_reports:
                    logging.error("%s (third-party)", i)
                else:
                    logging.error(i)

        logging.info("Total time: %.2f minutes", (time.time() - start_time) / 60)
        logging.info("END\n\n")


if __name__ == "__main__":
    main()
