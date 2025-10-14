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

# Standard Python Libraries
import distutils.dir_util
import glob
import logging
import os
import shutil
import subprocess
import sys
import threading
import time

# Third-Party Libraries
from bson import ObjectId
from collections import defaultdict
from docopt import docopt
import numpy

# cisagov Libraries
from cyhy.core import SCAN_TYPE
from cyhy.core.common import REPORT_TYPE, REPORT_PERIOD
from cyhy.db import database, CHDatabase
from cyhy.util import util
from ncats_webd import cybex_queries

current_time = util.utcnow()

LOGGING_LEVEL = logging.INFO
LOG_FILE = "snapshots_reports_scorecard_automation.log"
REPORT_THREADS = 70
SNAPSHOT_THREADS = 70

NCATS_DHUB_URL = "dhub.ncats.cyber.dhs.gov:5001"

WEEKLY_REPORT_BASE_DIR = "/var/cyhy/reports/output"
SCORECARD_OUTPUT_DIR = "scorecards"
SCORECARD_JSON_OUTPUT_DIR = "JSONfiles"
CYBEX_CSV_DIR = "cybex_csvs"
CYHY_REPORT_DIR = os.path.join(
    "report_archive", "reports{}".format(current_time.strftime("%Y%m%d"))
)

# Global variables and their associated thread locks
snapshots_to_generate = list()
stg_lock = threading.Lock()

successful_snapshots = list()
ss_lock = threading.Lock()

failed_snapshots = list()
fs_lock = threading.Lock()

snapshot_durations = list()
sd_lock = threading.Lock()

reports_to_generate = list()
rtg_lock = threading.Lock()

successful_reports = list()
sr_lock = threading.Lock()

failed_reports = list()
fr_lock = threading.Lock()

report_durations = list()
rd_lock = threading.Lock()

# Global variables for third-party snapshots and reports. Note that
# snapshots_to_generate and reports_to_generate are reused for third-party
# snapshots and reports, so we don't need variables for them below.
successful_tp_snapshots = list()
failed_tp_snapshots = list()
tp_snapshot_durations = list()
successful_tp_reports = list()
failed_tp_reports = list()
tp_report_durations = list()

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


def create_list_of_reports_to_generate(db, third_party):
    """Create list of organizations that need reports generated."""
    if third_party:
        # Find orgs that receive third-party reports and that also have
        # children.  If a third-party org has no children, there is no point in
        # generating a report since it would be empty.
        query = {
            "children": {"$exists": True, "$ne": []},
            "report_types": REPORT_TYPE.CYHY_THIRD_PARTY,
        }
    else:
        # Find orgs that receive weekly CyHy reports
        query = {
            "report_period": REPORT_PERIOD.WEEKLY,
            "report_types": REPORT_TYPE.CYHY,
        }
    return sorted(
        [
            i["_id"] for i in db.RequestDoc.collection.find(
                query, {"_id": 1}
            )
        ]
    )


def create_list_of_snapshots_to_generate(db, reports_to_generate):
    """Create list of organizations that need snapshots generated."""
    # Find all descendants of orgs that get reports and have children
    report_org_descendants = set()
    for i in db.RequestDoc.collection.find(
        {
            "_id": {"$in": reports_to_generate},
            "children": {"$exists": True, "$ne": []},
        },
        {"_id": 1},
    ):
        report_org_descendants.update(db.RequestDoc.get_all_descendants(i["_id"]))

    # Create the list of snapshots to generate by removing
    # report_org_descendants (their snapshots will be created when their
    # parent org's snapshot is created)
    return sorted(list(set(reports_to_generate) - report_org_descendants))


def generate_snapshot(db, cyhy_db_section, org_id, third_party):
    """Generate a snapshot for a specified organization."""
    snapshot_start_time = time.time()

    snapshot_command = ["cyhy-snapshot", "--section", cyhy_db_section, "create"]

    # Third-party snapshots are based on snapshots that already exist
    if third_party:
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

    # Determine org's descendants for logging below
    org_descendants = list()
    # Third-party snapshots are based on descendant snapshots that already
    # exist, so there is no need to log their descendants here because those
    # descendant snapshots are not being created by this script.
    if not third_party:
        if snapshot_process.returncode == 0:
            org_descendants = db.SnapshotDoc.find_one(
                {"latest": True, "owner": org_id}
            )["descendants_included"]
        else:
            # Since snapshot creation failed, we must use this (slower)
            # method of finding all descendants
            org_descendants = db.RequestDoc.get_all_descendants(org_id)

    if snapshot_process.returncode == 0:
        logging.info(
            "[%s] Successful %ssnapshot: %s (%.2f s)",
            threading.current_thread().name,
            "third-party " if third_party else "",
            org_id,
            snapshot_duration,
        )
        with sd_lock:
            if third_party:
                tp_snapshot_durations.append((org_id, snapshot_duration))
            else:
                snapshot_durations.append((org_id, snapshot_duration))
        with ss_lock:
            if third_party:
                successful_tp_snapshots.append(org_id)
            else:
                successful_snapshots.append(org_id)
                if org_descendants:
                    logging.info(
                        "[%s]  - Includes successful descendant snapshot(s): %s",
                        threading.current_thread().name,
                        org_descendants,
                    )
                    successful_snapshots.extend(org_descendants)
    else:
        logging.error(
            "[%s] Unsuccessful %ssnapshot: %s (%.2f s)",
            threading.current_thread().name,
            "third-party " if third_party else "",
            org_id,
            snapshot_duration,
        )
        with fs_lock:
            if third_party:
                failed_tp_snapshots.append(org_id)
            else:
                failed_snapshots.append(org_id)
                if org_descendants:
                    logging.error(
                        "[%s]  - Unsuccessful descendant snapshot(s): %s",
                        threading.current_thread().name,
                        org_descendants,
                    )
                    failed_snapshots.extend(org_descendants)
        logging.error(
            "[%s] Stderr failure detail: %s %s",
            threading.current_thread().name,
            data,
            err,
        )
    return snapshot_process.returncode


def generate_snapshots_from_list(db, cyhy_db_section, third_party):
    """Attempt to generate a snapshot for each organization in a global list.

    Each thread pulls an organization ID from the global list
    (snapshots_to_generate) and attempts to generate a snapshot for it."""
    global snapshots_to_generate
    while True:
        with stg_lock:
            logging.debug(
                "[%s] %d %ssnapshot(s) left to generate",
                threading.current_thread().name,
                len(snapshots_to_generate),
                "third-party " if third_party else "",
            )
            if snapshots_to_generate:
                org_id = snapshots_to_generate.pop(0)
            else:
                logging.info(
                    "[%s] No %ssnapshots left to generate - thread exiting",
                    threading.current_thread().name,
                    "third-party " if third_party else "",
                )
                break

        logging.info(
            "[%s] Starting %ssnapshot for: %s",
            threading.current_thread().name,
            "third-party " if third_party else "",
            org_id,
        )
        generate_snapshot(db, cyhy_db_section, org_id, third_party)


def prepare_for_third_party_snapshots(db, cyhy_db_section, tp_reports_to_generate):
    """Create grouping node snapshots needed for third-party reports
    
    Also, return the list of third-party snapshots and reports to create.
    """
    start_time = time.time()

    # Build set of all third-party descendants and a map of each descendant to
    # the third-parties that require them.
    all_tp_descendants = set()
    tp_dependence_map = defaultdict(list)
    logging.info("Building third-party descendant dependence map...")
    for tp_org_id in tp_reports_to_generate:
        descendants = db.RequestDoc.get_all_descendants(tp_org_id)
        all_tp_descendants.update(descendants)
        for d in descendants:
            tp_dependence_map[d].append(tp_org_id)
    logging.info("Done")

    # Check descendants of all third-party orgs for "grouping nodes",
    # then create snapshots, since they otherwise wouldn't have them.
    logging.info("Checking for grouping nodes in descendants of third-party orgs...")
    grouping_node_ids = [
        org["_id"]
        for org in db.RequestDoc.collection.find(
            # Grouping nodes are not stakeholders and have no report_types or scan_types
            {
                "_id": {"$in": list(all_tp_descendants)},
                "report_types": [],
                "scan_types": [],
                "stakeholder": False,
            },
            {"_id": 1},
        )
    ]
    logging.info("Done")

    if grouping_node_ids:
        # Create required grouping node snapshots
        logging.info(
            "Creating grouping node snapshots needed for third-party reports..."
        )
        for grouping_node_id in grouping_node_ids:
            # Grouping nodes are treated as third-party orgs when creating
            # snapshots since both require the "--use-only-existing-snapshots"
            # flag to be set.
            snapshot_rc = generate_snapshot(
                db, cyhy_db_section, grouping_node_id, third_party=True
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
                # remove them from list of tp_reports_to_generate so that we
                # don't attempt to create reports for them later.
                global failed_tp_snapshots
                for tp_org_id in tp_dependence_map[grouping_node_id]:
                    if tp_org_id not in failed_tp_snapshots:
                        failed_tp_snapshots.append(tp_org_id)
                    if tp_org_id in tp_reports_to_generate:
                        tp_reports_to_generate.remove(tp_org_id)
    else:
        logging.info("No grouping node snapshots needed for third-party reports")
    
    time_to_generate_grouping_node_snapshots = time.time() - start_time
    logging.info(
        "Time to complete grouping node snapshots: %.2f minutes",
        time_to_generate_grouping_node_snapshots / 60,
    )
    return sorted(list(tp_reports_to_generate)), time_to_generate_grouping_node_snapshots


def manage_snapshot_threads(db, cyhy_db_section, third_party):
    """Spawn threads to generate snapshots
    
    Build the list of snapshots to be generated, then spawn the threads that
    generate the snapshots."""
    start_time = time.time()

    # This variable is only used when generating third-party snapshots
    time_to_generate_grouping_node_snapshots = 0

    global reports_to_generate
    global snapshots_to_generate
    # No thread locking is needed here for reports_to_generate or
    # snapshots_to_generate because we are still single-threaded at this point

    if third_party:
        # Some extra preparation must be done before generating third-party snapshots
        snapshots_to_generate, time_to_generate_grouping_node_snapshots = \
        prepare_for_third_party_snapshots(db, cyhy_db_section, reports_to_generate)
    else:
        logging.info("Building list of snapshots to generate...")
        snapshots_to_generate = create_list_of_snapshots_to_generate(
            db, reports_to_generate
        )

    logging.debug(
        "%d %ssnapshots to generate: %s",
        len(snapshots_to_generate),
        "third-party " if third_party else "",
        snapshots_to_generate,
    )

    # List to keep track of our snapshot creation threads
    snapshot_threads = list()

    # Start up the threads to create snapshots
    for t in range(SNAPSHOT_THREADS):
        try:
            snapshot_thread = threading.Thread(
                target=generate_snapshots_from_list,
                args=(db, cyhy_db_section, third_party)
            )
            snapshot_threads.append(snapshot_thread)
            snapshot_thread.start()
        except Exception:
            logging.error(
                "Unable to start %ssnapshot thread #%s",
                "third-party " if third_party else "",
                t,
            )

    # Wait until each thread terminates
    for snapshot_thread in snapshot_threads:
        snapshot_thread.join()
    
    # If there are any failed snapshots, attempt to regenerate them in a
    # single-threaded manner, which may be less likely to fail than the
    # multi-threaded approach.
    #
    # Make a copy of the list of failed snapshots to iterate over, then clear
    # the global list of failed snapshots.  Any failures will be re-added during
    # this regeneration attempt.
    if third_party:
        global failed_tp_snapshots
        snapshots_to_reattempt = list(failed_tp_snapshots)
        failed_tp_snapshots = list()
    else:
        global failed_snapshots
        snapshots_to_reattempt = list(failed_snapshots)
        failed_snapshots = list()
    
    if snapshots_to_reattempt:
        reattempt_start_time = time.time()
        logging.info("Attempting to regenerate failed %ssnapshots: %s",
                     "third-party " if third_party else "",
                     snapshots_to_reattempt)
        for org_id in snapshots_to_reattempt:
            generate_snapshot(db, cyhy_db_section, org_id, third_party)
        logging.info(
            "Time to complete re-attempting failed %ssnapshots: %.2f minutes",
            "third-party " if third_party else "",
            (time.time() - reattempt_start_time) / 60,
        )
  
    time_to_generate_snapshots = time.time() - start_time
    logging.info(
        "Time to complete %ssnapshots: %.2f minutes",
        "third-party " if third_party else "",
        time_to_generate_snapshots / 60,
    )

    # Remove any failed snapshots from the list of reports to generate
    if third_party:
        reports_to_generate = set(reports_to_generate) - set(failed_tp_snapshots)
    else:
        reports_to_generate = set(reports_to_generate) - set(failed_snapshots)

    return sorted(list(reports_to_generate)), time_to_generate_snapshots, time_to_generate_grouping_node_snapshots


def generate_report(org_id, cyhy_db_section, scan_db_section, use_docker, nolog, third_party):
    """Generate a report for a specified organization."""
    report_start_time = time.time()
    logging.info(
        "[%s] Starting %sreport for: %s",
        threading.current_thread().name,
        "third-party " if third_party else "",
        org_id,
    )

    # Base command for generating a report (we will append the org_id below)
    report_command = [
        "cyhy-report",
        "--cyhy-section",
        cyhy_db_section,
        "--scan-section",
        scan_db_section,
        "--final",
        "--encrypt",
    ]

    if use_docker == 1:
        report_command = [
            "docker",
            "run",
            "--rm",
            "--volume",
            "/etc/cyhy:/etc/cyhy",
            "--volume",
            "{}:/home/cyhy".format(CYHY_REPORT_DIR),
            "{}/cyhy-reports:stable".format(NCATS_DHUB_URL),
        ] + report_command        

    # Skip logging if requested
    if nolog:
        report_command.append("--nolog")

    report_command.append(org_id)

    report_process = subprocess.Popen(
        report_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    data, err = report_process.communicate()

    report_duration = time.time() - report_start_time

    if report_process.returncode == 0:
        logging.info(
            "[%s] Successful %sreport: %s (%.2f s)",
            threading.current_thread().name,
            "third-party " if third_party else "",
            org_id,
            report_duration,
        )
        with rd_lock:
            if third_party:
                tp_report_durations.append((org_id, report_duration))
            else:
                report_durations.append((org_id, report_duration))
        with sr_lock:
            if third_party:
                successful_tp_reports.append(org_id)
            else:
                successful_reports.append(org_id)
    else:
        logging.info(
            "[%s] Unsuccessful %sreport: %s (%.2f s)",
            threading.current_thread().name,
            "third-party " if third_party else "",
            org_id,
            report_duration,
        )
        logging.info(
            "[%s] Stderr report detail: %s%s",
            threading.current_thread().name,
            data,
            err,
        )
        with fr_lock:
            if third_party:
                failed_tp_reports.append(org_id)
            else:
                failed_reports.append(org_id)


def generate_reports_from_list(cyhy_db_section, scan_db_section, use_docker, nolog, third_party):
    """Attempt to generate a report for each organization in a global list.

    Each thread pulls an organization ID from the global list
    (reports_to_generate) and attempts to generate a report for it."""
    global reports_to_generate
    while True:
        with rtg_lock:
            logging.debug(
                "[%s] %d %sreports left to generate",
                threading.current_thread().name,
                len(reports_to_generate),
                "third-party " if third_party else "",
            )
            if reports_to_generate:
                org_id = reports_to_generate.pop(0)
            else:
                logging.info(
                    "[%s] No %sreports left to generate - exiting",
                    threading.current_thread().name,
                    "third-party " if third_party else "",
                )
                break
        generate_report(
            org_id,
            cyhy_db_section,
            scan_db_section,
            use_docker,
            nolog,
            third_party
        )


def manage_report_threads(cyhy_db_section, scan_db_section, use_docker, nolog, third_party):
    """Spawn the threads that generate the reports."""
    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    start_time = time.time()

    global reports_to_generate
    # No thread locking is needed here for reports_to_generate because we are
    # still single-threaded at this point
    logging.debug(
        "%d %sreports to generate: %s",
        len(reports_to_generate),
        "third-party " if third_party else "",
        reports_to_generate,
    )

    # List to keep track of our report creation threads
    report_threads = list()

    # Start up the threads to create reports
    for t in range(REPORT_THREADS):
        try:
            report_thread = threading.Thread(
                target=generate_reports_from_list,
                args=(cyhy_db_section, scan_db_section, use_docker, nolog, third_party),
            )
            report_threads.append(report_thread)
            report_thread.start()
            # Add a short pause between starting threads to avoid overloading
            # the system
            time.sleep(0.5)
        except Exception:
            logging.error("Unable to start report thread #%s", t)

    # Wait until each thread terminates
    for report_thread in report_threads:
        report_thread.join()

    # If there are any failed reports, attempt to regenerate them in a
    # single-threaded manner, which may be less likely to fail than the
    # multi-threaded approach.
    #
    # Make a copy of the list of failed reports to iterate over, then clear the
    # global list of failed reports.  Any failures will be re-added during this
    # regeneration attempt.
    if third_party:
        global failed_tp_reports
        reports_to_reattempt = list(failed_tp_reports)
        failed_tp_reports = list()
    else:
        global failed_reports
        reports_to_reattempt = list(failed_reports)
        failed_reports = list()
    
    if reports_to_reattempt:
        reattempt_start_time = time.time()
        logging.info("Attempting to regenerate failed %sreports: %s",
                     "third-party " if third_party else "",
                     reports_to_reattempt)
        for org_id in reports_to_reattempt:
            generate_report(
                org_id,
                cyhy_db_section,
                scan_db_section,
                use_docker,
                nolog,
                third_party
            )
        logging.info(
            "Time to complete re-attempting failed %sreports: %.2f minutes",
            "third-party " if third_party else "",
            (time.time() - reattempt_start_time) / 60,
        )

    time_to_generate_reports = time.time() - start_time
    logging.info(
        "Time to complete %sreports: %.2f minutes",
        "third-party " if third_party else "",
        time_to_generate_reports / 60,
    )

    # Create a symlink to the latest reports.  This is for the
    # automated sending of reports.
    latest_cyhy_reports = os.path.join(WEEKLY_REPORT_BASE_DIR, "report_archive/latest")
    if os.path.exists(latest_cyhy_reports):
        os.remove(latest_cyhy_reports)
    os.symlink(
        os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR), latest_cyhy_reports
    )

    return time_to_generate_reports


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
    PAUSE_ITERATION_LIMIT = 90

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
        "cybex_open_tickets_potentially_risky_services_{}.csv".format(today),
        cybex_queries.csv_get_open_tickets(db, "risky_services"),
    )
    save_csv(
        "cybex_closed_tickets_potentially_risky_services_{}.csv".format(today),
        cybex_queries.csv_get_closed_tickets(db, "risky_services"),
    )
    save_csv(
        "cybex_open_tickets_urgent_{}.csv".format(today),
        cybex_queries.csv_get_open_tickets(db, "urgent"),
    )
    save_csv(
        "cybex_closed_tickets_urgent_{}.csv".format(today),
        cybex_queries.csv_get_closed_tickets(db, "urgent"),
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

    time_to_generate_snapshots = 0
    time_to_generate_reports = 0
    time_to_generate_grouping_node_snapshots = 0
    time_to_generate_tp_snapshots = 0
    time_to_generate_tp_reports = 0

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

        global reports_to_generate
        # No thread locking is needed here for reports_to_generate because we
        # are still single-threaded at this point
        logging.info("Building list of reports to generate...")
        reports_to_generate = create_list_of_reports_to_generate(db, third_party=False)

        if args["--no-snapshots"]:
            # Skip creation of "regular" (non-third-party) snapshots
            logging.info("Skipping snapshot creation due to --no-snapshots parameter")
        else:
            # Generate all "regular" (non-third-party) snapshots and return the
            # updated list of reports to be generated
            reports_to_generate, time_to_generate_snapshots, \
            time_to_generate_grouping_node_snapshots = manage_snapshot_threads(
                db, cyhy_db_section, third_party=False
            )

        sample_report(
            cyhy_db_section, scan_db_section, nolog
        )  # Create the sample (anonymized) report

        # Generate all necessary "regular" (non-third-party) reports
        time_to_generate_reports = manage_report_threads(
            cyhy_db_section, scan_db_section, use_docker, nolog, third_party=False
        )

        # We reuse reports_to_generate here as we prepare to generate the
        # third-party reports.  Again, no thread locking is needed here for
        # because we are still single-threaded at this point.
        logging.info("Building list of third-party reports to generate...")
        reports_to_generate = create_list_of_reports_to_generate(db, third_party=True)

        if args["--no-snapshots"]:
            # Skip creation of third-party snapshots
            logging.info("Skipping third-party snapshot creation due to --no-snapshots parameter")
        else:
            # Generate all third-party snapshots and return the updated list of
            # third-party reports to be generated
            reports_to_generate, time_to_generate_tp_snapshots, \
            time_to_generate_grouping_node_snapshots = manage_snapshot_threads(
                db, cyhy_db_section, third_party=True
            )

        # Generate all necessary third-party reports
        time_to_generate_tp_reports = manage_report_threads(
            cyhy_db_section, scan_db_section, use_docker, nolog, third_party=True
        )

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
                "Number of snapshots generated: %d",
                len(successful_snapshots) + len(successful_tp_snapshots),
            )
            logging.info(
                "  Number of third-party and grouping node snapshots generated: %d",
                len(successful_tp_snapshots),
            )
            logging.info(
                "Number of snapshots failed: %d",
                len(failed_snapshots) + len(failed_tp_snapshots),
            )
            logging.info(
                "  Number of third-party and grouping node snapshots failed: %d",
                len(failed_tp_snapshots),
            )
            if failed_snapshots or failed_tp_snapshots:
                logging.error("Failed snapshots (reports not attempted):")
                for i in failed_snapshots + failed_tp_snapshots:
                    if i in failed_tp_snapshots:
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
            logging.error("Failed reports:")
            for i in failed_reports + failed_tp_reports:
                if i in failed_tp_reports:
                    logging.error("%s (third-party)", i)
                else:
                    logging.error(i)

        if not args["--no-snapshots"] and len(snapshot_durations) > 0:
            logging.info("Snapshot performance:")
            durations = [x[1] for x in snapshot_durations]
            max = numpy.max(durations)
            logging.info("  Longest snapshot: %.1f seconds (%.1f minutes)", max, max / 60)
            median = numpy.median(durations)
            logging.info("  Median snapshot: %.1f seconds (%.1f minutes)", median, median / 60)
            mean = numpy.mean(durations)
            logging.info("  Mean snapshot: %.1f seconds (%.1f minutes)", mean, mean / 60)
            min = numpy.min(durations)
            logging.info("  Shortest snapshot: %.1f seconds (%.1f minutes)", min, min / 60)

            snapshot_durations.sort(key=lambda tup: tup[1], reverse=True)
            logging.info("Longest snapshots:")
            for i in snapshot_durations[:10]:
                logging.info("  %s: %.1f seconds (%.1f minutes)", i[0], i[1], i[1] / 60)

            if len(tp_snapshot_durations) > 0:
                logging.info("Third-party and grouping node snapshot performance:")
                durations = [x[1] for x in tp_snapshot_durations]
                max = numpy.max(durations)
                logging.info("  Longest third-party/grouping node snapshot: %.1f seconds (%.1f minutes)",
                             max, max / 60)
                median = numpy.median(durations)
                logging.info("  Median third-party/grouping node snapshot: %.1f seconds (%.1f minutes)",
                             median, median / 60)
                mean = numpy.mean(durations)
                logging.info("  Mean third-party/grouping node snapshot: %.1f seconds (%.1f minutes)",
                             mean, mean / 60)
                min = numpy.min(durations)
                logging.info("  Shortest third-party/grouping node snapshot: %.1f seconds (%.1f minutes)",
                             min, min / 60)

                tp_snapshot_durations.sort(key=lambda tup: tup[1], reverse=True)
                logging.info("Longest third-party/grouping node snapshots:")
                for i in tp_snapshot_durations[:10]:
                    logging.info("  %s: %.1f seconds (%.1f minutes)",
                                 i[0], i[1], i[1] / 60)

        if len(report_durations) > 0:
            logging.info("Report performance:")
            durations = [x[1] for x in report_durations]
            max = numpy.max(durations)
            logging.info("  Longest report: %.1f seconds (%.1f minutes)",
                         max, max / 60)
            median = numpy.median(durations)
            logging.info("  Median report: %.1f seconds (%.1f minutes)",
                         median, median / 60)
            mean = numpy.mean(durations)
            logging.info("  Mean report: %.1f seconds (%.1f minutes)",
                         mean, mean / 60)
            min = numpy.min(durations)
            logging.info("  Shortest report: %.1f seconds (%.1f minutes)",
                         min, min / 60)

            report_durations.sort(key=lambda tup: tup[1], reverse=True)
            logging.info("Longest reports:")
            for i in report_durations[:10]:
                logging.info("  %s: %.1f seconds (%.1f minutes)", i[0], i[1], i[1] / 60)

        if len(tp_report_durations) > 0:
            logging.info("Third-party report performance:")
            durations = [x[1] for x in tp_report_durations]
            max = numpy.max(durations)
            logging.info("  Longest third-party report: %.1f seconds (%.1f minutes)",
                         max, max / 60)
            median = numpy.median(durations)
            logging.info("  Median third-party report: %.1f seconds (%.1f minutes)",
                         median, median / 60)
            mean = numpy.mean(durations)
            logging.info("  Mean third-party report: %.1f seconds (%.1f minutes)",
                         mean, mean / 60)
            min = numpy.min(durations)
            logging.info("  Shortest third-party report: %.1f seconds (%.1f minutes)",
                         min, min / 60)

            tp_report_durations.sort(key=lambda tup: tup[1], reverse=True)
            logging.info("Longest third-party reports:")
            for i in tp_report_durations[:10]:
                logging.info("  %s: %.1f seconds (%.1f minutes)",
                             i[0], i[1], i[1] / 60)

        logging.info("Time to generate snapshots: %.2f minutes",
                     time_to_generate_snapshots / 60)
        logging.info("Time to generate reports: %.2f minutes",
                     time_to_generate_reports / 60)
        logging.info("Time to generate grouping node snapshots: %.2f minutes",
                     time_to_generate_grouping_node_snapshots / 60)
        logging.info("Time to generate third-party snapshots: %.2f minutes",
                     time_to_generate_tp_snapshots / 60)
        logging.info("Time to generate third-party reports: %.2f minutes",
                     time_to_generate_tp_reports / 60)
        logging.info("Total time: %.2f minutes", (time.time() - start_time) / 60)
        logging.info("END\n\n")


if __name__ == "__main__":
    main()
