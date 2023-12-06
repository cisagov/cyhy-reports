#!/usr/bin/env python

"""Create CyHy notifications and email them out to CyHy points of contact.

Usage:
  create_send_notifications [options] CYHY_DB_SECTION
  create_send_notifications (-h | --help)

Options:
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug",
                         "info", "warning", "error", and "critical".
                         [default: warning]
"""

import distutils.dir_util
import logging
import os
import subprocess
import sys

import docopt

from cyhy.core import Config
from cyhy.db import database
from cyhy.util import util
from cyhy_report.cyhy_notification import NotificationGenerator

current_time = util.utcnow()

NOTIFICATIONS_BASE_DIR = "/var/cyhy/reports/output"
NOTIFICATION_ARCHIVE_DIR = os.path.join(
    "notification_archive", "notifications{}".format(current_time.strftime("%Y%m%d"))
)
CYHY_MAILER_DIR = "/var/cyhy/cyhy-mailer"


def create_output_directories():
    """Create all necessary output directories."""
    distutils.dir_util.mkpath(
        os.path.join(NOTIFICATIONS_BASE_DIR, NOTIFICATION_ARCHIVE_DIR)
    )

def build_notifications_org_list(db):
    """Return list of notifications to generate and 
       notifications not generated.

    This is the list of organization IDs that should
    have a notification generated and sent.
    """
    notifications_to_generate = set()
    cyhy_parent_ids = set()
    ticket_owner_ids = db.NotificationDoc.collection.distinct("ticket_owner")
    for request in db.RequestDoc.collection.find({"_id": {"$in": ticket_owner_ids}}, {"_id": 1, "report_types": 1}):
        if "CYHY" in request["report_types"]:
            # If the notification document's ticket owner has "CYHY" in its list of report_types,
            # then a notification should be generated for that owner:
            notifications_to_generate.add(request["_id"])
            logging.debug("Added {} to notifications_to_generate".format(request["_id"]))
        # Recursively check for any ancestors of the ticket owner that have "CYHY" in
        # their list of report_types.  If found, add them to the list of owners that
        # should get a notification.
        logging.debug("Checking for ancestors of {} with CYHY in their list of report_types".format(request["_id"]))
        cyhy_parent_ids.update(find_cyhy_parents(db, request["_id"]))
    notifications_to_generate.update(cyhy_parent_ids)
    notifications_not_generated = set(ticket_owner_ids) - notifications_to_generate
    return sorted(notifications_to_generate), list(notifications_not_generated)
          
def find_cyhy_parents(db, org_id):
    """Return parents/grandparents/etc. of an organization that have "CYHY" in their list of report_types.
    """

    # WARNING: Even though cyhy-suborg explicitly checks for and blocks
    # stakeholder cycles (e.g. org A is a descendant of org B, which is a
    # descendant of org A), if that guardrail is ever subverted, this function
    # will recursively overflow and fail.
    cyhy_parents = set()
    for request in db.RequestDoc.collection.find({"children": org_id}, {"_id": 1, "report_types": 1}):
        if "CYHY" in request["report_types"]:
            # There is an undocumented convention at CISA to set up CyHy
            # organizations with only one level of children (i.e. no
            # grandchildren orgs). Since it is only a convention and not an
            # enforced rule, we decided that following the hierarchy to the top
            # is the safest solution.
            cyhy_parents.add(request["_id"])
            # Found a parent of org_id with "CYHY" in their list of report_types,
            # so add it to our set
            logging.debug("{} - Adding to set of CYHY parents".format(request["_id"]))
        # Recursively call find_cyhy_parents() to check if this org has any parents
        # with "CYHY" in their list of report_types
        logging.debug("Checking for ancestors of {} with CYHY in their list of report_types".format(request["_id"]))
        cyhy_parents.update(find_cyhy_parents(db, request["_id"]))
    return cyhy_parents

def generate_notification_pdfs(db, org_ids, master_report_key): 
    """Generate all notification PDFs for a list of organizations."""
    num_pdfs_created = 0
    for org_id in org_ids:
        logging.info("{} - Starting to create notification PDF".format(org_id))
        generator = NotificationGenerator(
            db, org_id, final=True, encrypt_key=master_report_key
        )
        was_encrypted, results = generator.generate_notification()
        if was_encrypted:
            num_pdfs_created += 1
            logging.info("{} - Created encrypted notification PDF".format(org_id))
        elif results is not None and len(results["notifications"]) == 0:
            logging.info("{} - No notifications found, no PDF created".format(org_id))
        else:
            logging.error("{} - Unknown error occurred".format(org_id))
            return -1
    return num_pdfs_created


def main():
    """Set up logging and call the notification-related functions."""
    args = docopt.docopt(__doc__, version="1.0.0")
    # Set up logging
    log_level = args["--log-level"]
    try:
        logging.basicConfig(
            format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
        )
    except ValueError:
        logging.critical(
            '"{}" is not a valid logging level.  Possible values '
            "are debug, info, warning, and error.".format(log_level)
        )
        return 1

    # Set up database connection
    db = database.db_from_config(args["CYHY_DB_SECTION"])

    # Create all necessary output subdirectories
    create_output_directories()

    # Change to the correct output directory
    os.chdir(os.path.join(NOTIFICATIONS_BASE_DIR, NOTIFICATION_ARCHIVE_DIR))

    # Build list of orgs that should receive notifications
    notifications_org_ids, notifications_to_delete = build_notifications_org_list(db)
    logging.debug("Will attempt to generate notifications for {} orgs: {}".format(len(notifications_org_ids), notifications_org_ids))

    # Create notification PDFs for CyHy orgs
    master_report_key = Config(args["CYHY_DB_SECTION"]).report_key
    num_pdfs_created = generate_notification_pdfs(db, notifications_org_ids, master_report_key)
    logging.info("{} notification PDFs created".format(num_pdfs_created))

    # Create a symlink to the latest notifications.  This is for the
    # automated sending of notification emails.
    latest_notifications = os.path.join(
        NOTIFICATIONS_BASE_DIR, "notification_archive/latest"
    )
    if os.path.exists(latest_notifications):
        os.remove(latest_notifications)
    os.symlink(
        os.path.join(NOTIFICATIONS_BASE_DIR, NOTIFICATION_ARCHIVE_DIR),
        latest_notifications,
    )

    if num_pdfs_created:
        # Email all notification PDFs in
        # NOTIFICATIONS_BASE_DIR/notification_archive/latest
        os.chdir(CYHY_MAILER_DIR)
        p = subprocess.Popen(
            [
                "docker",
                "compose",
                "-f",
                "docker-compose.yml",
                "-f",
                "docker-compose.cyhy-notification.yml",
                "up",
            ],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        data, err = p.communicate()
        return_code = p.returncode

        if return_code == 0:
            logging.info("Notification emails successfully sent")
        else:
            logging.error("Failed to email notifications")
            logging.error("Stderr report detail: %s%s", data, err)

        # Determine true list of orgs that just had notifications generated,
        # either directly or via an ancestor org
        orgs_notified = db.NotificationDoc.collection.distinct(
            "ticket_owner", {"generated_for": {"$ne": []}})

        # Delete all NotificationDocs where generated_for is not []
        result = db.NotificationDoc.collection.delete_many(
            {"generated_for": {"$ne": []}}
        )
        logging.info(
            "Deleted {} notifications from DB (corresponding to "
            "those just emailed out)".format(result.deleted_count)
        )
    else:
        logging.info("Nothing to email - skipping this step")

    # Remove orgs from notifications_to_delete if they are in the list of orgs
    # that we just generated notifications for (most likely because the
    # notification was included in an ancestor org's notification)
    notifications_to_delete = sorted(set(notifications_not_generated) - set(orgs_notified))

    # Delete NotificationDocs belonging to organizations that we didn't
    # generate notifications for
    result = db.NotificationDoc.collection.delete_many(
        {"ticket_owner": {"$in": notifications_to_delete}}
    )
    logging.info(
        "Deleted {} notifications from DB owned by the following "
        "organizations which do not currently receive notification "
        "emails: {})".format(result.deleted_count, notifications_to_delete)
    )

    # Stop logging and clean up
    logging.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
