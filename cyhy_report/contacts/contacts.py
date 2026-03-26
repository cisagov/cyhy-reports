"""Output all points of contact in the CyHy database in CSV format.

Usage:
  cyhy-contacts [--section SECTION]
  cyhy-contacts (-h | --help)
  cyhy-contacts --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
"""

# Standard Python Libraries
from __future__ import print_function
from csv import DictWriter
import StringIO
import sys

# Third-Party Libraries
from docopt import docopt

# cisagov Libraries
from cyhy.db import database

def generate_contacts_csv(db):
    """Generate a CSV file containing all points of contact in the CyHy database."""
    output = StringIO.StringIO()

    fields = (
        "Org ID",
        "Org Name",
        "Org Type",
        "Org Retired",
        "Contact Name",
        "Contact Email",
        "Contact Type",
    )

    writer = DictWriter(output, fields)
    writer.writeheader()

    # Iterate through all request documents
    for doc in db.RequestDoc.find().sort("_id", 1):
        row = {
            "Org ID": doc["_id"],
            "Org Name": doc["agency"]["name"],
            "Org Type": doc["agency"].get("type", "N/A"),
            "Org Retired": doc.get("retired", False),
        }
        for contact in doc["agency"].get("contacts", []):
            row.update(
                {
                    "Contact Name": contact.get("name", "N/A"),
                    "Contact Email": contact.get("email", "N/A"),
                    "Contact Type": contact.get("type", "N/A"),
                }
            )
            try:
                writer.writerow(row)
            except UnicodeEncodeError as e:
                # We catch this exception so we can output a helpful
                # message with the context to allow the user to fix the
                # request document.  Without this we would have to go in
                # and edit this file to determine which org is the
                # problem child.
                print("Non-ASCII character in contact of org {org_id}: {exception}".format(org_id=doc["_id"], exception=e), file=sys.stderr)
                raise

    return output


def main():
    """Output all points of contact in the CyHy database in CSV format."""
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    try:
        print(generate_contacts_csv(db).getvalue())
    except UnicodeDecodeError:
        print("Unable to handle non-ASCII characters in a request doc.", file=sys.stderr)
