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
from csv import DictWriter
import StringIO

# Third-Party Libraries
from docopt import docopt

# cisagov Libraries
from cyhy.db import database

def generate_contacts_csv(db):
    all_request_docs = db.RequestDoc.find().sort("_id", 1)
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

    for doc in all_request_docs:
        for contact in doc["agency"].get("contacts", []):
            row = {
                "Org ID": doc["_id"],
                "Org Name": doc["agency"]["name"],
                "Org Type": doc["agency"].get("type", "N/A"),
                "Org Retired": doc.get("retired", False),
                "Contact Name": contact.get("name", "N/A"),
                "Contact Email": contact.get("email", "N/A"),
                "Contact Type": contact.get("type", "N/A"),
            }
            writer.writerow(row)

    return output


def main():
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    print(generate_contacts_csv(db).getvalue())
