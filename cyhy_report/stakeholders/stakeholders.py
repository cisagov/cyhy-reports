"""Output all stakeholder information in the CyHy database in CSV format.

Usage:
  cyhy-stakeholders [--section SECTION]
  cyhy-stakeholders (-h | --help)
  cyhy-stakeholders --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
"""

# Standard Python Libraries
import csv
import StringIO

# Third-Party Libraries
from docopt import docopt

# cisagov Libraries
from cyhy.db import database

REGION_MAPPING = {
    "Region 1": ["CT", "MA", "ME", "NH", "RI", "VT"],
    "Region 2": ["NJ", "NY", "PR", "VI"],
    "Region 3": ["DE", "DC", "MD", "PA", "VA", "WV"],
    "Region 4": ["AL", "FL", "GA", "KY", "MS", "NC", "SC", "TN"],
    "Region 5": ["IL", "IN", "MI", "MN", "OH", "WI"],
    "Region 6": ["AR", "LA", "NM", "OK", "TX"],
    "Region 7": ["IA", "KS", "MO", "NE"],
    "Region 8": ["CO", "MT", "ND", "SD", "UT", "WY"],
    "Region 9": ["AZ", "CA", "HI", "NV", "AS", "GU", "MP"],
    "Region 10": ["AK", "ID", "OR", "WA"],
}

def get_first_snapshot_times(db, owners):
    """Return a dictionary with first snapshot times for a list of CyHy owner IDs.
    
    The dictionary key is the owner (entity) ID and the value is the start time
    of the first snapshot for that entity."""
    first_snapshot_time_by_owner = list(
        db.SnapshotDoc.collection.aggregate(
            [
                {"$match": {"owner": {"$in": owners}}},
                {"$project": {"owner": 1, "start_time": 1}},
                {"$sort": {"owner": 1, "start_time": 1}},
                {
                    "$group": {
                        "_id": "$owner",
                        "first_snapshot_start_time": {"$first": "$start_time"},
                    }
                },
                {"$sort": {"_id": 1}},
            ],
            allowDiskUse=True,
            cursor={},
        )
    )

    first_snapshot_time_dict = dict()
    for i in first_snapshot_time_by_owner:
        first_snapshot_time_dict[i["_id"]] = i["first_snapshot_start_time"]
    return first_snapshot_time_dict


def generate_stakeholders_csv(db):
    """Generate a CSV file containing all CyHy stakeholder information."""
    org_types = db.RequestDoc.get_owner_to_type_dict(stakeholders_only=True)
    stakeholder_ids = org_types.keys()
    first_snapshot_time_dict = get_first_snapshot_times(db, stakeholder_ids)

    all_CI_orgs = db.RequestDoc.get_all_descendants("CRITICAL_INFRASTRUCTURE")
    all_ELECTION_orgs = db.RequestDoc.get_all_descendants("ELECTION")
    all_FCEB_orgs = db.RequestDoc.get_all_descendants("FED_GOLD")

    CI_sectors = dict()
    for sector in db.RequestDoc.get_by_owner("CRITICAL_INFRASTRUCTURE")["children"]:
        CI_sectors[sector] = db.RequestDoc.get_by_owner(sector)["children"]

    new_csvfile = StringIO.StringIO()
    wr = csv.writer(new_csvfile)
    wr.writerow(
        (
            "Organization ID",
            "Organization Name",
            "City",
            "County",
            "State",
            "Region",
            "GNIS ID",
            "Organization Type",
            "Critical Infrastructure",
            "CI Sector",
            "Scheduler",
            "Reporting Period",
            "Election",
            "FCEB",
            "Enrolled",
            "First Scan",
        )
    )
    for org in db.RequestDoc.find({"_id": {"$in": stakeholder_ids}}).sort([("_id", 1)]):
        org_ELECTION = "No"
        if org["_id"] in all_ELECTION_orgs:
            org_ELECTION = "Yes"
        
        org_FCEB = "No"
        if org["_id"] in all_FCEB_orgs:
            org_FCEB = "Yes"

        first_scan = first_snapshot_time_dict.get(org["_id"], "No Scans")

        org_CI = "No"
        org_CI_sector = ""
        if org["_id"] in all_CI_orgs:
            org_CI = "Yes"
            for sector in CI_sectors.keys():
                if org["_id"] in CI_sectors[sector]:
                    org_CI_sector = sector
                    break
        
        org_state = org["agency"]["location"].get("state", "N/A")
        # Check the state against the REGION_MAPPING
        for region_name, states in REGION_MAPPING.items():
            if org_state in states:
                org_region = region_name
                break

        wr.writerow(
            (
                org["_id"],
                org["agency"]["name"],
                org["agency"]["location"]["name"].encode("utf-8"),
                org["agency"]["location"]["county"],
                org["agency"]["location"]["state"],
                org_region,
                org["agency"]["location"]["gnis_id"],
                org_types[org["_id"]],
                org_CI,
                org_CI_sector,
                org["scheduler"],
                org["report_period"],
                org_ELECTION,
                org_FCEB,
                org.get("enrolled"),
                first_scan,
            )
        )

    return new_csvfile


def main():
    """Output all CyHy stakeholder information in CSV format."""
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    print(generate_stakeholders_csv(db).getvalue())
