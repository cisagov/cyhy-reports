#!/usr/bin/env python
'''
Usage:
  create_snapshots_reports_scorecard.py [options] CYHY_DB_SECTION SCAN_DB_SECTION

Generate the weekly cybex scorecard and all the weekly persistent reports.

Options:
  -h, --help            show this help message and exit
  --no-dock             do not use docker for scorecard and reports
  --no-snapshots        do not create a scorecard or snapshots, jump straight to reports
  --no-log              do not log that this scorecard and these reports were created
'''

from docopt import docopt
from cyhy.db import database, CHDatabase
from cyhy.core import Config, STATUS, STAGE, SCAN_TYPE
from cyhy.util import util
from sets import Set
from collections import defaultdict
import datetime, time
import subprocess
from bson import ObjectId
import sys
import glob
import os
from cyhy.core.common import REPORT_TYPE, REPORT_PERIOD
from socket import gethostname
import logging
import urllib2
import threading
import multiprocessing
import math
import distutils.dir_util
import shutil

current_time = util.utcnow()

LOGGING_LEVEL = logging.INFO
LOG_FILE = 'snapshots_reports_scorecard_automation.log'
REPORT_THREADS = 16

NCATS_DHUB_URL = 'dhub.ncats.cyber.dhs.gov:5001'
NCATS_WEB_URL = 'web.data.ncats.cyber.dhs.gov'

WEEKLY_REPORT_BASE_DIR = '/var/cyhy/reports'
SCORECARD_OUTPUT_DIR =  'scorecards'
SCORECARD_JSON_OUTPUT_DIR = 'JSONfiles'
CYBEX_CSV_DIR = 'cybex_csvs'
CYHY_REPORT_DIR = os.path.join('report_archive', 'reports{}'.format(current_time.strftime('%Y%m%d')))

# Global variables for threading
reports_generated = []
reports_failed = []
longest_reports = []

def create_subdirectories():
    # Create all required subdirectories (if they don't already exist)
    for subdir in [SCORECARD_OUTPUT_DIR, SCORECARD_JSON_OUTPUT_DIR,
                   CYBEX_CSV_DIR, CYHY_REPORT_DIR]:
        distutils.dir_util.mkpath(os.path.join(WEEKLY_REPORT_BASE_DIR, subdir))

def gen_weekly_scorecard(previous_scorecard_filename, cyhy_db_section, scan_db_section, use_docker, nolog):
    response = None
    if use_docker == 1:
        if nolog:
            response = subprocess.call(['docker', 'run', '--rm', '--volume', '/etc/cyhy:/etc/cyhy', '--volume', '{}:/home/cyhy'.format(SCORECARD_OUTPUT_DIR), '{}/cyhy-reports:stable'.format(NCATS_DHUB_URL), 'cyhy-cybex-scorecard', '--nolog', '-f', cyhy_db_section, scan_db_section, os.path.join(SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename)])
        else:
            response = subprocess.call(['docker', 'run', '--rm', '--volume', '/etc/cyhy:/etc/cyhy', '--volume', '{}:/home/cyhy'.format(SCORECARD_OUTPUT_DIR), '{}/cyhy-reports:stable'.format(NCATS_DHUB_URL), 'cyhy-cybex-scorecard', '-f', cyhy_db_section, scan_db_section, os.path.join(SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename)])
    else:
        logging.info('  Not using Docker to create CybEx Scorecard...')
        os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_OUTPUT_DIR))
        if nolog:
            response = subprocess.call(['cyhy-cybex-scorecard','--nolog','-f', cyhy_db_section, scan_db_section, os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename)])
        else:
            response = subprocess.call(['cyhy-cybex-scorecard','-f', cyhy_db_section, scan_db_section, os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_JSON_OUTPUT_DIR, previous_scorecard_filename)])

    return response

#def gen_election_report(cyhy_db_section):
#    output = subprocess.Popen(['cyhy-snapshot','-s',cyhy_db_section,'create','--use-only-existing-snapshots','ELECTION'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#    data, err = output.communicate('yes')
#    return_code = output.returncode
#    if return_code == 0:
#        logging.info('Successful ELECTION snap')
#    else:
#        logging.info('Failed ELECTION snap')
#        logging.info('Stderr failure detail: %s%s', data, err)
#    p = subprocess.Popen(['cyhy-report','-s',cyhy_db_section,'-n','-e','-f','ELECTION'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
#    data, err = p.communicate()
#    return_code = p.returncode
#    if return_code == 0:
#        logging.info('Successful ELECTION report')
#    else:
#        logging.info('Failed ELECTION report')
#        logging.info('Stderr report detail: %s%s', data, err)

def sample_report(cyhy_db_section, nolog):
    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    logging.info('Creating SAMPLE report...')
    if nolog:
        p = subprocess.Popen(['cyhy-report','--nolog','-s',cyhy_db_section,'-a','DHS'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(['cyhy-report','-s',cyhy_db_section,'-a','DHS'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    data, err = p.communicate()
    return_code = p.returncode
    
    if return_code == 0:
        logging.info('SAMPLE report successfully created')
    else:
        logging.info('Failed to create SAMPLE report')
        logging.info('Stderr report detail: %s%s', data, err)

def create_weekly_snapshots(db, cyhy_db_section):
    start = time.time()
    successful_descendant_snaps = []
    successful_snaps = []
    failure_snaps = []
    longest_snaps = []
    request_list = sorted([i['_id'] for i in db.RequestDoc.collection.find({'report_period':REPORT_PERIOD.WEEKLY,'report_types':REPORT_TYPE.CYHY}, {'_id':1})])
    # request_list = ['49ers', 'USAID', 'Hawaii', 'DAS-BEST', 'COC', 'DHS', 'COLA', 'COA', 'COGG', 'AGRS', 'FEC', 'FHFA', 'FMC', 'LPG', 'MSFG', 'OGE', 'PRC', 'SJI', 'USAB', 'VB']
    # request_list = ['49ers', 'USAID', 'Hawaii', 'DAS-BEST', 'COC', 'DHS', 'COLA', 'COA', 'COGG']

    for i in request_list:
        # If the customer is in the decsendant org list then don't snap, add to successful
        # Assume that parent orgs will always be snapped first
        if i in successful_descendant_snaps:
            successful_snaps.append(i)
            logging.info('Added to successful snaps (descendant_snapshot): %s', i)
            continue

        snap_time = time.time()
        output = subprocess.Popen(['cyhy-snapshot', '-s', cyhy_db_section, 'create', i], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        data, err = output.communicate('yes')
        snap_time = time.time() - snap_time
        longest_snaps.append((i,snap_time))
        return_code = output.returncode

        if return_code == 0:
            successful_snaps.append(i)
            # TODO: If the org has children & their requestdoc has CYHY, add to descendant org list
            successful_descendant_snaps += db.RequestDoc.get_all_descendants(i)
            logging.info('Added to successful snaps: %s (%.2f s)', i, round(snap_time,2))
        else:
            failure_snaps.append(i)
            logging.info('Added to failed snaps: %s', i)
            logging.info('Stderr failure detail: %s%s', data, err)

    longest_snaps.sort(key=lambda tup: tup[1], reverse=True)
    logging.info('Longest Snapshots:')
    for i in longest_snaps[:10]:
        logging.info('%s: %s seconds', i[0], str(round(i[1],1)))
    logging.info('Time to complete snapshots: %.2f minutes', (round(time.time() - start,1)/60))
    return successful_snaps, failure_snaps

# Create a function called "chunks" with two arguments, l and n:
def chunks(l, n):
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

def create_reports(customer_list, cyhy_db_section, use_docker, nolog):
    for i in customer_list:
        report_time = time.time()
        logging.info('%s Starting report for: %s', threading.current_thread().name, i)
        if use_docker == 1:
            if nolog:
                p = subprocess.Popen(['docker', 'run', '--rm', '--volume', '/etc/cyhy:/etc/cyhy', '--volume', '{}:/home/cyhy'.format(CYHY_REPORT_DIR), '{}/cyhy-reports:stable'.format(NCATS_DHUB_URL), 'cyhy-report', '--nolog', '-s', cyhy_db_section, '-f', '-e', i], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['docker', 'run', '--rm', '--volume', '/etc/cyhy:/etc/cyhy', '--volume', '{}:/home/cyhy'.format(CYHY_REPORT_DIR), '{}/cyhy-reports:stable'.format(NCATS_DHUB_URL), 'cyhy-report', '-s', cyhy_db_section, '-f', '-e', i], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            if nolog:
                p = subprocess.Popen(['cyhy-report', '--nolog', '-s', cyhy_db_section, '-f', '-e', i], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                p = subprocess.Popen(['cyhy-report', '-s', cyhy_db_section, '-f', '-e', i], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        data, err = p.communicate()
        report_time = time.time() - report_time
        longest_reports.append((i,report_time))
        return_code = p.returncode
        if return_code == 0:
            logging.info('%s Successful report generated: %s (%.2f s)', threading.current_thread().name, i, round(report_time,2))
            reports_generated.append(i)
        else:
            logging.info('%s Failure to generate report: %s', threading.current_thread().name, i)
            logging.info('%s Stderr report detail: %s%s', threading.current_thread().name, data, err)
            reports_failed.append(i)

def gen_weekly_reports(db, successful_snaps, cyhy_db_section, use_docker, nolog):
    os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR))
    start = time.time()
    # Create a list that from the results of the function chunks:
    threads = []
    thread_list = list(chunks(successful_snaps, int(math.ceil(float(len(successful_snaps))/float(REPORT_THREADS)))))
    for i in thread_list:
        try:
           t = threading.Thread(target=create_reports, args=(i, cyhy_db_section, use_docker, nolog))
           threads.append(t)
           t.start()
           time.sleep(0.5)
        except:
           print "Error: Unable to start thread"
    for t in threads:
        t.join()
    longest_reports.sort(key=lambda tup: tup[1], reverse=True)
    logging.info('Longest Reports:')
    for i in longest_reports[:10]:
        logging.info('%s: %s seconds', i[0], str(round(i[1],1)))
    logging.info('Time to complete reports: %.2f minutes', (round(time.time() - start,1)/60))

    # Create a symlink to the latest reports.  This is for the
    # automated sending of reports.
    latest_cyhy_reports = os.path.join(WEEKLY_REPORT_BASE_DIR,
                                       'report_archive/latest')
    if os.path.exists(latest_cyhy_reports):
        os.remove(latest_cyhy_reports)
    os.symlink(os.path.join(WEEKLY_REPORT_BASE_DIR, CYHY_REPORT_DIR),
               latest_cyhy_reports)

    return reports_generated, reports_failed

def sync_all_tallies(db):
    owners = []
    for r in db.RequestDoc.find({'scan_types':SCAN_TYPE.CYHY}).sort('_id', 1):
        owners.append(r['_id'])

    logging.info('Syncing all tallies...')
    for owner in owners:
        tally = db.TallyDoc.get_by_owner(owner)
        if tally:
            tally.sync(db)
    logging.info('Done syncing all tallies')

def pause_commander(db):
    PAUSE_ITERATION_LIMIT = 24          # number of iterations to wait before giving up
    PAUSE_ITERATION_WAIT_SECONDS = 5    # number of seconds to wait between each check to see if the commander has paused
    pause_iteration_count = 0
    ch = CHDatabase(db)
    doc = ch.pause_commander('create_snapshots_reports_scorecard', 'report generation')
    logging.info('Requesting commander pause (control doc id = {_id})'.format(**doc))
    while not doc['completed']:
        pause_iteration_count += 1
        logging.info('  Waiting for commander to pause... (#{})'.format(pause_iteration_count))
        time.sleep(PAUSE_ITERATION_WAIT_SECONDS)
        if pause_iteration_count == PAUSE_ITERATION_LIMIT:
            logging.error('Commander failed to pause!')
            doc.delete()
            logging.info('Commander control doc {_id} successfully deleted'.format(**doc))
            sys.exit(return_code)
            return None
        doc.reload()
    return doc['_id']

def resume_commander(db, pause_doc_id):
    # if failed_reports > 5; keep the commander paused & notify of failure
    if len(reports_failed) > 5:
        logging.error('Large number of reports failing. Keeping commander paused')
        return False
    doc = db.SystemControlDoc.find_one({'_id':ObjectId(pause_doc_id)})
    if not doc:
        logging.error('Could not find a control doc with id {}'.format(pause_doc_id))
        return False
    doc.delete()
    logging.info('Commander control doc {} successfully deleted (commander should resume unless other control docs exist)'.format(pause_doc_id))
    return True

def pull_cybex_ticket_csvs():
    today = current_time.strftime('%Y%m%d')
    url_tail = ('c2', 'c3', 'c5', 'c6')
    file_name = ('cybex_open_tickets_critical_', 'cybex_closed_tickets_critical_', 'cybex_open_tickets_high_', 'cybex_closed_tickets_high_')

    for u, f in zip(url_tail, file_name):
        current_csv_url = 'http://{}/api/cybex/?{}'.format(NCATS_WEB_URL, u)
        current_csv_filename = '{}{}.csv'.format(f, today)
        current_csv_path = os.path.join(WEEKLY_REPORT_BASE_DIR, CYBEX_CSV_DIR, current_csv_filename)
        logging.info('Downloading CSV: {} -> {}'.format(current_csv_url, current_csv_filename))
        try:
            response = urllib2.urlopen(current_csv_url)
            html = response.read()
            text_file = open(current_csv_path, "w")
            text_file.write(html)
            text_file.close()
        except Exception as e:
            logging.error('Failed to download {} from {}'.format(current_csv_filename, current_csv_url))
            logging.error(e)

        # Copy the CSV into the "latest" scorecard directory.  This is
        # for the automated report sending.
        shutil.copy(current_csv_path,
                    os.path.join(WEEKLY_REPORT_BASE_DIR,
                                 SCORECARD_OUTPUT_DIR,
                                 "latest",
                                 current_csv_filename))

def main():
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['CYHY_DB_SECTION'])
    logging.basicConfig(filename=os.path.join(WEEKLY_REPORT_BASE_DIR, LOG_FILE), format='%(asctime)-15s %(levelname)s - %(message)s', level=LOGGING_LEVEL)
    start = time.time()
    logging.info('BEGIN')

    cyhy_db_section = args['CYHY_DB_SECTION']
    scan_db_section = args['SCAN_DB_SECTION']
    use_docker = 1
    success_snaps = list()
    failed_snaps = list()
    reports_generated = list()
    reports_failed = list()

    create_subdirectories()
    if args['--no-dock']:
        # take action to run scorecard and reports without docker
        use_docker = 0

    nolog = False
    if args['--no-log']:
        nolog = True

    control_id = pause_commander(db)
    logging.info('Pausing Commander...')
    logging.info('Control ID: %s', control_id)

    # Check for cyhy-reports container running
    if use_docker == 1:
        if subprocess.call('docker run --rm --volume /etc/cyhy:/etc/cyhy --volume {}:/home/cyhy {}/cyhy-reports:stable cyhy-report -h'.format(WEEKLY_REPORT_BASE_DIR, NCATS_DHUB_URL), shell=True) != 0:
            # Output of stderr & out if fail
            logging.critical('Docker: cyhy-reports container failed')
            sys.exit(-1)

    try:
        logging.info('Generating CybEx Scorecard...')

        # list all cybex json files and grab latest filename
        os.chdir(os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_JSON_OUTPUT_DIR))
        old_json_files = filter(os.path.isfile, glob.glob('cybex_scorecard_*.json'))
        old_json_files.sort(key=lambda x: os.path.getmtime(x))
        if old_json_files:
            previous_scorecard_filename = old_json_files[-1]
            logging.info('  Using previous CybEx Scorecard JSON: {}'.format(previous_scorecard_filename))
            scorecard_success = gen_weekly_scorecard(previous_scorecard_filename, cyhy_db_section, scan_db_section, use_docker, nolog)
            if scorecard_success == 0:
                logging.info('Successfully generated CybEx Scorecard')
                # Create latest directory where we can stash a copy of the
                # latest CybEx scorecard.  This is for the automated sending of
                # reports.
                latest = os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_OUTPUT_DIR, 'latest')
                if os.path.exists(latest):
                    shutil.rmtree(latest)
                os.mkdir(latest)
                # Find the CybEx scorecard that was just created in the
                # scorecard output directory and copy it to the latest
                # directory.
                cybex_scorecards = filter(os.path.isfile, glob.glob('../{}/Federal_Cyber_Exposure_Scorecard-*.pdf'.format(SCORECARD_OUTPUT_DIR)))
                cybex_scorecards.sort(key=lambda x: os.path.getmtime(x))
                shutil.copy(cybex_scorecards[-1], latest)

                # Move newly-created cybex_scorecard.json to SCORECARD_JSON_OUTPUT_DIR
                new_json_files = filter(os.path.isfile, glob.glob('cybex_scorecard_*.json'))
                new_json_files.sort(key=lambda x: os.path.getmtime(x))
                shutil.move(new_json_files[-1], os.path.join(WEEKLY_REPORT_BASE_DIR, SCORECARD_JSON_OUTPUT_DIR, new_json_files[-1]))
            else:
                logging.warning('Failed to generate CybEx Scorecard')
        else:
            logging.critical('No previous CybEx Scorecard JSON file found - continuing without creating CybEx Scorecard')

        if args['--no-snapshots']:
            # Skip creation of snapshots
            logging.info('Skipping snapshot creation due to --no-snapshots parameter')
            success_snaps = sorted([i['_id'] for i in db.RequestDoc.collection.find({'report_period':REPORT_PERIOD.WEEKLY,'report_types':REPORT_TYPE.CYHY}, {'_id':1})])
            # For testing:
            # success_snaps = ['49ers', 'USAID', 'Hawaii', 'DAS-BEST', 'COC', 'DHS', 'SDSD', 'COLA', 'COA', 'COGG', 'AGRS', 'FEC', 'FHFA', 'FMC', 'LPG', 'MSFG', 'OGE', 'PRC', 'SJI', 'USAB', 'VB']
        else:
            success_snaps, failed_snaps = create_weekly_snapshots(db, cyhy_db_section)

        #gen_election_report(cyhy_db_section)

        sample_report(cyhy_db_section, nolog)  # Create the sample (anonymized) report
        reports_generated, reports_failed = gen_weekly_reports(db, success_snaps, cyhy_db_section, use_docker, nolog)
        pull_cybex_ticket_csvs()
    finally:
        sync_all_tallies(db)
        resume_commander(db,control_id)

        if args['--no-snapshots']:
            logging.info('Number of snapshots generated: 0')
            logging.info('Number of snapshots failed: 0')
        else:
            logging.info('Number of snapshots generated: %d', len(success_snaps))
            logging.info('Number of snapshots failed: %d', len(failed_snaps))
            if failed_snaps:
                logging.info('Failed snapshots:')
                for i in failed_snaps:
                    logging.info(i)

        logging.info('Number of reports generated: %d', len(reports_generated))
        logging.info('Number of reports failed: %d', len(reports_failed))
        if reports_failed:
            logging.info('Failed reports:')
            for i in reports_failed:
                logging.info(i)

        logging.info('Total time: %.2f minutes', (round(time.time() - start,1)/60))
        logging.info('END\n\n')

        # logging.info('Kicking off the emailing of reports...')
        # subprocess.call('/var/cyhy/cyhy-mailer/start.sh')
        # logging.info('Done.')

if __name__=='__main__':
    main()
