#!/usr/bin/env python

'''Create Cyber Hygiene Binding Operational Directive (BOD) Scorecard PDF.

Usage:
  cyhy-bod-scorecard [options] BOD_EFFECTIVE_DATE PREVIOUS_SCORECARD_JSON_FILE EXCEPTIONS_GRANTED_JSON_FILE
  cyhy-bod-scorecard (-h | --help)
  cyhy-bod-scorecard --version

Options:
  -d --debug                     Keep intermediate files for debugging.
  -f --final                     Remove draft watermark.
  -h --help                      Show this screen.           
  -s SECTION --section=SECTION   Configuration section to use.
  --version                      Show version.
'''

# Standard Python Libraries
import codecs
import csv
from datetime import timedelta
from dateutil import parser, tz
import json
import os
import shutil
import subprocess
import sys
import tempfile

# Third-Party Libraries
import chevron
from docopt import docopt
from pyPdf import PdfFileWriter, PdfFileReader

# cisagov Libraries
from cyhy.core import *
from cyhy.db import CHDatabase, database
from cyhy.util import *

# constants
SCORING_ENGINE_VERSION = '1.0'
CURRENTLY_SCANNED_DAYS = 14  # Number of days in the past that an org's tally doc was last changed; a.k.a. a 'currently-scanned' org
BEFORE_THE_DAWN_OF_CYHY = time_to_utc(parser.parse("20000101"))

# Do not include the orgs below (based on _id) in the Scorecard
EXEMPT_ORGS = []

MUSTACHE_FILE = 'bod_scorecard.mustache'
REPORT_JSON = 'bod_scorecard.json'
REPORT_PDF = 'bod_scorecard.pdf'
REPORT_TEX = 'bod_scorecard.tex'
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
PDF_CAPTURE_JS = 'pdf_capture.js'
BOD_WEB_SERVER = 'http://web.data.ncats.dhs.gov:5000'
BOD_WEB_CHART1_URL = BOD_WEB_SERVER + '/bod/chart1'
BOD_WEB_CHART1_FILE = 'bod_chart1.pdf'
BOD_WEB_CHART2_URL = BOD_WEB_SERVER + '/bod/chart2'
BOD_WEB_CHART2_FILE = 'bod_chart2.pdf'
BOD_WEB_CHART_WIN_WIDTH = '920'     # Size of the viewport (virtual browser window)
BOD_WEB_CHART_WIN_HEIGHT = '325'
BOD_WEB_CHART1_CSV_URL = BOD_WEB_SERVER + '/bod/?c1'
BOD_WEB_CHART1_CSV_FILE = 'BOD-graph.csv'

class ScorecardGenerator(object):
    def __init__(self, db, bod_effective_date, previous_scorecard_json_file, exceptions_granted_json_file, debug=False, final=False):
        self.__db = db
        self.__generated_time = utcnow()
        self.__bod_effective_date = bod_effective_date
        self.__results = dict() # reusable query results
        self.__requests = None
        self.__tallies = []
        self.__debug = debug
        self.__draft = not final
        self.__scorecard_doc = {'scores':[]}
        self.__cfo_act_orgs = []
        self.__cfo_orgs_with_criticals = []
        self.__cfo_orgs_without_criticals = []
        self.__all_scanned_cfo_orgs = []
        self.__cfo_not_scanned_orgs = []
        self.__non_cfo_orgs_with_criticals = []
        self.__non_cfo_orgs_without_criticals = []
        self.__non_cfo_not_scanned_orgs = []
        self.__all_scanned_non_cfo_orgs = []
        self.__all_scanned_orgs = []
        self.__previous_scorecard_data = json.load(codecs.open(previous_scorecard_json_file,'r', encoding='utf-8'))
        self.__exceptions_granted_data = json.load(codecs.open(exceptions_granted_json_file,'r', encoding='utf-8'))
        
    def __open_critical_tix_opened_in_date_range_pl(self, start_date, end_date):
        return [
               {'$match': {'open':True, 'details.severity':4, 'false_positive':False, 'time_opened':{'$gte':start_date, '$lt':end_date}}},
               {'$group': {'_id': {'owner':'$owner'},
                           'open_criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION
               
    def __open_critical_tix_opened_in_date_range_for_orgs_pl(self, start_date, end_date, parent_org, descendant_orgs):
        return [
               {'$match': {'open':True, 'details.severity':4, 'false_positive':False, 'time_opened':{'$gte':start_date, '$lt':end_date},
                           'owner':{'$in':[parent_org] + descendant_orgs}}},
               {'$group': {'_id': {'owner':parent_org},
                           'open_criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION

    def __critical_tix_open_on_date_open_since_date_pl(self, open_on_date, open_since_date):
        return [
               {'$match': {'details.severity':4, 'false_positive':False, 'time_opened':{'$lte':open_since_date},
                           '$or':[{'time_closed':{'$gt':open_on_date}}, {'time_closed':None}]}},
               {'$group': {'_id': {'owner':'$owner'},
                           'criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION
               
    def __critical_tix_open_on_date_open_since_date_for_orgs_pl(self, open_on_date, open_since_date, parent_org, descendant_orgs):
        return [
               {'$match': {'details.severity':4, 'false_positive':False, 'time_opened':{'$lte':open_since_date},
                           '$or':[{'time_closed':{'$gt':open_on_date}}, {'time_closed':None}],
                           'owner':{'$in':[parent_org] + descendant_orgs}}},
               {'$group': {'_id': {'owner':parent_org},
                           'criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION

    def __closed_critical_tix_open_on_date_pl(self, open_on_date, closed_by_date):
        return [
               {'$match': {'open':False, 'details.severity':4, 'false_positive':False, 'time_opened':{'$lte':open_on_date},
                           'time_closed':{'$gt':open_on_date, '$lte':closed_by_date}}},
               {'$group': {'_id': {'owner':'$owner'},
                           'closed_criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION
               
    def __closed_critical_tix_open_on_date_for_orgs_pl(self, open_on_date, closed_by_date, parent_org, descendant_orgs):
        return [
               {'$match': {'open':False, 'details.severity':4, 'false_positive':False, 'time_opened':{'$lte':open_on_date},
                           'time_closed':{'$gt':open_on_date, '$lte':closed_by_date},
                           'owner':{'$in':[parent_org] + descendant_orgs}}},
               {'$group': {'_id': {'owner':parent_org},
                           'closed_criticals_count':{'$sum':1}
                          }
               }
               ], database.TICKET_COLLECTION

    def __active_hosts_pl(self):
        return [
               {'$match': {'state.up':True}},
               {'$group': {'_id': {'owner':'$owner'},
                           'active_hosts_count':{'$sum':1}
                          }
               }
               ], database.HOST_COLLECTION
               
    def __active_hosts_for_orgs_pl(self, parent_org, descendant_orgs):
        return [
               {'$match': {'state.up':True, 'owner':{'$in':[parent_org] + descendant_orgs}}},
               {'$group': {'_id': {'owner':parent_org},
                           'active_hosts_count':{'$sum':1}
                          }
               }
               ], database.HOST_COLLECTION
               
    def __run_queries(self):
        # Get request docs for all orgs that have BOD in their report_types
        self.__requests = list(self.__db.RequestDoc.find({'report_types':REPORT_TYPE.BOD}))
        bod_orgs = []
        for r in self.__requests:
            bod_orgs.append(r['_id'])
        
        # Build up list of BOD org tallies that were updated within past CURRENTLY_SCANNED_DAYS days
        for tally in list(self.__db.TallyDoc.find({'_id':{'$in':bod_orgs}})):
            if tally['last_change'] >= self.__generated_time - timedelta(days=CURRENTLY_SCANNED_DAYS):
                self.__tallies.append(tally)                # Append the tally if it's been changed recently
            else:       # Check if this org has any descendants with tallies that have been changed recently
                tally_descendant_orgs = self.__db.RequestDoc.get_all_descendants(tally['_id'])
                if tally_descendant_orgs:
                    for tally_descendant in list(self.__db.TallyDoc.find({'_id':{'$in':tally_descendant_orgs}})):
                        if tally_descendant['last_change'] >= self.__generated_time - timedelta(days=CURRENTLY_SCANNED_DAYS):
                            self.__tallies.append(tally)    # Append the top-level org's tally if the descendant has been changed recently
                            break                           # No need to check any other descendants
                                    
        # Get list of 'CFO Act' orgs
        self.__cfo_act_orgs = self.__db.RequestDoc.find_one({'_id':'FED_CFO_ACT'})['children']
        
        # If an org has descendants, we only want the top-level org to show up in the Scorecard
        # Make list of orgs that have children and their request docs so their child data can be accumulated later
        orgs_with_descendants = []
        requests_with_descendants = []
        for r in self.__requests:
            if r.get('children'):
                orgs_with_descendants.append(r['_id'])
                requests_with_descendants.append(r)
        
        # Get relevant critical ticket data
        pipeline_collection = self.__open_critical_tix_opened_in_date_range_pl(BEFORE_THE_DAWN_OF_CYHY, self.__generated_time)
        self.__results['open_critical_tix'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        prev_scorecard_generated_time = parser.parse(self.__previous_scorecard_data['generated_time'])
        pipeline_collection = self.__open_critical_tix_opened_in_date_range_pl(prev_scorecard_generated_time, self.__generated_time)
        self.__results['open_critical_tix_opened_since_previous_scorecard'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__open_critical_tix_opened_in_date_range_pl(self.__generated_time - timedelta(days=30), self.__generated_time)
        self.__results['open_critical_tix_opened_less_than_30_days_ago'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__open_critical_tix_opened_in_date_range_pl(BEFORE_THE_DAWN_OF_CYHY, self.__generated_time - timedelta(days=90))
        self.__results['open_critical_tix_opened_more_than_90_days_ago'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__critical_tix_open_on_date_open_since_date_pl(self.__bod_effective_date, self.__bod_effective_date)
        self.__results['critical_tix_open_at_bod_start'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__closed_critical_tix_open_on_date_pl(self.__bod_effective_date, self.__generated_time)
        self.__results['critical_tix_open_at_bod_start_now_closed'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__critical_tix_open_on_date_open_since_date_pl(self.__bod_effective_date, 
                                                                                  self.__bod_effective_date - timedelta(days=30))
        self.__results['critical_tix_open_more_than_30_days_at_bod_start'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = self.__active_hosts_pl()
        self.__results['active_hosts'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        
        # Throw out data from orgs with descendants
        # list(self.__results[results_field]) iterates over a *copy* of the list so items can be properly removed from the original
        for results_field in ['open_critical_tix', 'open_critical_tix_opened_less_than_30_days_ago',
                              'open_critical_tix_opened_since_previous_scorecard',
                              'open_critical_tix_opened_more_than_90_days_ago',
                              'critical_tix_open_at_bod_start', 'critical_tix_open_at_bod_start_now_closed',
                              'critical_tix_open_more_than_30_days_at_bod_start', 'active_hosts']:
                              for r in list(self.__results[results_field]):
                                  if r['_id']['owner'] in orgs_with_descendants:
                                      self.__results[results_field].remove(r)
                                      
        # Pull grouped data for orgs with descendants and add it to results
        for r in requests_with_descendants:
            descendants = self.__db.RequestDoc.get_all_descendants(r['_id'])
            pipeline_collection = self.__open_critical_tix_opened_in_date_range_for_orgs_pl(BEFORE_THE_DAWN_OF_CYHY, self.__generated_time, r['_id'], descendants)
            self.__results['open_critical_tix'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__open_critical_tix_opened_in_date_range_for_orgs_pl(prev_scorecard_generated_time, self.__generated_time, r['_id'], descendants)
            self.__results['open_critical_tix_opened_since_previous_scorecard'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__open_critical_tix_opened_in_date_range_for_orgs_pl(self.__generated_time - timedelta(days=30), self.__generated_time, r['_id'], descendants)
            self.__results['open_critical_tix_opened_less_than_30_days_ago'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__open_critical_tix_opened_in_date_range_for_orgs_pl(BEFORE_THE_DAWN_OF_CYHY, self.__generated_time - timedelta(days=90), r['_id'], descendants)
            self.__results['open_critical_tix_opened_more_than_90_days_ago'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__critical_tix_open_on_date_open_since_date_for_orgs_pl(self.__bod_effective_date, self.__bod_effective_date, r['_id'], descendants)
            self.__results['critical_tix_open_at_bod_start'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__closed_critical_tix_open_on_date_for_orgs_pl(self.__bod_effective_date, self.__generated_time, r['_id'], descendants)
            self.__results['critical_tix_open_at_bod_start_now_closed'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = self.__critical_tix_open_on_date_open_since_date_for_orgs_pl(self.__bod_effective_date, self.__bod_effective_date - timedelta(days=30), r['_id'], descendants)
            self.__results['critical_tix_open_more_than_30_days_at_bod_start'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            
            pipeline_collection = self.__active_hosts_for_orgs_pl(r['_id'], descendants)
            self.__results['active_hosts'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
        
    def __populate_scorecard_doc(self):        
        # Go through each request doc and check if the org has a current tally doc
        for r in self.__requests:
            currentlyScanned = False
            score = { 'previous_scorecard_open_criticals_more_than_30_days':0,
                      'delta_open_criticals_more_than_30_days':0, 
                      'open_criticals_more_than_30_days':0,
                      'open_criticals':0,
                      'open_criticals_since_previous_scorecard':0, 
                      'open_criticals_past_30_days':0,
                      'open_criticals_more_than_90_days':0,
                      'exceptions_granted':0,
                      'open_criticals_at_bod_start':0,
                      'open_criticals_at_bod_start_now_closed':0,
                      'open_criticals_at_bod_start_percent_closed':'N/A',
                      'open_criticals_at_bod_start_open_more_than_30_days':0,
                      'open_criticals_at_bod_start_percent_open_more_than_30_days':'N/A',
                      'open_criticals_percent_open_more_than_30_days':'N/A',
                      'active_hosts':0
                    }
            score['owner'] = r['_id']
            score['acronym'] = r['agency']['acronym']
            score['name'] = r['agency']['name']
            if r['_id'] in self.__cfo_act_orgs:
                score['cfo_act_org'] = True
            else:
                score['cfo_act_org'] = False
            for t in self.__tallies:
                if t['_id'] == r['_id']:  # Found a current tally that matches this request (org)
                    currentlyScanned = True
                    for i in self.__previous_scorecard_data['all_scanned_orgs_alpha']:
                        if i['owner'] == score['owner']:  #Found info for the current org
                            score['previous_scorecard_open_criticals_more_than_30_days'] = i['open_criticals_more_than_30_days']
                            break
                    for i in self.__results['open_critical_tix']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals'] = i['open_criticals_count']
                            break
                    for i in self.__results['open_critical_tix_opened_since_previous_scorecard']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_since_previous_scorecard'] = i['open_criticals_count']
                            break
                    for i in self.__results['open_critical_tix_opened_less_than_30_days_ago']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_past_30_days'] = i['open_criticals_count']
                            break
                    for i in self.__results['open_critical_tix_opened_more_than_90_days_ago']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_more_than_90_days'] = i['open_criticals_count']
                            break
                    for i in self.__exceptions_granted_data['orgs_with_exceptions_granted']:
                        if i['owner'] == score['owner']:  #Found info for the current org
                            score['exceptions_granted'] = i['exceptions']
                            break
                    for i in self.__results['critical_tix_open_at_bod_start']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_at_bod_start'] = i['criticals_count']
                            break
                    for i in self.__results['critical_tix_open_at_bod_start_now_closed']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_at_bod_start_now_closed'] = i['closed_criticals_count']
                            break
                    for i in self.__results['critical_tix_open_more_than_30_days_at_bod_start']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['open_criticals_at_bod_start_open_more_than_30_days'] = i['criticals_count']
                            break
                    for i in self.__results['active_hosts']:
                        if i['_id']['owner'] == score['owner']:  #Found info for the current org
                            score['active_hosts'] = i['active_hosts_count']
                            break
                            
                    # Fields calculated from info retrieved above
                    score['open_criticals_more_than_30_days'] = score['open_criticals'] - score['open_criticals_past_30_days']
                    score['delta_open_criticals_more_than_30_days'] = score['open_criticals_more_than_30_days'] - score['previous_scorecard_open_criticals_more_than_30_days']

                    if score['open_criticals']:
                        score['open_criticals_percent_open_more_than_30_days'] = '{:.0%}'.format(float(score['open_criticals_more_than_30_days']) / score['open_criticals'])
                    
                    if score['open_criticals_at_bod_start']:
                        score['open_criticals_at_bod_start_percent_closed'] = '{:.0%}'.format(float(score['open_criticals_at_bod_start_now_closed']) / score['open_criticals_at_bod_start'])
                        score['open_criticals_at_bod_start_percent_open_more_than_30_days'] = '{:.0%}'.format(float(score['open_criticals_at_bod_start_open_more_than_30_days']) / score['open_criticals_at_bod_start'])
                    
                    # Add org's score to appropriate list
                    if score.get('open_criticals') and score['cfo_act_org']:
                        self.__cfo_orgs_with_criticals.append(score)
                    elif score.get('open_criticals') and not score['cfo_act_org']:
                        self.__non_cfo_orgs_with_criticals.append(score)
                    elif score['cfo_act_org']:
                        self.__cfo_orgs_without_criticals.append(score)
                    else:
                        self.__non_cfo_orgs_without_criticals.append(score)
                    
                    # Add current org's score to master list of scores
                    self.__scorecard_doc['scores'].append(score)
                    break
                    
            if currentlyScanned == False:
                # Went through all tallies and didn't find a matching org for this request doc
                if score['cfo_act_org']:
                    self.__cfo_not_scanned_orgs.append(score)
                else:
                    self.__non_cfo_not_scanned_orgs.append(score)
                self.__scorecard_doc['scores'].append(score)
        
        # Assemble 'all_scanned_orgs' lists
        self.__all_scanned_orgs = (self.__cfo_orgs_with_criticals + self.__non_cfo_orgs_with_criticals + 
                                   self.__cfo_orgs_without_criticals + self.__non_cfo_orgs_without_criticals)
        self.__all_scanned_cfo_orgs = self.__cfo_orgs_with_criticals + self.__cfo_orgs_without_criticals
        self.__all_scanned_non_cfo_orgs = self.__non_cfo_orgs_with_criticals + self.__non_cfo_orgs_without_criticals
        
        # Build Federal/CFO Act/Non-CFO Act Totals
        for (total_id, org_list) in [('federal_totals', self.__all_scanned_orgs), 
                                     ('cfo_totals', self.__all_scanned_cfo_orgs), 
                                     ('non_cfo_totals', self.__all_scanned_non_cfo_orgs)]:
            self.__results[total_id] = {'previous_scorecard_open_criticals_more_than_30_days':0, 'delta_open_criticals_more_than_30_days':0, 'open_criticals_more_than_30_days':0, 'open_criticals':0, 'open_criticals_since_previous_scorecard':0, 'open_criticals_past_30_days':0, 'open_criticals_more_than_90_days':0, 'exceptions_granted':0, 'open_criticals_at_bod_start':0, 'open_criticals_at_bod_start_now_closed':0, 'open_criticals_at_bod_start_percent_closed':'N/A', 'open_criticals_at_bod_start_open_more_than_30_days':0, 'open_criticals_at_bod_start_percent_open_more_than_30_days':'N/A', 'open_criticals_percent_open_more_than_30_days':'N/A', 'active_hosts':0}
            
            for org in org_list:
                self.__results[total_id]['previous_scorecard_open_criticals_more_than_30_days'] += org['previous_scorecard_open_criticals_more_than_30_days']
                self.__results[total_id]['open_criticals'] += org['open_criticals']
                self.__results[total_id]['open_criticals_since_previous_scorecard'] += org['open_criticals_since_previous_scorecard']
                self.__results[total_id]['open_criticals_past_30_days'] += org['open_criticals_past_30_days']
                self.__results[total_id]['open_criticals_more_than_90_days'] += org['open_criticals_more_than_90_days']
                self.__results[total_id]['exceptions_granted'] += org['exceptions_granted']
                self.__results[total_id]['open_criticals_at_bod_start'] += org['open_criticals_at_bod_start']
                self.__results[total_id]['open_criticals_at_bod_start_now_closed'] += org['open_criticals_at_bod_start_now_closed']
                self.__results[total_id]['open_criticals_at_bod_start_open_more_than_30_days'] += org['open_criticals_at_bod_start_open_more_than_30_days']
                self.__results[total_id]['active_hosts'] += org['active_hosts']
            
            self.__results[total_id]['open_criticals_more_than_30_days'] = (self.__results[total_id]['open_criticals'] -
                                                                            self.__results[total_id]['open_criticals_past_30_days'])
            self.__results[total_id]['delta_open_criticals_more_than_30_days'] = self.__results[total_id]['open_criticals_more_than_30_days'] - self.__results[total_id]['previous_scorecard_open_criticals_more_than_30_days']
            
            if self.__results[total_id]['open_criticals']:
                self.__results[total_id]['open_criticals_percent_open_more_than_30_days'] = '{:.0%}'.format(float(self.__results[total_id]['open_criticals_more_than_30_days']) / self.__results[total_id]['open_criticals'])
            
            if self.__results[total_id]['open_criticals_at_bod_start']:
                self.__results[total_id]['open_criticals_at_bod_start_percent_closed'] = '{:.0%}'.format(float(self.__results[total_id]['open_criticals_at_bod_start_now_closed']) / self.__results[total_id]['open_criticals_at_bod_start'])
                self.__results[total_id]['open_criticals_at_bod_start_percent_open_more_than_30_days'] = '{:.0%}'.format(float(self.__results[total_id]['open_criticals_at_bod_start_open_more_than_30_days']) / self.__results[total_id]['open_criticals_at_bod_start'])

    def generate_bod_scorecard(self):            
        # access database and cache results
        self.__run_queries()
    
        # build up the scorecard_doc from the query results
        self.__populate_scorecard_doc()
        
        # sort org lists
        self.__cfo_orgs_with_criticals.sort(key=lambda x:x['acronym'])
        self.__cfo_orgs_without_criticals.sort(key=lambda x:x['acronym'])
        self.__cfo_not_scanned_orgs.sort(key=lambda x:x['acronym'])
        self.__non_cfo_orgs_with_criticals.sort(key=lambda x:x['acronym'])
        self.__non_cfo_orgs_without_criticals.sort(key=lambda x:x['acronym'])
        self.__non_cfo_not_scanned_orgs.sort(key=lambda x:x['acronym'])
        self.__all_scanned_orgs.sort(key=lambda x:x['acronym'])
        self.__all_scanned_cfo_orgs.sort(key=lambda x:x['acronym'])
        self.__all_scanned_non_cfo_orgs.sort(key=lambda x:x['acronym'])
        
        # create a working directory
        original_working_dir = os.getcwdu()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # setup the working directory
        self.__setup_work_directory(temp_working_dir)
                
        # generate attachments
        self.__generate_attachments()
        
        # generate chart PDFs
        self.__generate_charts()

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)
        
        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        # generate report figures + latex
        self.__generate_final_pdf()
            
        # revert working directory
        os.chdir(original_working_dir)
        
        # copy report and json file to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            dest_filename = 'Federal_BOD_Scorecard-%s.pdf' % (timestamp)
            shutil.move(src_filename, dest_filename)
            src_filename = os.path.join(temp_working_dir, REPORT_JSON)
            timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            dest_filename = 'bod_scorecard_%s.json' % (timestamp)
            shutil.move(src_filename, dest_filename)
            shutil.rmtree(temp_working_dir)
        
        return self.__results
        
    def __setup_work_directory(self, work_dir):
        me = os.path.realpath(__file__)
        my_dir = os.path.dirname(me)
        for n in (MUSTACHE_FILE, PDF_CAPTURE_JS):            
            file_src = os.path.join(my_dir, n)
            file_dst = os.path.join(work_dir, n)
            shutil.copyfile(file_src, file_dst)
        # copy static assets 
        dir_src = os.path.join(my_dir, ASSETS_DIR_SRC)
        dir_dst = os.path.join(work_dir, ASSETS_DIR_DST)
        shutil.copytree(dir_src,dir_dst)

    ###############################################################################
    # Utilities
    ###############################################################################
    
    def __latex_escape(self, to_escape):
        return ''.join([LATEX_ESCAPE_MAP.get(i,i) for i in to_escape])
               
    def __latex_escape_structure(self, data):
        '''assumes that all sequences contain dicts'''
        if isinstance(data, dict):
            for k,v in data.items():
                if k.endswith('_tex'): # skip special tex values
                    continue
                if isinstance(v, basestring):
                    data[k] = self.__latex_escape(v)
                else:
                    self.__latex_escape_structure(v)
        elif isinstance(data, (list, tuple)):
            for i in data:
                self.__latex_escape_structure(i)
    
    def led(self, data):
        self.__latex_escape_dict(data)
    
    def __convert_levels_to_text(self, data, field):
        for row in data:
            row[field] = SEVERITY_LEVELS[row[field]]
            
    def __level_keys_to_text(self, data, lowercase=False):
        result = {}
        for k,v in data.items():
            if lowercase:
                new_key = SEVERITY_LEVELS[k].lower()
            else:
                new_key = SEVERITY_LEVELS[k]
            result[new_key] = v
        return result
            
    def __join_lists(self, data, field, joiner):
        for row in data:
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
        max_diff = max(diff)
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
    #  Attachment Generation
    ###############################################################################
    def __generate_attachments(self):
        self.__generate_bod_attachment()
        self.__generate_bod_graph_csv()
        
    def __generate_bod_attachment(self):
        generated_date_txt = self.__generated_time.strftime('%Y-%m-%d')
        bod_effective_date_txt = self.__bod_effective_date.strftime('%Y-%m-%d')
        prev_scorecard_date_txt = parser.parse(self.__previous_scorecard_data['generated_time']).strftime('%Y-%m-%d')
        header_fields = ('acronym', 'name', 'active_critical_vulns_30+_days', 'active_critical_vulns_<30_days', 'active_critical_vulns_>90_days', 'active_critical_vulns', 'new_active_critical_vulns_since_'+prev_scorecard_date_txt, 'exceptions_granted', 'active_on_'+bod_effective_date_txt+'_mitigated', 'active_for_30+_days_on_'+bod_effective_date_txt, 'active_for_30+_days_on_'+generated_date_txt, 'hosts_scanned')
        data_fields = ('acronym', 'name', 'open_criticals_more_than_30_days', 'open_criticals_past_30_days', 'open_criticals_more_than_90_days', 'open_criticals', 'open_criticals_since_previous_scorecard', 'exceptions_granted', 'open_criticals_at_bod_start_percent_closed', 'open_criticals_at_bod_start_percent_open_more_than_30_days', 'open_criticals_percent_open_more_than_30_days', 'active_hosts')
        with open('BOD-scorecard-details.csv', 'wb') as out_file:
            header_writer = csv.DictWriter(out_file, header_fields, extrasaction='ignore')
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction='ignore')
            header_writer.writeheader()
            for org in self.__all_scanned_orgs:
                data_writer.writerow(org)
    
    def __generate_bod_graph_csv(self):
        output = open(BOD_WEB_CHART1_CSV_FILE, 'w')
        subprocess.call(['curl', '-s', BOD_WEB_CHART1_CSV_URL], stdout=output, stderr=subprocess.STDOUT) 
    
    ###############################################################################
    #  Web Chart PDF Generation
    ###############################################################################
    def __generate_charts(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')
            
        return_code = subprocess.call(['phantomjs', 'pdf_capture.js', BOD_WEB_CHART1_URL, BOD_WEB_CHART1_FILE, BOD_WEB_CHART_WIN_WIDTH, BOD_WEB_CHART_WIN_HEIGHT], stdout=output, stderr=subprocess.STDOUT) 
        #assert return_code == 0, 'phantomjs pdf_capture.js (chart1) return code was %s' % return_code
        return_code = subprocess.call(['phantomjs', 'pdf_capture.js', BOD_WEB_CHART2_URL, BOD_WEB_CHART2_FILE, BOD_WEB_CHART_WIN_WIDTH, BOD_WEB_CHART_WIN_HEIGHT], stdout=output, stderr=subprocess.STDOUT) 
        #assert return_code == 0, 'phantomjs pdf_capture.js (chart2) return code was %s' % return_code
    
    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        result = {'cfo_orgs_with_criticals':self.__cfo_orgs_with_criticals}
        result['cfo_orgs_without_criticals'] = self.__cfo_orgs_without_criticals
        result['cfo_not_scanned_orgs'] = self.__cfo_not_scanned_orgs
        result['non_cfo_orgs_with_criticals'] = self.__non_cfo_orgs_with_criticals
        result['non_cfo_orgs_without_criticals'] = self.__non_cfo_orgs_without_criticals
        result['non_cfo_not_scanned_orgs'] = self.__non_cfo_not_scanned_orgs
        result['all_scanned_orgs_alpha'] = self.__all_scanned_orgs
        result['all_scanned_cfo_orgs_alpha'] = self.__all_scanned_cfo_orgs
        result['all_scanned_non_cfo_orgs_alpha'] = self.__all_scanned_non_cfo_orgs
        result['all_scanned_orgs_vuln'] = sorted(self.__all_scanned_orgs, key=lambda x:(x.get('open_criticals_more_than_30_days'), x.get('open_criticals_past_30_days'), x.get('open_criticals_more_than_90_days'),  x.get('open_criticals'), x.get('open_criticals_since_previous_scorecard'), x.get('exceptions_granted')), reverse=True)
        result['all_scanned_cfo_orgs_vuln'] = sorted(self.__all_scanned_cfo_orgs, key=lambda x:(x.get('open_criticals_more_than_30_days'), x.get('open_criticals_past_30_days'), x.get('open_criticals_more_than_90_days'),  x.get('open_criticals'), x.get('open_criticals_since_previous_scorecard'), x.get('exceptions_granted')), reverse=True)
        result['all_scanned_non_cfo_orgs_vuln'] = sorted(self.__all_scanned_non_cfo_orgs, key=lambda x:(x.get('open_criticals_more_than_30_days'), x.get('open_criticals_past_30_days'), x.get('open_criticals_more_than_90_days'),  x.get('open_criticals'), x.get('open_criticals_since_previous_scorecard'), x.get('exceptions_granted')), reverse=True)
        result['currently_scanned_days'] = CURRENTLY_SCANNED_DAYS
        result['title_date_tex'] = self.__generated_time.strftime('{%d}{%m}{%Y}')
        result['bod_effective_date_tex'] = self.__bod_effective_date.strftime('{%d}{%m}{%Y}')
        result['draft'] = self.__draft
        result['federal_totals'] = self.__results['federal_totals']
        result['cfo_totals'] = self.__results['cfo_totals']
        result['non_cfo_totals'] = self.__results['non_cfo_totals']
        result['generated_time'] = self.__generated_time
        result['previous_scorecard_date_tex'] = parser.parse(self.__previous_scorecard_data['generated_time']).strftime('{%d}{%m}{%Y}')
        
        # escape latex special characters in key lists
        for x in ('all_scanned_orgs_alpha', 'cfo_not_scanned_orgs', 'non_cfo_not_scanned_orgs', 'federal_totals', 'cfo_totals', 'non_cfo_totals'):
            self.__latex_escape_structure(result[x])
                
        with open(filename, 'wb') as out:
            out.write(to_json(result))
        
    def __generate_latex(self, mustache_file, json_file, latex_file):
        template = codecs.open(mustache_file,'r', encoding='utf-8').read()

        with codecs.open(json_file,'r', encoding='utf-8') as data_file:
            data = json.load(data_file)

        r = chevron.render(template, data)
        with codecs.open(latex_file,'w', encoding='utf-8') as output:
            output.write(r)

    def __generate_final_pdf(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')
        
        return_code = subprocess.call(['xelatex','bod_scorecard.tex'], stdout=output, stderr=subprocess.STDOUT) 
        assert return_code == 0, 'xelatex pass 1 of 2 return code was %s' % return_code
        
        return_code = subprocess.call(['xelatex','bod_scorecard.tex'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 2 return code was %s' % return_code       


def main():
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    
    bod_effective_date = parser.parse(args['BOD_EFFECTIVE_DATE']).replace(tzinfo=tz.tzutc())
    
    print 'Generating Binding Operational Directive (BOD) Scorecard...',
    generator = ScorecardGenerator(db, bod_effective_date, args['PREVIOUS_SCORECARD_JSON_FILE'], args['EXCEPTIONS_GRANTED_JSON_FILE'], debug=args['--debug'], final=args['--final'])
    results = generator.generate_bod_scorecard()
    print 'Done'
    sys.exit(0)
        
if __name__=='__main__':
    main()
