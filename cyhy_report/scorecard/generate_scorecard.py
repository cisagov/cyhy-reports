#!/usr/bin/env python

'''Create Cyber Hygiene Scorecard PDF.

Usage:
  cyhy-scorecard [options] (create | list)
  cyhy-scorecard [options] delete SCORECARD_ID
  cyhy-scorecard (-h | --help)
  cyhy-scorecard --version

Options:
  -a --anonymize                 Make a sample anonymous scorecard.
  -d --debug                     Keep intermediate files for debugging.
  -f --final                     Remove draft watermark.
  -h --help                      Show this screen.           
  -p --previous=SCORECARD_ID     Generate a previous scorecard. 
  -s SECTION --section=SECTION   Configuration section to use.
  -t --title-date=YYYYMMDD       Change the title page date.
  --version                      Show version.
'''

# Standard Python Libraries
import codecs
from datetime import timedelta
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

# Third-Party Libraries
from bson import ObjectId
import chevron
import dateutil
from docopt import docopt
import numpy as np
import unicodecsv as csv

# cisagov Libraries
from cyhy.core import *
from cyhy.db import database
from cyhy.util import *
import queries

# constants
SCORING_ENGINE_VERSION = '1.0'
CURRENTLY_SCANNED_DAYS = 14  # Number of days in the past that an org's tally doc was last changed; a.k.a. a 'currently-scanned' org
CLOSED_TICKETS_DAYS = 182    # Number of days in the past to examine closed tickets
                             # (182 days = 26 weeks = ~6 months)
CLOSED_TICKETS_MONTHS = 6    # Only displayed in the 'Cyber Exposure Rating Methodology' section of scorecard.mustache
HIGH_RISK_AVG_DAYS_TO_CLOSE_CRITICALS = 30
HIGH_RISK_MAX_DAYS_TO_CLOSE_CRITICALS = 90
HIGH_RISK_AVG_DAYS_TO_CLOSE_HIGHS = 45
HIGH_RISK_MAX_DAYS_TO_CLOSE_HIGHS = 120
MED_RISK_AVG_DAYS_TO_CLOSE_CRITICALS = 15
MED_RISK_MAX_DAYS_TO_CLOSE_CRITICALS = 45
MED_RISK_AVG_DAYS_TO_CLOSE_HIGHS = 30
MED_RISK_MAX_DAYS_TO_CLOSE_HIGHS = 90
MED_RISK_MAX_DAYS_CURRENTLY_OPEN_MEDIUMS = 180

# Do not include the orgs below (based on _id) in the Scorecard
EXEMPT_ORGS = []

HIGH_RISK_SCORE = 'High'
MED_RISK_SCORE = 'Medium'
LOW_RISK_SCORE = 'Low'
NOT_SCANNED_RISK_SCORE = 'Not Scanned'

MUSTACHE_FILE = 'scorecard.mustache'
REPORT_JSON = 'scorecard.json'
REPORT_PDF = 'scorecard.pdf'
REPORT_TEX = 'scorecard.tex'
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

#import IPython; IPython.embed() #<<<<<BREAKPOINT>>>>>>>
#sys.exit(0)

class ScorecardGenerator(object):
    def __init__(self, db, debug=False, scorecard_id=None, title_date=None, final=False, anonymize=False):
        self.__db = db
        self.__generated_time = utcnow()
        self.__results = dict() # reusable query results
        self.__requests = None
        self.__tallies = []
        self.__debug = debug 
        self.__title_date = title_date
        self.__draft = not final
        self.__anonymize = anonymize
        self.__scorecard_id = scorecard_id  # if regenerating a previous scorecard, otherwise scorecard_id = None
        self.__scorecard_doc = None
        self.__high_risk_orgs = []
        self.__medium_risk_orgs = []
        self.__low_risk_orgs = []
        self.__not_scanned_orgs = []
        self.__all_scanned_orgs = []
    
    def __run_queries(self):        
        fed_executive_orgs = self.__db.RequestDoc.find_one({'_id':'EXECUTIVE'})['children']
        # Get request docs for all FEDERAL EXECUTIVE orgs, except those in EXEMPT_ORGS list
        self.__requests = list(self.__db.RequestDoc.find({'_id':{'$in':fed_executive_orgs, '$nin':EXEMPT_ORGS}}))
        
        # Build up list of FED EXECUTIVE tallies updated within past CURRENTLY_SCANNED_DAYS days
        for tally in list(self.__db.TallyDoc.find({'_id':{'$in':fed_executive_orgs, '$nin':EXEMPT_ORGS}})):
            if tally['last_change'] >= self.__generated_time - timedelta(days=CURRENTLY_SCANNED_DAYS):
                self.__tallies.append(tally)                # Append the tally if it's been changed recently
            else:       # Check if this org has any descendants with tallies that have been changed recently
                tally_descendant_orgs = self.__db.RequestDoc.get_all_descendants(tally['_id'])
                if tally_descendant_orgs:
                    for tally_descendant in list(self.__db.TallyDoc.find({'_id':{'$in':tally_descendant_orgs}})):
                        if tally_descendant['last_change'] >= self.__generated_time - timedelta(days=CURRENTLY_SCANNED_DAYS):
                            self.__tallies.append(tally)    # Append the top-level org's tally if the descendant has been changed recently
                            break                           # No need to check any other descendants

        # If an org has descendants, we only want the top-level org to show up in the Scorecard
        # Make list of orgs that have children and their request docs so their child data can be accumulated later
        orgs_with_descendants = []
        requests_with_descendants = []
        for r in self.__requests:
            if r.get('children'):
                #all_descendants += r['children']
                orgs_with_descendants.append(r['_id'])
                requests_with_descendants.append(r)
                        
        # Get relevant ticket age data
        pipeline_collection = queries.open_ticket_age_pl(self.__generated_time)
        self.__results['open_ticket_age'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        pipeline_collection = queries.closed_ticket_age_pl(self.__generated_time - timedelta(days=CLOSED_TICKETS_DAYS))
        self.__results['closed_ticket_age'] = database.run_pipeline_cursor(pipeline_collection, self.__db)
        
        # Throw out ticket data from orgs with descendants
        # list(<ticket_data>) iterates over a *copy* of the list so items can be properly removed from the original
        for r in list(self.__results['open_ticket_age']):
            if r['_id']['owner'] in orgs_with_descendants:
                self.__results['open_ticket_age'].remove(r)
                
        for r in list(self.__results['closed_ticket_age']):
            if r['_id']['owner'] in orgs_with_descendants:
                self.__results['closed_ticket_age'].remove(r)
                
        # Pull grouped ticket age data for orgs with descendants and add it to results
        for r in requests_with_descendants:
            descendants = self.__db.RequestDoc.get_all_descendants(r['_id'])
            pipeline_collection = queries.open_ticket_age_for_orgs_pl(self.__generated_time, r['_id'], descendants)
            self.__results['open_ticket_age'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
            pipeline_collection = queries.closed_ticket_age_for_orgs_pl(self.__generated_time - timedelta(days=CLOSED_TICKETS_DAYS), r['_id'], descendants)
            self.__results['closed_ticket_age'] += database.run_pipeline_cursor(pipeline_collection, self.__db)
    
    def __populate_scorecard_doc(self):
        # Go through each request doc and check if the org has a current tally doc
        for r in self.__requests:
            currentlyScanned = False
            score = { 'open_tickets': {
                        'critical': { 'count':0 },
                        'high': { 'count':0 },
                        'medium': { 'count':0 },
                        'low': { 'count':0 }
                        },
                      'closed_tickets': {
                        'critical': { 'count':0 },
                        'high': { 'count':0 },
                        'medium': { 'count':0 },
                        'low': { 'count':0 }
                        }
                    }
            score['owner'] = r['_id']
            score['acronym'] = r['agency']['acronym']
            score['name'] = r['agency']['name']
            for t in self.__tallies:
                if t['_id'] == r['_id']:  # Found a current tally that matches this request (org)
                    currentlyScanned = True
                    for i in self.__results['open_ticket_age']:
                        if i['_id']['owner'] == score['owner']:  #Found some open_ticket_age info for the current org
                            avg_open_ticket_age = timedelta(milliseconds=i['avg_open_ticket_duration_msec'])
                            max_open_ticket_age = timedelta(milliseconds=i['max_open_ticket_duration_msec'])
                            if i['_id']['severity'] == 1:
                                severity = 'low'
                            elif i['_id']['severity'] == 2:
                                severity = 'medium'
                            elif i['_id']['severity'] == 3:
                                severity = 'high'
                            elif i['_id']['severity'] == 4:
                                severity = 'critical' 
                            score['open_tickets'][severity]['count'] = i['open_ticket_count']
                            score['open_tickets'][severity]['avg_days_open'] = avg_open_ticket_age.days + avg_open_ticket_age.seconds/(24*60*60.0)
                            score['open_tickets'][severity]['max_days_open'] = max_open_ticket_age.days + max_open_ticket_age.seconds/(24*60*60.0)
                            
                    for i in self.__results['closed_ticket_age']:
                        if i['_id']['owner'] == score['owner']:  #Found some closed_ticket_age info for the current org
                            avg_closed_ticket_age = timedelta(milliseconds=i['avg_duration_to_close_msec'])
                            max_closed_ticket_age = timedelta(milliseconds=i['max_duration_to_close_msec'])
                            if i['_id']['severity'] == 1:
                                severity = 'low'
                            elif i['_id']['severity'] == 2:
                                severity = 'medium'
                            elif i['_id']['severity'] == 3:
                                severity = 'high'
                            elif i['_id']['severity'] == 4:
                                severity = 'critical' 
                            score['closed_tickets'][severity]['count'] = i['closed_ticket_count']
                            score['closed_tickets'][severity]['avg_days_to_close'] = avg_closed_ticket_age.days + avg_closed_ticket_age.seconds/(24*60*60.0)
                            score['closed_tickets'][severity]['max_days_to_close'] = max_closed_ticket_age.days + max_closed_ticket_age.seconds/(24*60*60.0)
                    
                    self.__scorecard_doc['scores'].append(score)
                    break
            if currentlyScanned == False:
                # Went through all tallies and didn't find a matching org for this request doc
                score['risk_score'] = NOT_SCANNED_RISK_SCORE
                self.__not_scanned_orgs.append(score)   # Add org/request to the not_scanned list   
                self.__scorecard_doc['scores'].append(score)   

    def __calc_risk_scores(self):
        for s in self.__scorecard_doc['scores']:
            if s.get('risk_score') == NOT_SCANNED_RISK_SCORE:
                continue
            # High Risk
            elif (s['open_tickets']['critical'].get('count') > 0 or
                  s['open_tickets']['high'].get('count') or
                  s['closed_tickets']['critical'].get('avg_days_to_close') >= HIGH_RISK_AVG_DAYS_TO_CLOSE_CRITICALS or
                  s['closed_tickets']['critical'].get('max_days_to_close') >= HIGH_RISK_MAX_DAYS_TO_CLOSE_CRITICALS or
                  s['closed_tickets']['high'].get('avg_days_to_close') >= HIGH_RISK_AVG_DAYS_TO_CLOSE_HIGHS or
                  s['closed_tickets']['high'].get('max_days_to_close') >= HIGH_RISK_MAX_DAYS_TO_CLOSE_HIGHS):
                s['risk_score'] = HIGH_RISK_SCORE
                self.__high_risk_orgs.append(s)
            # Medium Risk
            elif (s['closed_tickets']['critical'].get('avg_days_to_close') >= MED_RISK_AVG_DAYS_TO_CLOSE_CRITICALS or
                  s['closed_tickets']['critical'].get('max_days_to_close') >= MED_RISK_MAX_DAYS_TO_CLOSE_CRITICALS or
                  s['closed_tickets']['high'].get('avg_days_to_close') >= MED_RISK_AVG_DAYS_TO_CLOSE_HIGHS or
                  s['closed_tickets']['high'].get('max_days_to_close') >= MED_RISK_MAX_DAYS_TO_CLOSE_HIGHS or
                  s['open_tickets']['medium'].get('max_days_open') >= MED_RISK_MAX_DAYS_CURRENTLY_OPEN_MEDIUMS):
                s['risk_score'] = MED_RISK_SCORE
                self.__medium_risk_orgs.append(s)
            # Low Risk
            else:
                s['risk_score'] = LOW_RISK_SCORE
                self.__low_risk_orgs.append(s)
            self.__all_scanned_orgs.append(s)


    def __make_fake_agency(self, real_agencies, real_acronyms, fake_agencies, fake_acronyms):
        FIRST = ['American', 'Atlantic', 'Central', 'Civil', 'Eastern American', 'Executive', 'Federal', 'Foreign', 'General', 'Government', 'Interstate', 'International', 'Midwest', 'National', 'North American', 'Overseas', 'Pacific', 'Regional', 'State', 'Western American', 'United States']
        SECOND = ['Agriculture', 'Art', 'Airport', 'Business', 'Commerce', 'Communication', 'Development', 'Economic', 'Education', 'Election', 'Energy', 'Environment', 'Finance', 'Gaming', 'Health', 'Housing', 'Infrastructure', 'Industrial', 'Insurance', 'Justice', 'Labor', 'Land', 'Maritime', 'Management', 'Natural Resources', 'Nuclear', 'Planning', 'Policy', 'Protection', 'Records', 'Resource', 'Regulatory', 'Retirement', 'Safety', 'Science', 'Security', 'Space', 'Trade', 'Transportation', 'Water']
        THIRD = ['Administration', 'Advisory Council', 'Agency', 'Authority', 'Bureau', 'Board', 'Center', 'Commission', 'Corporation', 'Corps', 'Council', 'Department', 'Enforcement', 'Foundation', 'Inquisition', 'Institute', 'Institutes', 'Laboratories', 'Office', 'Program', 'Regulatory Commission', 'Review Board', 'Service', 'Services', 'Trust']
        bad_acronyms = ['ASS']
        
        acceptableName = False
        while not acceptableName:
            fakeName = random.choice(FIRST) + ' ' + random.choice(SECOND) + ' ' + random.choice(THIRD)
            fakeAcronym = "".join(c[0] for c in fakeName.split())
            if (fakeName not in real_agencies + fake_agencies) and (fakeAcronym not in real_acronyms + fake_acronyms + bad_acronyms):
                acceptableName = True
        return fakeName, fakeAcronym


    def __anonymize_scorecard(self):
        realAgencyNames = []
        realAgencyAcronyms = []
        fakeAgencyNames = []
        fakeAgencyAcronyms = []
        
        for r in self.__requests:
            realAgencyNames.append(r['agency']['name'])
            realAgencyAcronyms.append(r['agency']['acronym'])
        
        for s in self.__scorecard_doc['scores']:
            fakeAgencyName, fakeAgencyAcronym = self.__make_fake_agency(realAgencyNames, realAgencyAcronyms, fakeAgencyNames, fakeAgencyAcronyms)
            fakeAgencyNames.append(fakeAgencyName)
            fakeAgencyAcronyms.append(fakeAgencyAcronym)
            s['acronym'] = fakeAgencyAcronym
            s['owner'] = fakeAgencyAcronym
            s['name'] = fakeAgencyName


    def generate_scorecard(self):
        if self.__scorecard_id:
            # Look for previously-generated scorecard_id
            self.__scorecard_doc = self.__db.ScorecardDoc.find_one({"_id":ObjectId(self.__scorecard_id)})
            if not self.__scorecard_doc:
                raise Exception('Could not find requested scorecard %s' % (self.__scorecard_id))
            self.__report_type = 'Federal'  # For now, all previously-generated scorecards are assumed to be Federal
            # Populate the various org lists used to create the scorecard PDF
            for s in self.__scorecard_doc['scores']:
                if s['risk_score'] == NOT_SCANNED_RISK_SCORE:
                    self.__not_scanned_orgs.append(s)
                    continue
                if s['risk_score'] == HIGH_RISK_SCORE:
                    self.__high_risk_orgs.append(s)
                elif s['risk_score'] == MED_RISK_SCORE:
                    self.__medium_risk_orgs.append(s)
                elif s['risk_score'] == LOW_RISK_SCORE:
                    self.__low_risk_orgs.append(s)
                self.__all_scanned_orgs.append(s)
        else:  # Creating a brand new scorecard
            self.__scorecard_doc = self.__db.ScorecardDoc()
            self.__scorecard_doc['_id'] = ObjectId()
            self.__scorecard_doc['scoring_engine'] = SCORING_ENGINE_VERSION
            self.__scorecard_doc['generated_time'] = self.__generated_time
        
            # access database and cache results
            self.__run_queries()
        
            # build up the scorecard_doc from the query results
            self.__populate_scorecard_doc()
        
            # anonymize data if requested
            if self.__anonymize:
                self.__report_type = 'SAMPLE'
                self.__anonymize_scorecard()
                self.__calc_risk_scores()   # calculate risk score for each org in the scorecard_doc
            else:
                self.__report_type = 'Federal'
                self.__calc_risk_scores()   # calculate risk score for each org in the scorecard_doc
                self.__scorecard_doc.save() # Only save non-anonymized scorecards to the DB
        
        # sort org lists
        self.__high_risk_orgs.sort(key=lambda x:x['acronym'])
        self.__medium_risk_orgs.sort(key=lambda x:x['acronym'])
        self.__low_risk_orgs.sort(key=lambda x:x['acronym'])
        self.__not_scanned_orgs.sort(key=lambda x:x['acronym'])
        self.__all_scanned_orgs.sort(key=lambda x:x['acronym'])
        
        # round floats for output as integers
        for i in self.__all_scanned_orgs:
            for severity in ['critical', 'high', 'medium', 'low']:
                if i['open_tickets'][severity].get('avg_days_open'):
                    i['open_tickets'][severity]['avg_days_open'] = int(round(i['open_tickets'][severity]['avg_days_open']))
                if i['open_tickets'][severity].get('max_days_open'):
                    i['open_tickets'][severity]['max_days_open'] = int(round(i['open_tickets'][severity]['max_days_open']))
                if i['closed_tickets'][severity].get('avg_days_to_close'):
                    i['closed_tickets'][severity]['avg_days_to_close'] = int(round(i['closed_tickets'][severity]['avg_days_to_close']))
                if i['closed_tickets'][severity].get('max_days_to_close'):
                    i['closed_tickets'][severity]['max_days_to_close'] = int(round(i['closed_tickets'][severity]['max_days_to_close']))
    
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

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)
        
        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        # generate report figures + latex
        self.__generate_final_pdf()
            
        # revert working directory
        os.chdir(original_working_dir)
        
        # copy report to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            if self.__anonymize:
                dest_filename = 'SAMPLE_cyhy_scorecard-%s.pdf' % (timestamp)
            else:
                dest_filename = 'cyhy_fed_scorecard-%s.pdf' % (timestamp)
            shutil.move(src_filename, dest_filename)
            shutil.rmtree(temp_working_dir)
        
        return self.__results
        
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
    # Utilities
    ###############################################################################
    
    def __anonymize_structure(self, data):
        if isinstance(data, basestring):
            return re.sub(IPV4_ADDRESS_RE, ANONYMOUS_IPV4, data)
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
        self.__generate_risk_ratings_attachment()
        
    def __generate_risk_ratings_attachment(self):
        fields = ('acronym', 'name', 'cyber_exposure', 'open_critical_vulns', 'open_high_vulns', 'avg_days_to_close_critical_vulns', 'avg_days_to_close_high_vulns', 'max_days_to_close_critical_vulns', 'max_days_to_close_high_vulns', 'max_days_open_medium_vulns')
        with open('cyber-exposure-ratings.csv', 'wb') as out_file:
            writer = csv.DictWriter(out_file, fields, extrasaction='ignore')
            writer.writeheader()
            for i in self.__all_scanned_orgs:
                writer.writerow( {'acronym':i.get('acronym'), 'name':i.get('name'), 'cyber_exposure':i.get('risk_score'), 'open_critical_vulns':i['open_tickets']['critical'].get('count'), 'open_high_vulns':i['open_tickets']['high'].get('count'), 'avg_days_to_close_critical_vulns':i['closed_tickets']['critical'].get('avg_days_to_close'), 'avg_days_to_close_high_vulns':i['closed_tickets']['high'].get('avg_days_to_close'), 'max_days_to_close_critical_vulns':i['closed_tickets']['critical'].get('max_days_to_close'), 'max_days_to_close_high_vulns':i['closed_tickets']['high'].get('max_days_to_close'), 'max_days_open_medium_vulns':i['open_tickets']['medium'].get('max_days_open') })
    
    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        result = {'high_risk_orgs':self.__high_risk_orgs}
        result['medium_risk_orgs'] = self.__medium_risk_orgs
        result['low_risk_orgs'] = self.__low_risk_orgs
        result['not_scanned_orgs'] = self.__not_scanned_orgs
        result['all_scanned_orgs_alpha'] = self.__all_scanned_orgs
        result['all_scanned_orgs_vuln'] = sorted(self.__all_scanned_orgs, key=lambda x:(x['open_tickets']['critical'].get('count'), x['open_tickets']['high'].get('count'), x['closed_tickets']['critical'].get('avg_days_to_close'), x['closed_tickets']['high'].get('avg_days_to_close'), x['closed_tickets']['critical'].get('max_days_to_close'), x['closed_tickets']['high'].get('max_days_to_close'), x['open_tickets']['medium'].get('max_days_open')), reverse=True)
        result['scorecard_id'] = str(self.__scorecard_doc['_id'])
        result['currently_scanned_days'] = CURRENTLY_SCANNED_DAYS
        result['closed_tickets_months'] = CLOSED_TICKETS_MONTHS
        result['high_risk_avg_days_to_close_criticals'] = HIGH_RISK_AVG_DAYS_TO_CLOSE_CRITICALS
        result['high_risk_max_days_to_close_criticals'] = HIGH_RISK_MAX_DAYS_TO_CLOSE_CRITICALS
        result['high_risk_avg_days_to_close_highs'] = HIGH_RISK_AVG_DAYS_TO_CLOSE_HIGHS
        result['high_risk_max_days_to_close_highs'] = HIGH_RISK_MAX_DAYS_TO_CLOSE_HIGHS
        result['med_risk_avg_days_to_close_criticals'] = MED_RISK_AVG_DAYS_TO_CLOSE_CRITICALS
        result['med_risk_max_days_to_close_criticals'] = MED_RISK_MAX_DAYS_TO_CLOSE_CRITICALS
        result['med_risk_avg_days_to_close_highs'] = MED_RISK_AVG_DAYS_TO_CLOSE_HIGHS
        result['med_risk_max_days_to_close_highs'] = MED_RISK_MAX_DAYS_TO_CLOSE_HIGHS
        result['med_risk_max_days_currently_open_mediums'] = MED_RISK_MAX_DAYS_CURRENTLY_OPEN_MEDIUMS
        result['draft'] = self.__draft
        result['report_type'] = self.__report_type

        if self.__title_date: # date for title page
            result['title_date_tex'] = self.__title_date.strftime('{%d}{%m}{%Y}')  
        else:
            result['title_date_tex'] = self.__generated_time.strftime('{%d}{%m}{%Y}')
        
        # escape latex special characters in key lists
        for x in ('all_scanned_orgs_alpha', 'not_scanned_orgs'):
            self.__latex_escape_structure(result[x])
                
        with open(filename, 'wb') as out:
            out.write(to_json(result))
        
    def __generate_latex(self, mustache_file, json_file, latex_file):
        template = codecs.open(mustache_file,'r', encoding='utf-8').read()

        with codecs.open(json_file,'r', encoding='utf-8') as data_file:
            data = json.load(data_file)

        r = chevron.render(template, data).decode('utf-8')
        with codecs.open(latex_file,'w', encoding='utf-8') as output:
            output.write(r)

    def __generate_final_pdf(self):
        if self.__debug:
            output = sys.stdout
        else:
            output = open(os.devnull, 'w')
        
        return_code = subprocess.call(['xelatex','scorecard.tex'], stdout=output, stderr=subprocess.STDOUT) 
        assert return_code == 0, 'xelatex pass 1 of 2 return code was %s' % return_code
        
        return_code = subprocess.call(['xelatex','scorecard.tex'], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 2 return code was %s' % return_code

def warn_and_confirm(message):
    print >> sys.stderr, 'WARNING: %s' % message
    print >> sys.stderr
    yes = raw_input('Type "yes" if you are sure that you want to do this? ')
    return yes == 'yes'          

def print_scorecard_line(scorecard):
    scorecard_id = scorecard['_id']
    generated_time = scorecard['generated_time']
    print '%s %s' % (scorecard_id, generated_time)

def list_scorecards(db):
    cursor = db.ScorecardDoc.find({}).sort([('generated_time',-1)])
    for scorecard in cursor:
        print_scorecard_line(scorecard)
    return True
    
def delete_scorecard(db, scorecard_id):
    oid = ObjectId(scorecard_id)
    print 'Removing scorecard document...',
    if db.ScorecardDoc.collection.remove({'_id':oid}).get('n'):
        print 'Done'
        return True
    else:
        print '\nWARNING: Scorecard %s was NOT deleted; double-check that it exists.' % scorecard_id
        return False

def main():
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    success = False
    
    if args['--previous']:
        scorecard_id = ObjectId(args['--previous'])
    else:
        scorecard_id = None
    
    if args['--title-date']:
        title_date = dateutil.parser.parse(args['--title-date'])
    else:
        title_date = None

    if args['list']:
        list_scorecards(db)
        sys.exit(0)
        
    if args['delete']:
        confirmed = warn_and_confirm('This will delete a scorecard document from the database.')    
        if confirmed:
            delete_scorecard(db, args['SCORECARD_ID'])
            sys.exit(0)
        else:
            print 'ABORTED!'
            sys.exit(-1)
            
    if args['create']:
        print 'Generating scorecard...',
        generator = ScorecardGenerator(db, debug=args['--debug'], scorecard_id=scorecard_id,
                                    title_date=title_date, final=args['--final'], anonymize=args['--anonymize'])
        results = generator.generate_scorecard()
        print 'Done'
        sys.exit(0)
        
if __name__=='__main__':
    main()
