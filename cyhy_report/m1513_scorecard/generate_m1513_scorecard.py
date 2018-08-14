#!/usr/bin/env python

'''Create Cyber Hygiene HTTPS Report PDF.

Usage:
  cyhy-m1513-scorecard [options] "AGENCY"
  cyhy-m1513-scorecard (-h | --help)
  cyhy-m1513-scorecard --version

Options:
  -d --debug                     Keep intermediate files for debugging.
  -h --help                      Show this screen.           
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
'''
# standard python libraries
import sys
import os
import copy
from pymongo import MongoClient
from datetime import datetime, timedelta
from dateutil import parser, relativedelta, tz
import time
import json
import codecs
import tempfile
import shutil
import subprocess
import re
import csv
from collections import OrderedDict, defaultdict
import random
import numpy as np


# third-party libraries (install with pip)
import pystache
from pandas import Series, DataFrame 
import pandas as pd
#import numpy as np 
from bson import ObjectId
from docopt import docopt
from pyPdf import PdfFileWriter, PdfFileReader
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm



# intra-project modules
from cyhy.core import *
from cyhy.util import *
from cyhy.db import database, queries, CHDatabase
import graphs

# constants
SCORING_ENGINE_VERSION = '1.0'
CURRENTLY_SCANNED_DAYS = 14  # Number of days in the past that an org's tally doc was last changed; a.k.a. a 'currently-scanned' org
BEFORE_THE_DAWN_OF_CYHY = time_to_utc(parser.parse("20000101"))
#DEFAULT_DATABASE_URI = 'mongodb://172.17.0.2:27017/test'


# Do not include the orgs below (based on _id) in the Scorecard
EXEMPT_ORGS = []

MUSTACHE_FILE = 'm1513_scorecard.mustache'
REPORT_JSON = 'm1513_scorecard.json'
REPORT_PDF = 'm1513_scorecard.pdf'
REPORT_TEX = 'm1513_scorecard.tex'
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
CYBEX_WEB_SERVER = 'http://0.0.0.0:5000'


class ScorecardGenerator(object):
    #initiate variables
    def __init__(self, db, agency, debug=False):
        self.__db = db
        self.__agency = agency
        self.__debug = debug
        self.__generated_time = utcnow()
        self.__results = dict() # reusable query results
        self.__requests = None
        self.__scorecard_doc = {'scores':[]}
        self.__all_domains = []
        self.__base_domains = []
        self.__eligible_domains_count = 0  #second-level/base-domains
        self.__eligible_subdomains_count = 0
        self.__all_eligible_domains_count = 0 #responsive base+subs
        self.__https_compliance_list = []
        self.__non_https_compliance_list = []
        self.__ineligible_domains = []
        self.__domain_count = float(0)
        self.__base_domain_count = float(0)
        self.__subdomain_count = float(0)
        self.__domain_supports_https = float(0)
        self.__domain_supports_https_count = float(0)
        self.__domain_enforces_https_count = float(0) #added
        self.__domain_uses_strong_hsts_count = float(0)
        self.__strictly_forces_count = float(0)
        self.__downgrades_count = float(0)
        self.__hsts_count = float(0)
        self.__hsts_preloaded_count = float(0)
        self.__hsts_preload_ready_count = float(0)
        self.__hsts_entire_domain_count = float(0)
        self.__https_bad_chain_count = float(0)
        self.__https_bad_hostname_count = float(0)
        self.__https_expired_cert_count = float(0)
        self.__m1513_count = float(0)
        self.__path = os.getcwd()
        self.__hsts_low_max_age_count = float(0)
        self.__scorecard_oid = ObjectId()

        # Get list of all domains from the database
        all_domains_cursor = self.__db.m1513.find({'agency': agency})
        self.__domain_count = all_domains_cursor.count()

        for domain_doc in all_domains_cursor:
            self.__all_domains.append(domain_doc) 
            if domain_doc['base_domain'] == domain_doc['domain']:
                domain_doc['subdomains'] = list(self.__db.m1513.find({'base_domain': domain_doc['base_domain'], '_id': {'$ne': domain_doc['_id']}}).sort([('domain', 1)]))
                self.__subdomain_count += len(domain_doc['subdomains'])
                self.__base_domains.append(domain_doc)
            
        # Get list of all second-level domains an agency owns
        second_cursor = self.__db.m1513.find({'agency': agency}).distinct('base_domain')
        for document in second_cursor:
            self.__base_domain_count += 1      

    
    def __score_domain(self, domain):
        score = {'subdomain_scores' : list()}
        if domain['live'] == "True":
            if domain['domain'] == domain['base_domain']:
                self.__eligible_domains_count += 1
                self.__all_eligible_domains_count += 1
            else:
                self.__eligible_subdomains_count += 1
                self.__all_eligible_domains_count += 1

            score['domain'] = domain['domain']
            
            # strictly_forces_https
            if domain['strictly_forces_https'] == 'True':
                score['strictly_forces_https'] = 'Yes'
                score['strictly_forces_https_bool'] = True
                self.__strictly_forces_count += 1
            else:
                score['strictly_forces_https'] = 'No'
                score['strictly_forces_https_bool'] = False

            # "Uses HTTPS", domains_supports_https
            if domain['domain_supports_https'] == 'True':
                score['domain_supports_https'] = 'Yes'
                score['domain_supports_https_bool'] = True
                self.__domain_supports_https_count += 1 
                #print("Uses "+ score['domain'])  #debug 2
            else:
                score['domain_supports_https'] = 'No'
                score['domain_supports_https_bool'] = False   #print("valid no "+ score['domain'])  #debug 

            # "Enforces HTTPS", domain_enforces_https
            if domain['domain_enforces_https'] == 'True':
                score['domain_enforces_https'] = 'Yes'
                score['domain_enforces_https_bool'] = True
                self.__domain_enforces_https_count += 1 
            else:
                score['domain_enforces_https'] = 'No'
                score['domain_enforces_https_bool'] = False
       
            # https_bad_chain    
            if domain['https_bad_chain'] == 'True' and domain['https_bad_hostname'] == 'True':
                score['https_bad_chain_bool'] = True
                self.__https_bad_chain_count += 1 
            elif (domain['https_bad_chain'] == 'True' and domain['https_bad_hostname'] == 'False') or (domain['https_bad_chain'] == 'True' and domain['https_expired_cert'] == 'True'):
                self.__https_bad_chain_count += 1                 
                #self.__domain_supports_https_count += 1    
                print("valid no/bad chain "+ score['domain'])  #debug 1
            else:
                score['https_bad_chain_bool'] = False
            

            # https_bad_hostname 
            if domain['https_bad_hostname'] == 'True':
                score['https_bad_hostname_bool'] = True
                self.__https_bad_hostname_count += 1
            else:
                score['https_bad_hostname_bool'] = False
            

            # https_expired_cert
            if domain['https_expired_cert'] == 'True':
                score['https_expired_cert_bool'] = True
                self.__https_expired_cert_count += 1 
            else:
                score['https_expired_cert_bool'] = False
            

            # live
            if domain['live'] == "True":
                score['live_bool'] = True
            else:
                score['live_bool'] = False


            # redirect
            if domain['redirect'] == 'True':
                score['redirect_bool'] = True
            else:
                score['redirect_bool'] = False
            

            # downgrades_https
            if domain['downgrades_https'] == 'True':
                score['downgrades_https'] = 'Yes'
                score['downgrades_https_bool'] = True
                self.__downgrades_count += 1
            else:
                score['downgrades_https'] = 'No'
                score['downgrades_https_bool'] = False


            #HTTPS Strict Transport Security (HSTS): This is 'Yes' in the report only if HSTS is present and the max-age is >= 1 year, as M-15-13 requires
            if domain['hsts'] == 'True':
                score['hsts'] = 'Yes'
                score['hsts_bool'] = True
               
               # hsts_preloaded > hsts_preload_pending > hsts_preload_ready
                if domain['hsts_preloaded'] == 'True':
                    score['hsts_preloaded'] = 'Yes'
                    score['hsts_preloaded_bool'] = True
                    self.__hsts_preloaded_count += 1
                else:
                    score['hsts_preloaded_bool'] = False
                    score['hsts_preloaded'] = 'No'          
                    if domain['hsts_preload_pending'] == 'True':
                        score['hsts_preload_pending_bool'] = True
                    else:
                        score['hsts_preload_pending_bool'] = False

                    if domain['hsts_preload_ready'] == 'True':
                        score['hsts_preload_ready_bool'] = True
                        score['hsts_preload_ready'] = 'Yes'
                        self.__hsts_preload_ready_count += 1
                    else:
                        score['hsts_preload_ready_bool'] = False
                        score['hsts_preload_ready'] = 'No'
            
                if domain['domain_uses_strong_hsts'] == 'True':
                    score['domain_uses_strong_hsts_bool'] = True
                    self.__domain_uses_strong_hsts_count += 1
                else:
                    score['domain_uses_strong_hsts_bool'] = False
                    if 0 < domain['hsts_max_age'] < 31536000:
                        self.__hsts_low_max_age_count += 1

            else:
                score['hsts'] = 'No'
                score['hsts_bool'] = False
                #score['hsts_low_max_age_bool'] = False


            # M-15-13 compliant?
            if (domain['domain_supports_https'] == 'True' and domain['domain_enforces_https'] == 'True' and domain['domain_uses_strong_hsts'] == 'True'):
                score['m1513_compliance'] = True
                self.__m1513_count += 1
            else: 
                score['m1513_compliance'] = False

            if domain.get('subdomains'):    # if this domain has any subdomains
                for subdomain in domain['subdomains']:
                    subdomain_score  = self.__score_domain(subdomain)
                    if subdomain_score:
                        score['subdomain_scores'].append(subdomain_score)   # add this subdomain's score to this domain's list of subdomain_scores
            return score
            
        else:   # if domain['live'] == "False", ddd to ineligible domain list if host not live
            if domain['domain'] == domain['base_domain']: # only include base domains in the ineligible count; otherwise lots of non-existent subs will show in the report
                self.__ineligible_domains.append({'domain' : domain['domain']})
                return None

    
    def __populate_scorecard_doc(self):        
        #index = 0
        self.__all_domains.sort(key=lambda x:x['domain'])   # sort list of all domains
        self.__base_domains.sort(key=lambda x:x['domain'])   # sort list of base domains

        # Go through each base domain and score the attributes
        for domain in self.__base_domains:
            score  = self.__score_domain(domain)
            if score:
                self.__scorecard_doc['scores'].append(score)    # Add domain's score to master list of scores

        self.__uses_https_percentage = round((((self.__domain_supports_https_count)/self.__all_eligible_domains_count) * 100), 1)
        self.__enforces_https_percentage = round(((self.__domain_enforces_https_count/self.__all_eligible_domains_count) * 100), 1)
        self.__hsts_percentage = round(((self.__domain_uses_strong_hsts_count/self.__all_eligible_domains_count) * 100), 1)
        self.__m1513_percentage = round(((self.__m1513_count/self.__all_eligible_domains_count) * 100), 1)

        print(self.__domain_count) #base + subs
        print(self.__base_domain_count) #base
        print(self.__eligible_domains_count) #responsive base
        print(self.__subdomain_count) #subs
        print(self.__eligible_subdomains_count) #responsive subs
        print(self.__all_eligible_domains_count)
        print(self.__m1513_count)
        print(self.__m1513_percentage)
        print(self.__domain_supports_https_count)
        print(self.__uses_https_percentage)


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


    def generate_m1513_scorecard(self):  
        print ' parsing data'
        # build up the scorecard_doc from the query results
        self.__populate_scorecard_doc()

        # sort org lists
        #self.__scorecard_doc['scores'].sort(key=lambda x:x['domain'])
        if self.__https_compliance_list:
            self.__https_compliance_list.sort(key=lambda x:x['domain'])
        if self.__non_https_compliance_list:
            self.__non_https_compliance_list.sort(key=lambda x:x['domain'])
        
        # create a working directory
        original_working_dir = os.getcwdu()
        if self.__debug:
            temp_working_dir = tempfile.mkdtemp(dir=original_working_dir)
        else:
            temp_working_dir = tempfile.mkdtemp()
        os.chdir(temp_working_dir)

        # setup the working directory
        self.__setup_work_directory(temp_working_dir)
        
        print ' generating attachments'   
        # generate attachments
        self.__generate_attachments()

        print ' generating charts'   
        # generate charts
        self.__generate_charts()

        # generate json input to mustache
        self.__generate_mustache_json(REPORT_JSON)
        
        # generate latex json + mustache
        self.__generate_latex(MUSTACHE_FILE, REPORT_JSON, REPORT_TEX)

        print ' assembling PDF'  
        # generate report figures + latex
        self.__generate_final_pdf()
            
        # revert working directory
        os.chdir(original_working_dir)
        
        # copy report and json file to original working directory
        # and delete working directory
        if not self.__debug:
            src_filename = os.path.join(temp_working_dir, REPORT_PDF)
            timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            dest_filename = self.__agency +'-https-report'+ '.pdf' #% (timestamp)
            shutil.move(src_filename, dest_filename)
            src_filename = os.path.join(temp_working_dir, REPORT_JSON)
            #timestamp = self.__generated_time.isoformat().replace(':','').split('.')[0]
            #dest_filename = 'http-report-' + self.__agency + '.json' #% (timestamp)
            #shutil.move(src_filename, dest_filename)
            #shutil.rmtree(temp_working_dir)
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
    #  Attachment Generation
    ###############################################################################
    def __generate_attachments(self):
        self.__generate_https_attachment()
        bashCommand = "bash /home/report/exporting_agency.sh " + '"' + self.__agency + '"' 
        os.system(bashCommand)
        

    def __generate_https_attachment(self):
        generated_date_txt = self.__generated_time.strftime('%Y-%m-%d')
        header_fields = ('Agency', 'Registered Domains', 'Found Subdomains', 'Web-responsive Domains', 'Uses HTTPS', 'Enforces HTTPS', 'HSTS', 'Preloaded', 'M-15-13 Compliant Domains')
        data_fields = ('Agency', 'Registered Domains', 'Found Subdomains', 'Web-responsive Domains', 'Uses HTTPS', 'Enforces HTTPS', 'HSTS', 'Preloaded', 'M-15-13 Compliant Domains')
        with open('totals.csv', 'wb') as out_file:
            header_writer = csv.DictWriter(out_file, header_fields, extrasaction='ignore')
            data_writer = csv.DictWriter(out_file, data_fields, extrasaction='ignore')
            header_writer.writeheader()
            data_writer.writerow({'Agency':self.__agency, 'Registered Domains':self.__base_domain_count, 'Found Subdomains':self.__subdomain_count, 'Web-responsive Domains':self.__all_eligible_domains_count, 'Uses HTTPS':self.__domain_supports_https_count, 'Enforces HTTPS':self.__strictly_forces_count, 'HSTS':self.__hsts_count, 'Preloaded':self.__hsts_preloaded_count, 'M-15-13 Compliant Domains':self.__m1513_count})

    ###############################################################################
    #  Chart Generation
    ###############################################################################
    def __generate_charts(self):
        graphs.setup()
        self.__figure_overview()
        self.__donut_figure()


    def __figure_overview(self):
        N = 3
        Perct = (self.__uses_https_percentage, self.__enforces_https_percentage, self.__hsts_percentage)
        Diff = (100 - self.__uses_https_percentage, 100 - self.__enforces_https_percentage, 100 - self.__hsts_percentage)

        ind = np.arange(N)    # the x locations for the groups
        width = 0.5       # the width of the bars: can also be len(x) sequence

        p1 = plt.bar(ind, Perct, width, color="#0058A1", edgecolor="none") #dhs blue
        p2 = plt.bar(ind, Diff, width, color='w',
                 bottom=Perct, edgecolor="none")
    
        plt.ylabel('Percent (%)', fontsize=14, style='italic')
        plt.title('M-15-13 Components', fontsize=20, fontweight='bold')
        plt.xticks(ind + width/2., ('Uses HTTPS', 'Enforces HTTPS', 'Uses HSTS'), fontsize=14, style='italic')
        plt.yticks(np.arange(10, 100, 10), fontsize=13)

        def autolabel(p):
            # attach some text labels
            for bar in p:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., 1.05*height, #0.99 works well
                        '%d' % int(height) +'%',
                        ha='center', va='bottom', fontsize=15)

        autolabel(p1)
        #plt.show()
        plt.savefig(self.__path + '/component-compliance')#, bbox_inches=0, pad_inches=0
        plt.clf()


    def __donut_figure(self):
        labels = '', ''
        sizes = [100 - self.__m1513_percentage, self.__m1513_percentage]
        colors = ['white', "#0058A1"] #dhs blue

        plt.pie(sizes, labels=labels, colors=colors, shadow=False, startangle=90) #autopct='%1.1f%%'
        
        #draw a circle at the center of pie to make it look like a donut
        centre_circle = plt.Circle((0,0),0.75,color='black', fc='white',linewidth=1.25)
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)

        plt.text(0 , 0.15 , str(self.__m1513_percentage) + '%', horizontalalignment='center', verticalalignment='center', fontsize=50)
        plt.text(0 , -0.2 , 'M-15-13 Compliant', horizontalalignment='center', verticalalignment='center', fontsize=19.5, fontweight='bold')
        plt.tight_layout(pad=0.4, w_pad=0.5, h_pad=1.0)

        # Set aspect ratio to be equal so that pie is drawn as a circle.
        plt.axis('equal')
        #plt.show()
        plt.savefig(self.__path + '/overall-compliance')#bbox_inches='tight',pad_inches=0
        plt.close()
    
    ###############################################################################
    # Final Document Generation and Assembly
    ###############################################################################
    def __generate_mustache_json(self, filename):
        #result = {'all_domains':self.__all_domains}
        result = {'scorecard_doc':self.__scorecard_doc}
        result['ineligible_domains'] = self.__ineligible_domains
        result['domain_count'] = int(self.__domain_count) 
        result['subdomain_count'] = int(self.__subdomain_count)
        result['base_domain_count'] = int(self.__base_domain_count)
        result['eligible_domains_count'] = self.__eligible_domains_count
        result['eligible_subdomains_count'] = self.__eligible_subdomains_count
        result['https_compliance_list'] = self.__https_compliance_list
        result['non_https_compliance_list'] = self.__non_https_compliance_list
        result['title_date_tex'] = self.__generated_time.strftime('{%d}{%m}{%Y}')
        result['agency'] = self.__agency
        result['strictly_forces_percentage'] = round(((self.__strictly_forces_count/self.__domain_count) * 100), 1)
        result['downgrades_percentage'] = round(((self.__downgrades_count/self.__domain_count) * 100), 1)
        result['hsts_percentage'] = self.__hsts_percentage
        result['hsts_preloaded_percentage'] = round(((self.__hsts_preloaded_count/self.__domain_count) * 100), 1)
        result['hsts_entire_domain_percentage'] = round(((self.__hsts_entire_domain_count/self.__domain_count) * 100), 1)
        result['m1513_percentage'] = self.__m1513_percentage
        result['m1513_count'] = int(self.__m1513_count)
        result['domain_supports_https_count'] = int(self.__domain_supports_https_count)  #added
        result['uses_https_percentage'] = self.__uses_https_percentage
        result['enforces_https_percentage'] = self.__enforces_https_percentage
        result['strictly_forces_count'] = int(self.__strictly_forces_count)
        result['domain_enforces_https_count'] = int(self.__domain_enforces_https_count)
        result['hsts_count'] = int(self.__hsts_count)
        result['hsts_preloaded_count'] = int(self.__hsts_preloaded_count)
        result['hsts_preload_ready_count'] = int(self.__hsts_preload_ready_count)
        result['domain_uses_strong_hsts_count'] = int(self.__domain_uses_strong_hsts_count)        
        result['https_expired_cert_count'] = int(self.__https_expired_cert_count)
        result['https_bad_hostname_count'] = int(self.__https_bad_hostname_count)
        result['https_bad_chain_count'] = int(self.__https_bad_chain_count)
        result['path'] = self.__path
        result['hsts_low_max_age_count'] = self.__hsts_low_max_age_count
        
        self.__latex_escape_structure   (result['scorecard_doc'])

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
        
        return_code = subprocess.call(['xelatex', REPORT_TEX], stdout=output, stderr=subprocess.STDOUT) 
        assert return_code == 0, 'xelatex pass 1 of 2 return code was %s' % return_code
        
        return_code = subprocess.call(['xelatex', REPORT_TEX], stdout=output, stderr=subprocess.STDOUT)
        assert return_code == 0, 'xelatex pass 2 of 2 return code was %s' % return_code       


# connection to database
#def db_connection(uri): 
#    con = MongoClient(host='db', tz_aware=True)
#    db = con.m1513
#    return db


def main():
    args = docopt(__doc__, version='v0.0.1')
    #db = db_connection(database.db_from_config(args['--section']))
    con = MongoClient(host='db', tz_aware=True)
    db = con.m1513
     
    print 'Generating HTTPS Scorecard...'
    generator = ScorecardGenerator(db, args['"AGENCY"'], debug=args['--debug'])
    results = generator.generate_m1513_scorecard()
    print 'Done'
    sys.exit(0)

        
if __name__=='__main__':
    main()