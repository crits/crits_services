import re
import logging
import requests, time, json
from lxml import objectify
from urllib import quote_plus

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.services.handlers import get_service_config
from crits.emails.email import Email
from crits.events.event import Event
from crits.raw_data.raw_data import RawData
from crits.samples.sample import Sample
from crits.domains.domain import TLD
from crits.indicators.indicator import Indicator
from crits.core.data_tools import make_ascii_strings
from crits.vocabulary.indicators import IndicatorTypes, IndicatorThreatTypes

from . import forms
from searches import SplunkSearches

logger = logging.getLogger(__name__)


class SplunkSearchService(Service):
    """
    Craft custom Splunk searches from metadata gathered from a given TLO.

    Currently this service only runs on RawData, Samples, and Emails.
    """

    name = "SplunkSearch"
    version = '1.0.0'
    template = "splunk_search_service_template.html"
    supported_types = ['RawData', 'Sample', 'Email', 'Indicator']
    description = "Craft custom Splunk searches based on metadata."
    
    
    #### Handle configs stuff ####
    @staticmethod
    def parse_config(config):
        if not config['splunk_url']:
            raise ServiceConfigError("Splunk URL required.")
        if not config['splunk_user']:
            raise ServiceConfigError("Splunk username required.")
        if not config['password']:
            raise ServiceConfigError("Splunk password required.")
        
    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values
        config = {}
        fields = forms.SplunkSearchConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
            
        # If there is a config in the database, use values from that
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        
        return config
        
    @staticmethod
    def get_config_details(config):
        display_config = {}
        
        # Rename keys so they render nicely.
        fields = forms.SplunkSearchConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        
        return display_config
        
    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                'form': forms.SplunkSearchConfigForm(initial=config),
                                'config_error': None})
        form = forms.SplunkSearchConfigForm
        return form, html
    
    @staticmethod
    def save_runtime_config(config):
        del config ['splunk_user']
        del config ['password']
    
    @staticmethod
    def valid_for(obj):
        if isinstance(obj, Sample):
            if obj.filedata.grid_id == None:
                raise ServiceConfigError("Missing filedata.")

    def run(self, obj, config):
        self.config = config
        
		# Debug
        self._debug("Is triage run: %s" % str(self.is_triage_run))
		
        # Check if this is a triage run
        if self.is_triage_run:
            if isinstance(obj,Sample):
                filetype = str(obj.filetype)
                pattern = str(self.config['ignore_filetypes'])
                if re.match(pattern, filetype):
                    self._info("Search was not run on triage because %s matched on the regex %s" % (filetype, str(pattern)))
                    return
		
        #if isinstance(obj, Event):
        #    data = obj.description
        #elif isinstance(obj, RawData):
        if isinstance(obj, RawData):
            data = obj.data
        elif isinstance(obj, Email):
            data = obj.raw_body
        elif isinstance(obj, Sample):
            samp_data = obj.filedata.read()
            data = make_ascii_strings(data=samp_data)
            if not data:
                self._debug("Could not find sample data to parse.")
                return
        elif isinstance(obj, Indicator):
            data = ""
        else:
            self._debug("This type is not supported by this service.")
            return
            
        #Debug
        #self._debug(str(self.config))
        ips = []
        domains = []
        urls = []
        emails = []
        hashes = []
        
        all_splunk_searches = []
        
        '''
        if self.config['data_miner']==True:        
            ips = dedup(extract_ips(data))
            domains = dedup(extract_domains(data))
            urls = dedup(extract_urls(data))
            emails = dedup(extract_emails(data))
            hashes = dedup(extract_hashes(data))
            
            # Run searches based on DataMiner results
            datamined = {'urls': urls,
                         'domains': domains,
                         'ips': ips,
                         'hashes': hashes,
                         'emails': emails}
            splunk_obj = SplunkSearches(datamined,self.config['search_config'])
            splunk_searches_datamined = splunk_obj.datamined()
            all_splunk_searches.append(splunk_searches_datamined)
        '''
            
        if self.config['url_search']==True:
            urls = dedup(extract_urls(data))
            # Run searches for URLs
            splunk_obj = SplunkSearches(urls,self.config['search_config'])
            splunk_searches_urls = splunk_obj.url_searches()
            all_splunk_searches.append(splunk_searches_urls)
            
        if self.config['domain_search']==True:
            domains = dedup(extract_domains(data))
            # Run searches for domains
            splunk_obj = SplunkSearches(domains,self.config['search_config'])
            splunk_searches_domains = splunk_obj.domain_searches()
            all_splunk_searches.append(splunk_searches_domains)
            
        if self.config['ip_search']==True:
            ips = dedup(extract_ips(data)) 
            # Run searches for IPs
            splunk_obj = SplunkSearches(ips,self.config['search_config'])
            splunk_searches_ips = splunk_obj.ip_searches()
            all_splunk_searches.append(splunk_searches_ips)
            
        if self.config['hash_search']==True:
            hashes = dedup(extract_hashes(data)) 
            # Run searches for hashes
            splunk_obj = SplunkSearches(hashes,self.config['search_config'])
            splunk_searches_hashes = splunk_obj.hash_searches()
            all_splunk_searches.append(splunk_searches_hashes)
        
        if self.config['email_addy_search']==True:
            email_addys = dedup(extract_emails(data)) 
            # Run searches for Email addresses
            splunk_obj = SplunkSearches(email_addys,self.config['search_config'])
            splunk_searches_email_addys = splunk_obj.email_addy_searches()
            all_splunk_searches.append(splunk_searches_email_addys)
            
        # Set splunk_obj for TLO
        splunk_obj = SplunkSearches(obj,self.config['search_config'])
        
        if isinstance(obj, Email):
            splunk_searches = splunk_obj.email_searches()
            all_splunk_searches.append(splunk_searches)
            #self._debug(str(splunk_searches))
            
        elif isinstance(obj, Sample):
            splunk_searches = splunk_obj.sample_searches()
            all_splunk_searches.append(splunk_searches)
            
        elif isinstance(obj, Indicator):
            splunk_searches = splunk_obj.indicator_searches()
            all_splunk_searches.append(splunk_searches)
        
        '''
        all_splunk_searches = [{'description': 'Searches Splunk based on email attibutes',
                                'searches': [{'name': 'Searching for email subjects',
                                              'search': 'search index=smtp subject=blah'}]
                               },
                               {'description': 'Searches Splunk based on data mined',
                                'searches': [{'name': 'Searching for domain in http',
                                              'search': 'search index=http domain=badguy.com'}]
                               }
                               ]
        '''
        
        # Once splunk_searches is finally popluated, loop through the potential searches
        full_search_dict = {}
        self._debug("all_splunk_searches: %s" % str(all_splunk_searches))
        all_jobs = {}
        
        # Get the Session Key for talking with Splunk
        sessionKey = get_splunk_session_key(self.config)
        self._debug("Session key %s obtained." % sessionKey)
                        
        splunk_results = []
	
        for search_group in all_splunk_searches:
            if 'searches' in search_group and search_group['searches']:
                for search in search_group['searches']:
                    if search['search']!="":
                        ## Set the timeframe and search limit
                        search['search']="earliest="+self.config['search_earliest']+" "+search['search']
                        search['search']+="|head "+self.config['search_limit']
                        # Make sure it starts with 'search' or a | 
                        if not (search['search'].startswith("search") or search['search'].startswith("|")):
                            search['search']="search "+search['search']
                        
                        # Start a Splunk Search Job
                        job_sid = start_splunk_search_job(self.config, sessionKey, search['search'])
                        
                        # Add the job_sid to a list of jobs to poll
                        all_jobs[search['name']]=job_sid
                        

                        # Build a dict of search names and their searches
                        search_base=self.config['splunk_browse_url']+"en-US/app/search/search?q="
                        full_search=search_base+quote_plus(search['search'])
                        full_search_dict[search['name']] = full_search
                    
                
        # Poll the jobs now that we have a list of sids
        self._debug("Checking for results from the following jobs: %s" % str(all_jobs))
        poll_results = self.poll_jobs(self.config, sessionKey, all_jobs)
        self._debug("Results of the polling: %s" % str(poll_results))
        
        '''
        poll_results = {"done":[{'badguy.com': '<job_sid>'},
                               {'goodguy.com': '<job_sid>'}],
                       "timeout":[],
                       "failed":[]}
        '''
        
        
        # Log the results of the polls
        
        # Log errors
        for item in poll_results['timeout']:
            for k, v in item.iteritems():
                self._info("Splunk job %s for the search %s timed out." % (v,k))
                results = {k : {'results': [{'timeout':v}]}}
                splunk_results.append(results)
        for item in poll_results['failed']:
            for k, v in item.iteritems():
                self._info("Splunk job %s for the search %s FAILED. Check Splunk for deatils." % (v,k))
                results = {k : {'results': [{'failed':v}]}}
                splunk_results.append(results)
            
        # Get the results
        for item in poll_results['done']:
            self._debug("Sending the following item to Splunk to get the results: %s" % str(item))
            splunk_results.append(get_search_results(self.config, sessionKey, item))
            self._debug("splunk_results = %s" % str(splunk_results))
        
        # Parse the results and add to database
        
        # splunk_results = [{'search for emails': <json_content>},
        #                   {'search for domains': <json_content>}]
        
        '''
        # splunk_results for testing
        splunk_results = [{'test search 1': {'fields': [{'name': 'domain'},
                                                        {'groupby_rank': '0', 'name': 'src_ip'},
                                                        {'name': 'count'}],
                                             'results': [{'count': '1',
                                                          'domain': 'something.com',
                                                          'src_ip': '192.168.5.1'},
                                                         {'count': '1',
                                                          'domain': 'else.com',
                                                          'src_ip': '192.168.5.2'}]
                                            }
                           },
                           {'test search 2': {'fields': [{'groupby_rank': '0', 'name': 'domain'},
                                                        {'name': 'src_ip'},
                                                        {'name': 'count'}],
                                             'results': [{'count': '1',
                                                          'domain': 'badguy.com',
                                                          'src_ip': '192.168.1.1'},
                                                         {'count': '1',
                                                          'domain': 'goodguy.com',
                                                          'src_ip': '192.168.1.2'}]
                                            }
                           }]
        '''
        for splunk_result in splunk_results:
            for name, results in splunk_result.iteritems():
                # Build the header
                tdict = {"fields": [],
                         "full_search_dict": full_search_dict}
                field_count = 0
                self._debug("%s search results = %s" % (name, str(results)))
                if 'fields' in results:
                    for header in results['fields']:
                        for k, v in header.iteritems():
                            if k=='name':
                                if 'groupby_rank' in results['fields'][field_count]:
                                    tdict['fields'].insert(int(results['fields'][field_count]['groupby_rank']),
                                                           results['fields'][field_count]['name'])
                                else:
                                    tdict['fields'].append(v)
                        field_count+=1
                    # Build the search results
                    new_results = []
                    for event in results['results']:
                        # Set single string results to a list so all search results are in a list
                        event = {x : ([y] if isinstance(y,unicode) else y) for x,y in event.iteritems()}

                        # Check if there's a field from this event that doesn't have any data
                        for field in tdict['fields']:
                            if field not in event or not event[field]:
                                event[field]=['-']
                        new_results.append(event)
                        
                    results['results']=new_results
                    # Save it to the actual service results... Finally...
                    self._add_result(name, results['results'], tdict)
                
                # If 'fields' isn't in the results, something went wrong with the search,
                # or it didn't get any hits.
                else:
                    search_error=False
                    
                    for item in poll_results['failed']:
                        for k,v in item.iteritems():
                            if k==name:
                                search_error=True
                                tdict['fields']=['search_failed']
                                results['results']=[{'search_failed': 
                                                    ["Search ID %s failed. Check Splunk for details." % v]}]
                                self._add_result(name, results['results'], tdict)
                                
                    for item in poll_results['timeout']:
                        for k,v in item.iteritems():
                            if k==name:
                                search_error=True
                                tdict['fields']=['search_timeout']
                                results['results']=[{'search_timeout': 
                                                    ["Search ID %s timed out. Check Splunk for details." % v]}]
                                self._add_result(name, results['results'], tdict)
                                
                    if search_error==False:
                        tdict['fields']=['no_matches']
                        results['results']=[{'no_matches': ["No matches were found for this search"]}]
                        self._add_result(name, results['results'], tdict)


    # Poll Job IDs
    def poll_jobs(self, configs, sessionKey, all_jobs):
        splunk_url = configs['splunk_url']
        splunk_timeout = configs['splunk_timeout']
        headers = {"Authorization":"Splunk "+str(sessionKey)}
        search_link = splunk_url+"services/search/jobs/"
        job_results = {"done":[],
                       "timeout":[],
                       "failed":[]}
        first_run = True

        # Loop through the full list of jobs, polling status every 2 seconds
        # until runDuration > configs['splunk_timeout']. Waits 5 seconds
        # before first poll b/c c'mon... Splunk's not that fast.
        #
        # Also, if dispatchState or runDuration are not returning, something
        # probably went wrong... So it breaks the while loop and returns whatever
        # results it's grabbed.
        
        
        while all_jobs:
            if first_run == True:
                time.sleep(5)
                first_run = False
            '''
            all_jobs = {'badguy.com': '<job_sid>',
                        'goodguy.com': '<job_sid>'}
            '''
            for name, job_sid in all_jobs.iteritems():
                runDuration = ''
                dispatchState = ''
                search_check = requests.get(search_link+job_sid, headers=headers, verify=False)
                scheck_root = objectify.fromstring(search_check._content)
                for a in scheck_root.getchildren():
                    for b in a.getchildren():
                        for c in b.getchildren():
                            if 'name' in c.attrib and c.attrib['name']=='dispatchState':
                                dispatchState = c.text
                            if 'name' in c.attrib and c.attrib['name']=='runDuration':
                                runDuration = c.text
                
                # Emergency STOP if runDuration or dispatchState aren't found...
                self._debug("Search is %s. Run duration: %s" % (dispatchState, runDuration))
                if dispatchState=='':
                    self._debug("dispatchState was not returned for some reason.")
                    all_jobs = {x : y for x,y in all_jobs.iteritems() if x!=x}
                    return job_results
                if dispatchState!="QUEUED" and runDuration=='':
                    self._debug("runDuration was not returned for some reason.")
                    all_jobs = {x : y for x,y in all_jobs.iteritems() if x!=x}
                    return job_results

                if dispatchState=="DONE":
                    #job_results['done'].append(job_sid)
                    #all_jobs.remove(job_sid)
                    job_results['done'].append({name:job_sid})
                    all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
                elif dispatchState=="FAILED":
                    #job_results['failed'].append(job_sid)
                    #all_jobs.remove(job_sid)
                    job_results['failed'].append({name:job_sid})
                    all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
                if runDuration!='' and float(runDuration) > int(splunk_timeout):
                    #job_results['timeout'].append(job_sid)
                    #all_jobs.remove(job_sid)
                    job_results['timeout'].append({name:job_sid})
                    all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
                else:
                    self._debug("Search %s is currently %s. It has been running for %s seconds."
                                % (job_sid, dispatchState, runDuration))
                
            # Sleep 2 seconds between checking all jobs
            time.sleep(2)

        '''
        job_results = {"done":[{'badguy.com': '<job_sid>'},
                               {'goodguy.com': '<job_sid>'}],
                       "timeout":[],
                       "failed":[]}
        '''
        return job_results
    
    
# Get Search Results
def get_search_results(configs, sessionKey, name_sid):
    splunk_url = configs['splunk_url']
    headers = {"Authorization":"Splunk "+str(sessionKey)}
    data = {'output_mode': 'json'}
    json_response={}
    for name, sid in name_sid.iteritems():
        search_link = splunk_url+"services/search/jobs/"+sid+"/results/"
        search_rez = requests.get(search_link, headers=headers, params=data, verify=False)
        json_response[name] = json.loads(search_rez._content)
    
    '''
    json_response = {'search for emails': <json_content>}
    '''
    
    return json_response
    
# Start Splunk Search Job
def start_splunk_search_job(configs, sessionKey, search):
    splunk_url = configs['splunk_url']
    headers = {"Authorization":"Splunk "+str(sessionKey)}
    
    search_link = splunk_url+"services/search/jobs"
    search_data = {"search": search}
    search_resp = requests.post(search_link, headers=headers, data=search_data, verify=False)
    search_root = objectify.fromstring(search_resp._content)
    job_sid = str(search_root['sid'])
    
    return job_sid

# Get a Splunk session ID
def get_splunk_session_key(configs):
    splunk_url = configs['splunk_url']
    login_link = "services/auth/login"    
    login_data = {"username": configs['splunk_user'],
                  "password": configs['password']}
    auth_link = splunk_url+login_link
    resp = requests.get(auth_link, data=login_data, verify=False)
    root = objectify.fromstring(resp._content)
    sessionKey = root['sessionKey']
    
    return sessionKey

# Deduplicate results from DataMiner
def dedup(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]
        
# hack of a parser to extract potential ip addresses from data
def extract_ips(data):
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, data)]
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip)
    return ips

# hack of a parser to extract potential domains from data
def extract_domains(data):
    pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    domains = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_domains = []
    for item in domains:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_domains.append(item)
            except:
                pass
    return final_domains

# hack of a parser to extract potential URIs from data
'''
def extract_uris(data):
    pattern = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
    results = re.findall(pattern,data)
    #domains = [each[1] for each in results if len(each) > 0]
    uris = [each[2] for each in results if len(each) > 0]
    final_uris = []
    for item in uris:
        final_uris.append(item)
    return final_uris
'''

# hack of a parser to extract potential URLs (Links) from data
def extract_urls(data):
    pattern = r'(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
    results = re.findall(pattern,data)
    urls = [each for each in results if len(each) >0]
    final_urls = []
    for item in urls:
        url = item[0]+"://"+item[1]+item[2]
        final_urls.append(url)
    return final_urls


# hack of a parser to extract potential emails from data
def extract_emails(data):
    pattern = r'[a-zA-Z0-9-\.\+]+@.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    emails = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_emails = []
    for item in emails:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_emails.append(item)
            except:
                pass
    return final_emails

# hack of a parser to extract potential domains from data
def extract_hashes(data):

    re_md5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
    re_sha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
    re_sha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
    re_ssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

    final_hashes = []
    md5 = IndicatorTypes.MD5
    sha1 = IndicatorTypes.SHA1
    sha256 = IndicatorTypes.SHA256
    ssdeep = IndicatorTypes.SSDEEP
    final_hashes.extend(
        [(md5,each) for each in re.findall(re_md5, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(sha1,each) for each in re.findall(re_sha1, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(sha256,each) for each in re.findall(re_sha256, data) if len(each) > 0]
    )
    final_hashes.extend(
        [(ssdeep,each) for each in re.findall(re_ssdeep, data) if len(each) > 0]
    )
    return final_hashes

