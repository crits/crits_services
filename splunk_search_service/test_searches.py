# This is a helper script used to test your searches.json file and make sure it returns
# the Splunk results you're looking for.

# Make sure the configs match your specific options, and set the desired search type to 'True'.
# Feel free to modify the dummy data to emulate a desired TLO, or list of domains/hashes/etc.

import json, time, requests

from searches import SplunkSearches

from lxml import objectify
from urllib import quote_plus
from pprint import pprint

# Manual configs for test run
configs = {'splunk_url': 'https://192.168.1.100:8089/',
           'splunk_browse_url': 'https://192.168.1.100:8000/',
           'search_limit': '10',
           'splunk_timeout': '180',
           'splunk_user': '<username>',
           'password': '<password>',
           'search_earliest':'-1d@d',
           'search_config':'/opt/crits/crits_services/splunk_search_service/searches.json',
           'url_search': False,
           'domain_search': False,
           'ip_search': False,
           'hash_search': False,
           'email_addy_search': False,
           'sample_search': False,
           'email_search': False,
           'indicator_search': False}
           
#### Set dummy data for Splunk searches ####

dummy_sample = {'filedata': 'block_of_data',
                'filename': 'test_file.bin',
                'filenames': ['test1.bin','test2.bin'],
                'filetype': 'PDF document, version 1.5',
                'md5': '098f6bcd4621d373cade4e832627b4f6',
                'mimetype': 'application/pdf',
                'sha1':'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
                'sha256':'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                'size':'111530',
                'ssdeep':'3072:LeaaIQxECw+cRCd8iMXsxWcdkQyMGDPl492RMUtQpYqgJQ:LevIQxEfLYdAX/8kmGB4IRMFYjJQ',
                'impfuzzy':'None'}
                
dummy_email = {'boundary': 'None',
               'cc': 'test@test.com',
               'date': 'Sat, 8 Apr 2017 05:30:00 +0700',
               'from_address': '"Badguy, Worst" <test@badsender.com>',
               'helo': 'None',
               'message_id': '<123456789@test.com>',
               'originating_ip': '192.168.1.100',
               'raw_body': 'This is the email',
               'raw_header': 'Test header',
               'reply_to': 'spoof@test.com',
               'sender': 'test@badsender.com',
               'subject': 'Test subject',
               'to': 'recip1@test.com, recip2@test.com',
               'x_originating_ip': '192.168.1.101',
               'x_mailer': 'None'}
               
dummy_indicator = {'activity': 'None',
                   'confidence': 'Unknown',
                   'impact': 'Unknown',
                   'ind_type': 'Domain',
                   'threat_types': 'Unknown',
                   'attack_types': 'Unknown',
                   'value': 'badguy.com',
                   'lower': 'None'}
                   
urls = ['https://badguy.com/test', 'http://goodguy.com/test']
domains = ['badguy.com', 'goodguy.com']
ips = ['192.168.1.100', '192.168.1.102']
emails = ['test@test.com', 'test2@test2.com']
hashes = [['md5', '098f6bcd4621d373cade4e832627b4f6'],['sha1','a94a8fe5ccb19ba61c4c0873d391e987982fbbd3']]


#### Handle Splunk Interaction ####

# Poll Job IDs
def poll_jobs(configs, sessionKey, all_jobs):
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
            print("Search is %s. Run duration: %s" % (dispatchState, runDuration))
            if dispatchState=='':
                print("dispatchState was not returned for some reason.")
                all_jobs = {x : y for x,y in all_jobs.iteritems() if x!=x}
                return job_results
            if dispatchState!="QUEUED" and runDuration=='':
                print("runDuration was not returned for some reason.")
                all_jobs = {x : y for x,y in all_jobs.iteritems() if x!=x}
                return job_results

            if dispatchState=="DONE":
                job_results['done'].append({name:job_sid})
                all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
            elif dispatchState=="FAILED":
                job_results['failed'].append({name:job_sid})
                all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
            if runDuration!='' and float(runDuration) > int(splunk_timeout):
                job_results['timeout'].append({name:job_sid})
                all_jobs = {x : y for x,y in all_jobs.iteritems() if name!=x}
            else:
                print("Search %s is currently %s. It has been running for %s seconds."
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
    
#### Run the tests ####

all_splunk_searches = []
all_jobs={}

if configs['url_search']==True:
    #urls = dedup(extract_urls(data))
    # Run searches for URLs
    splunk_obj = SplunkSearches(urls,configs['search_config'])
    splunk_searches_urls = splunk_obj.url_searches()
    all_splunk_searches.append(splunk_searches_urls)
    
if configs['domain_search']==True:
    #domains = dedup(extract_domains(data))
    # Run searches for domains
    splunk_obj = SplunkSearches(domains,configs['search_config'])
    splunk_searches_domains = splunk_obj.domain_searches()
    all_splunk_searches.append(splunk_searches_domains)
    
if configs['ip_search']==True:
    #ips = dedup(extract_ips(data)) 
    # Run searches for IPs
    splunk_obj = SplunkSearches(ips,configs['search_config'])
    splunk_searches_ips = splunk_obj.ip_searches()
    all_splunk_searches.append(splunk_searches_ips)
    
if configs['hash_search']==True:
    #hashes = dedup(extract_hashes(data)) 
    # Run searches for hashes
    splunk_obj = SplunkSearches(hashes,configs['search_config'])
    splunk_searches_hashes = splunk_obj.hash_searches()
    all_splunk_searches.append(splunk_searches_hashes)

if configs['email_addy_search']==True:
    #email_addys = dedup(extract_emails(data)) 
    # Run searches for Email addresses
    splunk_obj = SplunkSearches(email_addys,configs['search_config'])
    splunk_searches_email_addys = splunk_obj.email_addy_searches()
    all_splunk_searches.append(splunk_searches_email_addys)
    

if configs['email_search']==True:
    # Set splunk_obj for TLO
    splunk_obj = SplunkSearches(dummy_email,configs['search_config'])
    
    splunk_searches = splunk_obj.email_searches()
    all_splunk_searches.append(splunk_searches)
    #self._debug(str(splunk_searches))
    
if configs['sample_search']==True:
    # Set splunk_obj for TLO
    splunk_obj = SplunkSearches(dummy_sample,configs['search_config'])
    
    splunk_searches = splunk_obj.sample_searches()
    all_splunk_searches.append(splunk_searches)
    
if configs['indicator_search']==True:
    # Set splunk_obj for TLO
    splunk_obj = SplunkSearches(dummy_indicator,configs['search_config'])

    splunk_searches = splunk_obj.indicator_searches()
    all_splunk_searches.append(splunk_searches)

# Get the Splunk session ID
sessionKey = get_splunk_session_key(configs)

# Start the search jobs
for search_group in all_splunk_searches:
    if 'searches' in search_group and search_group['searches']:
        
        splunk_results = []
        
        
        
        for search in search_group['searches']:
            if search['search']!="":
                ## Set the timeframe and search limit
                search['search']="earliest="+configs['search_earliest']+" "+search['search']
                search['search']+="|head "+configs['search_limit']
                # Make sure it starts with 'search' or a | 
                if not (search['search'].startswith("search") or search['search'].startswith("|")):
                    search['search']="search "+search['search']
                
                # Start a Splunk Search Job
                job_sid = start_splunk_search_job(configs, sessionKey, search['search'])
                
                # Add the job_sid to a list of jobs to poll
                all_jobs[search['name']]=job_sid
                
                # Output
                print("Launched search!\r\n%s\r\n%s\r\nJob ID: %s" % (search['name'],search['search'], job_sid))

                # Build a dict of search names and their searches
                search_base=configs['splunk_browse_url']+"en-US/app/search/search?q="
                full_search=search_base+quote_plus(search['search'])
                print("Open in browser: %s \r\n\r\n" % full_search)
                #full_search_dict[search['name']] = full_search
                
        # Poll results
        poll_results = poll_jobs(configs, sessionKey, all_jobs)
        print("Polling results:")
        
        for item in poll_results['timeout']:
            for k, v in item.iteritems():
                print("Splunk job %s for the search %s timed out." % (v,k))
                
        for item in poll_results['failed']:
            for k, v in item.iteritems():
                print("Splunk job %s for the search %s FAILED. Check Splunk for deatils." % (v,k))
                            
        # Get the results
        for item in poll_results['done']:
            #print("Sending the following item to Splunk to get the results: %s" % str(item))
            splunk_results.append(get_search_results(configs, sessionKey, item))
        print("Finished job results:")
        pprint(splunk_results)

