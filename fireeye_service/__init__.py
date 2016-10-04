import base64
import requests
import json
import time
import re
from lxml import etree

from django.template.loader import render_to_string
from . import forms
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.core.user_tools import get_user_organization
from crits.core.data_tools import create_zip

class FireeyeService(Service):
    """
    Analyze a sample using the FireyeMAS appliance through the Fireeye CMS.
    """

    name = 'Fireeye_Sandbox'
    version = '1.1.0'
    supported_types = ['Sample']
    description = "Analyze a sample using the FireyeMAS appliance through the Fireeye CMS."

    @staticmethod
    def parse_config(config):
        # When editing a config we are given a string.
        # When validating an existing config it will be a list.
        # Convert it to a list of strings.
        machines = config.get('machine', [])
        if isinstance(machines, basestring):
            config['machine'] = [machine for machine in machines.split('\r\n')]
        errors = []
        if not config['host']:
            errors.append("Fireeye host required.")
        if not config['machine']:
            errors.append("List of machines required.")
        if not config['username']:
            errors.append("Username is required.")
        if not config['password']:
            errors.append("Password is required.")
        if errors:
            raise ServiceConfigError(errors)

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.FireeyeConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        # Convert machines to newline separated strings
            config['machine'] = '\r\n'.join(config['machine'])
            html = render_to_string('services_config_form.html',
                                    {'name': self.name,
                                    'form': forms.FireeyeConfigForm(initial=config),
                                    'config_error': None})
            form = forms.FireeyeConfigForm
            return form, html

    @staticmethod
    def _tuplize_machines(machines):
        return [(machine, machine) for machine in machines]

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        machines = FireeyeService._tuplize_machines(config['machine'])
        return render_to_string("services_run_form.html",
                                {'name': self.name,
                                'form': forms.FireeyeRunForm(machines=machines),
                                'crits_type': crits_type,
                                'identifier': identifier})

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'force' not in config:
            config['force'] = False
        machines = FireeyeService._tuplize_machines(config['machine'])

        # The integer values are submitted as a list for some reason.
        # Package and machine are submitted as a list too.
        data = { 'timeout': config['timeout'][0],
                'machine': config['machine'][0],
                'force' : config['force']}
        return forms.FireeyeRunForm(machines=machines, data=data)

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.FireeyeConfigForm().fields
        for name, field in fields.iteritems():
            if name == 'machine':
                display_config[field.label] = '\r\n'.join(config[name])
            else:
                display_config[field.label] = config[name]
        return display_config

    @staticmethod
    def save_runtime_config(config):
        del config ['username']
        del config ['password']

    @property
    def base_url(self):
        return 'https://%s/wsapis/v1.1.0' % (self.config.get('host'))

    @property
    def username(self):
        return self.config.get('username')

    @property
    def password(self):
        return self.config.get('password')

    @property
    def proxies(self):
        proxy_host = self.config.get('proxy_host')
        proxy_port = self.config.get('proxy_port')
        if proxy_host:
            proxy = proxy_host + ':' + str(proxy_port)
        else:
            proxy = ''
        return {'http': proxy, 'https': proxy}
    
    #Authenicating to the CMS with a username and password. Then retrieving the token to use in this session.
    @property
    def authentication(self):
        credentials = self.username + ':' + self.password
        b64credentials = base64.b64encode(credentials)
        headers = {'Authorization': 'Basic ' + b64credentials}
        r = requests.post(self.base_url + '/auth/login', headers=headers, verify=False, proxies=self.proxies)
        token = r.headers['X-FeApi-Token']
        return token

    #Function to parse out the xml node (file, network, etc) within the os-changes node. 
    def parse(self, k, itags, iattributes, ikey, nodes):
        data = {tag: "none" for tag in itags}
        for attrib in iattributes:
            data[attrib] = "none"
        first = True
        result = ""
        for n in nodes:
            if n.tag == k:
                if not first:
                    self._add_result(k, result, data) 
                    result = ""
                data = {tag: "none" for tag in itags}
                for attrib in iattributes:
                    data[attrib] = "none"
            if n.tag == ikey:
                result = n.text
            elif n.tag in itags and data.get(n.tag, "none") == "none":
                data[n.tag] = n.text
            for attrib in iattributes:
                if attrib in data and data[attrib] == "none":
                    data[attrib] = n.attrib.get(attrib, "none")
            first = False
        self._add_result(k, result, data)

    #Submitting sample via a zip file. The MAS options are defined in json_option. 
    def submit_sample(self, obj):
        timeout = self.config.get('timeout')
        machine = self.config.get('machine', "")
        sc = self.authentication
        headers = {'X-feApi-Token': sc, 'X-FeClient-Token':'critsy test'}
        json_option = {"application":"0",
                       "timeout": str(timeout),
                       "priority":"0",
                       "profiles":[machine],
                       "analysistype":"2",
                       "force":self.config.get('force'),
                       "prefetch":"1"}
        jsondata = json.dumps(json_option)


        submission = {'filedata' : (obj.filename,obj.filedata)}
        self._info("About to post to FE MAS")
        r = requests.post(self.base_url + '/submissions',
                          headers=headers,
                          files=submission,
                          data ={'options':jsondata},
                          verify=False,
                          proxies=self.proxies)
        
        if r.status_code != requests.codes.ok:
            msg = "Failed to submit file to machine '%s'." % machine
            self._error(msg)
            self._debug(r.text)
        
        task_id = r.json()[0]['ID']
        self._info("Submitted Task ID %s for machine %s" % (task_id, machine))
        self.timeout = timeout
        self.sc = sc
        self.task = task_id

    #Does a loop check of up to five times to see if the analysis has been completed. If the the analysis is completed it grab the FE ID to pull back the xml report.
    def get_analysis(self):
        counter = 1
        headers = {'X-FEApi-Token': self.sc}
        first = True
        while counter <= 5:
            r = requests.get(self.base_url + '/submissions/status/' + self.task, headers=headers, verify=False, proxies=self.proxies)
            try:
                res = r.json()['submissionStatus']
            except TypeError as err:
                res = r.text
            if first is True:
                time.sleep(self.timeout+10)
            if res == "Done":
                complete = requests.get(self.base_url + '/submissions/results/' + self.task, headers=headers, verify=False, proxies=self.proxies, stream=True)
                analysis_xml = etree.parse(complete.raw)
                root = analysis_xml.getroot()
                analysis_id = root.find('{http://www.fireeye.com/alert/2013/AlertSchema}alert')
                fe_id = analysis_id.attrib['id']
                self._info ("Analysis has been completed. FE_ID = %s" % fe_id)
                self.fe_id = fe_id
                break
            elif res == "In Progress":
                self._info("Analysis is still running for %s" % self.task)
                time.sleep(30)
                counter += 1
            elif res == "Submission not found":
                self._info("Submission not found for task %s" % self.task)
                break
            first = False
            

    #Retrieve the xml report and parsing out parts of the xml report. 
    def get_report(self):
        headers = {'X-FEApi-Token': self.sc}
        r = requests.get(self.base_url + '/alerts?alert_id=' + self.fe_id + '&info_level=normal', headers=headers, verify=False, proxies=self.proxies, stream=True)
        report_xml = etree.parse(r.raw)
        root_xml = report_xml.getroot()
        #Using xpath to drill into the specific nodes in the report. 
        ns = {'ns2': 'http://www.fireeye.com/alert/2013/AlertSchema'}
        os_changes_nodes = root_xml.xpath("//ns2:explanation/os-changes", namespaces=ns)
        malware_nodes = root_xml.xpath("//ns2:malware", namespaces=ns)
        cnc_nodes = root_xml.xpath("//ns2:cnc-service", namespaces=ns)
        for node in malware_nodes:
            mnode = {}
            mnode['type'] = node.attrib.get('stype', 'none')
            mname = node.attrib.get('name', 'none')
            self._add_result('Malware-detected', mname, mnode)
        #Parsing cnc-service node and regexing out domain, UA, and URL from channel node. 
        if cnc_nodes:
            for node in cnc_nodes:
                data = {}
                domain = ""
                data['port'] = node.attrib.get('port', 'none')
                data['protocol'] = node.attrib.get('protocol', 'none')
                for child in node:
                    if 'channel' in child.tag:
                        result  = child.text
                        if result is None:
                            result = ""
                        host = re.findall ('~~Host:(.*?)::', result, re.DOTALL)
                        if host:
                            domain = host[0] 
                        else:
                            domain = ""
                        if result:
                            data ['channel'] = result
                        else:
                            data ['channel'] = ""
                        ua = re.findall ('~~User-Agent:(.*?)::', result, re.DOTALL)
                        if ua:
                            data ['User Agent'] = ua[0]
                        else:
                            data ['User Agent'] = ""
                        url = re.findall ('^(.*?)::', result, re.DOTALL)
                        if url:
                            data ['URL'] = url[0]
                        else:
                            data ['URL'] = ""
                self._add_result('CNC-Services', domain, data)

        #Parsing the os-changes looking for "malicious-alert". If malicious alert exist then it will attempt to parse out certain nodes. 
        for node in os_changes_nodes:
            malicious_alert_nodes = node.xpath("./malicious-alert")
            if not malicious_alert_nodes:
                continue
            os = node.xpath("./os")
            if os is None:
                continue
            data = {}
            data['OS'] = os[0].attrib.get('name', "os")
            version = os[0].attrib.get('version', "version")
            data['SP']  = os[0].attrib.get('sp', "sp")
            self._add_result('VM', version, data)
            app = node.xpath("./application")
            if app is None:
                continue
            appname = app[0].attrib.get('app-name', 'unknown')
            self._add_result('Application', appname, {})
            for ma_node in malicious_alert_nodes:
                self._add_result('Alert', ma_node.attrib['classtype'], {})
            network_nodes = node.xpath("network/descendant-or-self::*")
            #Check to see if these nodes exist in OS changes. If they do exist, it is sent to the parse function. 
            #key = the value you want to be able to pivot on. 
            #itags = are the tags you want to pull out and put in the dictionary. 
            #iattributes = are the attributes you want to pull out and put in the dictionary.
            #k = is the node name that is being parse out. 
            if network_nodes:
                ikey = 'md5sum'
                itags = ['imagepath', 'hostname', 'protocol_type', 'ipaddress', 'destination_port', 'http_request']
                iattributes = ['mode']
                k = 'network'
                self.parse(k, itags, iattributes, ikey, network_nodes)

            file_nodes = node.xpath("file/descendant-or-self::*")
            if file_nodes:
                ikey = 'md5sum'
                itags = ['value', 'imagepath']
                iattributes = ['mode', 'type']
                k = 'file'
                self.parse(k, itags, iattributes, ikey, file_nodes)
            
            folder_nodes = node.xpath("folder/descendant-or-self::*")
            if folder_nodes:
                ikey = 'value'
                itags = ['imagepath']
                iattributes = ['mode']
                k = 'folder'
                self.parse(k, itags, iattributes, ikey, folder_nodes)
            
            mutex_nodes = node.xpath("mutex/descendant-or-self::*")
            if mutex_nodes:
                ikey = 'value'
                itags = ['imagepath']
                iattributes = ''
                k = 'mutex'
                self.parse(k, itags, iattributes, ikey, mutex_nodes)

            regkey_nodes = node.xpath("regkey/descendant-or-self::*")
            if regkey_nodes:
                ikey = 'value'
                itags = ['imagepath']
                iattributes = ['mode']
                k = 'regkey'
                self.parse(k, itags, iattributes, ikey, regkey_nodes)

            #Parsing out the process node and pullin out mode, cmdline, parentname, and value. Some options were under target and source. 
            #If the option exist under target and source they went under value and parentname dictionary. 
            process_nodes = node.xpath("process")
            if process_nodes:
                for pnode in process_nodes:
                    data = {}
                    result = ""
                    data['mode'] =  pnode.attrib.get('mode', 'unknown')
                    for pnodel2 in pnode:
                        if pnodel2.tag == 'cmdline':
                            result = pnodel2.text
                        if pnodel2.tag == 'parentname':
                            data['parentname'] = pnodel2.text
                        if pnodel2.tag == 'value':
                            data['value'] = pnodel2.text
                        if pnodel2.tag == 'target':
                            for pnodel3 in pnodel2:
                                for pnodel4 in pnodel3:
                                    if pnodel4.tag == 'imagepath':
                                        data['value'] = pnodel4.text
                        if pnodel2.tag == 'source':
                            for pnodel3 in pnodel2:
                                for pnodel4 in pnodel3:
                                    if pnodel4.tag == 'imagepath':
                                        data['parentname'] = pnodel4.text
                    self._add_result('Process', result, data)

    #End the session for this current request.
    def logout(self):
        headers = {'X-FEApi-Token': self.sc}
        r = requests.post(self.base_url + '/auth/logout', headers=headers, verify=False, proxies=self.proxies)

    def run(self, obj, config):
        self.config = config
        self.obj = obj

        self.submit_sample(self.obj)
        self._info("Submission Completed")
        self.get_analysis()
        self._info("Analysis Completed")
        self.get_report()
        self._info("Report Generated")
        self.logout()
        self._info("Logged out now...")
