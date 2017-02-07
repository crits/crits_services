from crits.services.core import Service
from . import forms
from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError
import requests
import base64
from ipwhois import IPWhois


class XFE_Service(Service):
    name = "XForce Exchange Service"
    version = "1.0.0"
    supported_types  = ['Sample','IP', 'Indicator']
    description = "X-Force Exchange Service to search file hashes & IP addresses"
    @staticmethod
    def save_runtime_config(config):
        del config['xfe_api_key']
        del config['xfe_api_password']
    
    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.XFEConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config
    @staticmethod
    def parse_config(config):
        if not config['xfe_api_key']:
            raise ServiceConfigError("API key required.")
        if not config['xfe_api_password']:
            raise ServiceConfigError("API password required.")
            
    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.XFEConfigForm(initial=config),
                                 'config_error': None})
        form = forms.XFEConfigForm
        return form, html
    @staticmethod
    def get_config_details(config):
        display_config = {}
        # Rename keys so they render nice.
        fields = forms.XFEConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    def run(self, obj, config):
        try:
            xfe_api_key = config.get('xfe_api_key', '')
            xfe_api_password = config.get('xfe_api_password', '')

            if obj._meta['crits_type'] == 'IP':
                ip = obj.ip
                self.who(ip)
                self.get_xfe_ipr(ip,xfe_api_key,xfe_api_password)
                self.get_xfe_ipr_malware(ip,xfe_api_key,xfe_api_password)
                self.get_xfe_domains(ip,xfe_api_key,xfe_api_password)

            elif obj._meta['crits_type'] == 'Indicator':
                if obj['ind_type'] == 'IPv4 Address':
                    ip = obj['value']
                    self.who(ip)
                    self.get_xfe_ipr(ip,xfe_api_key,xfe_api_password)
                    self.get_xfe_ipr_malware(ip,xfe_api_key,xfe_api_password)
                    self.get_xfe_domains(ip,xfe_api_key,xfe_api_password)

                elif obj['ind_type'] == 'MD5' or obj['ind_type'] == 'SHA1' or obj['ind_type'] == 'SHA256':
                    self.get_xfe_md5(obj['value'],xfe_api_key,xfe_api_password)

                else:
                    self._add_result("Service Results:","The service ran successfully, but the indicator type is not supported by XForce Exchange")

            elif obj._meta['crits_type'] == 'Sample':
                self.get_xfe_md5(obj.md5,xfe_api_key,xfe_api_password)

        except Exception as e:
            self._error("Error running service : {0}".format(str(e)))

    def who(self, ip):
        try:
            obj = IPWhois(ip)
            results = obj.lookup_whois()
            if 'nets' in results:
                name=desc=cidr=iprange=''
                if 'name' in results['nets'][0]:
                    name = results['nets'][0]['name']
                if 'description' in results['nets'][0]:
                    desc = results['nets'][0]['description']
                    if desc:
                        desc = desc.replace("\n",",")    
                if 'cidr' in results['nets'][0]:
                    cidr = results['nets'][0]['cidr']
                if 'range' in results['nets'][0]:
                    iprange = results['nets'][0]['range']
                    d = {'Name': name, 'Description': desc, 'CIDR': cidr, 'IPRange': iprange}
                self._add_result('Whois Info:', ip, d)
                
        except Exception as e:
            self._error("Error getting WHOIS report from X-Force Exchange: {0}".format(str(e)))

    def get_xfe_md5(self,md5,api_key,api_password):
        try:
            fullurl = "https://api.xforce.ibmcloud.com:443/malware/" + md5
            token = base64.b64encode("{0}:{1}".format(api_key, api_password))
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
            response = requests.get(fullurl, params='', headers=headers, timeout=20)
            if response.status_code == 200:
                self._info("Malware query result code: {0}".format(response.status_code))
                all_json = response.json()
                family=created=risk=''
                if 'malware' in all_json:
                        if 'origins' in  all_json['malware']:
                            if  'external' in all_json['malware']['origins']:
                                for family in all_json['malware']['origins']['external']['family']:
                                    d = {'Detection Coverage:': all_json['malware']['origins']['external']['detectionCoverage']}
                                    self._add_result("Origin: external",family, d)
                      
                            if 'CnCServers' in all_json['malware']['origins']:
                                if 'rows' in all_json['malware']['origins']['CnCServers']:
                                    for row in all_json['malware']['origins']['CnCServers']['rows']:
                                        d = {'Type': row['type'], "FirstSeen": row['firstseen'],"LastSeen": row['lastseen'],"IP": row['ip'],"URI": row['uri']}
                                        self._add_result("Origin: CnCServers",row['domain'],d)

                        if 'family' in all_json['malware']:
                            for m in all_json['malware']['family']:
                                    family+=m + ","
                                    family=family[:-1]

                        if 'created' in all_json['malware']:
                            created = all_json['malware']['created']

                        if 'risk' in all_json['malware']:
                            risk = all_json['malware']['risk']
                        
                        d = {'created': created, 'risk': risk}
                        self._add_result('Malware related to MD5 hash:',family,d)
                
        except Exception as e:
            self._error("Error getting MD5 report from X-Force Exchange: {0}".format(str(e)))

    def get_xfe_domains(self,ip,api_key,api_password):
        try:
            fullurl = "https://api.xforce.ibmcloud.com:443/resolve/" + ip
            token = base64.b64encode("{0}:{1}".format(api_key, api_password))
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
            response = requests.get(fullurl, params='', headers=headers, timeout=20)

            if response.status_code == 200:
                all_json = response.json()
                self._info("DNS query result code: {0}".format(response.status_code))
                if 'Passive' in all_json:
                    if 'records' in all_json['Passive']:
                        for record in all_json['Passive']['records']:
                                d = {'RecordType': record['recordType'], 'LastSeen':record['last'], 'FirstSeen':record['first']}     
                                self._add_result('Passive DNS:',record['value'],d)
        
                if 'RDNS' in all_json:
                    for record in all_json['RDNS']:
                        self._add_result('RDNS:',record)
                else:
                    self._error("Error: {0}".format(response.status_code))

        except Exception as e:
            self._error("Error getting domain report from X-Force Exchange: {0}".format(str(e)))


    def get_xfe_ipr_malware(self,ip,api_key,api_password):
        try:
            fullurl = "https://api.xforce.ibmcloud.com:443/ipr/malware/" + ip
            token = base64.b64encode("{0}:{1}".format(api_key, api_password))
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
            response = requests.get(fullurl, params='', headers=headers, timeout=20)
            if response.status_code == 200:
                all_json = response.json()
                self._info("IPR Malware query result code: {0}".format(response.status_code))

                if 'malware' in all_json:
                    for k in all_json['malware']:
                        malware=''
                        for m in k['family']:
                            malware+=m + ","
                        malware=malware[:-1]
                        d = {'domain': k['domain'],'FirstSeen': k['firstseen'], 'LastSeen': k['lastseen'], 'FilePath':k['filepath'], 'Origin': k['origin'], 'Family': malware}
                        self._add_result("Malware associated with this IP address:",k['md5'],d)
            else:
                self._error("Error: {0}".format(response.status_code))

        except Exception as e:
            self._error("Error getting malware report from X-Force Exchange: {0}".format(str(e)))

    def get_xfe_ipr(self,ip,api_key,api_password):
        try:
            fullurl = "https://api.xforce.ibmcloud.com:443/ipr/" + ip
            token = base64.b64encode("{0}:{1}".format(api_key, api_password))
            headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
            response = requests.get(fullurl, params='', headers=headers, timeout=20)
            if response.status_code == 200:
                self._info("IPR query result code: {0}".format(response.status_code))
                all_json = response.json()
                if 'geo' in all_json:
                    if 'country' in all_json['geo']:
                        self._add_result('Country:',all_json['geo']['country'])

                if 'score' in all_json:
                    self._add_result('Current malicious score:',all_json['score'])

                if 'cats'in all_json:
                    for key,val in all_json['cats'].iteritems():                
                        d = {'Score':val}
                        self._add_result('Categories:',key,d)

                if 'history' in all_json:
                    for hist in all_json['history']:
                        d = {'Date': hist['created'], 'Score': hist['score'], 'Reason':hist['reason'], "Description": hist['reasonDescription'] }
                        self._add_result('History:',hist['ip'],d)
            else:
                self._error("Error: {0}".format(response.status_code))

        except Exception as e: 
            self._error("Error getting IPR report from X-Force Exchange: {0}".format(str(e)))

