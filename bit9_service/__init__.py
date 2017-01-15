from crits.services.core import Service
from . import forms
from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError
import requests

class Bit9Service(Service):
    name = "Bit9 Hash Lookup"
    version = "1.0.0"
    supported_types  = ['Sample', 'Indicator']
    description = "Bit9 Service to search file hashes"

    @staticmethod
    def save_runtime_config(config):
        del config['bit9_api_key']
        del config['bit9_server']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.Bit9ConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['bit9_api_key']:
            raise ServiceConfigError("API key required.")
        if not config['bit9_server']:
            raise ServiceConfigError("Bit9 Server required.")
        else:
            if 'https://' not in config.get('bit9_server','') and 'http://' not in config.get('bit9_server',''):
                raise ServiceConfigError("Bit9 Server required, include the http:// or https://") 

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.Bit9ConfigForm(initial=config),
                                 'config_error': None})
        form = forms.Bit9ConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.Bit9ConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        try:
            key = config.get('bit9_api_key', '')
            server = config.get('bit9_server','')
            self.get_hash(key,server, obj)

        except Exception as e:
            self._error("Error: %s" % str(e))

    def get_hash(self, apikey, server, obj):
        try: 
            url =''
            if obj._meta['crits_type'] == 'Indicator':
                if obj['ind_type'] == 'MD5':
                    url = ''.join((server,"/api/bit9platform/v1/filecatalog?q=md5:",obj['value']))
                
                elif obj['ind_type'] == 'SHA1':    
                    url = ''.join((server,"/api/bit9platform/v1/filecatalog?q=sha1:",obj['value']))

                elif obj['ind_type'] == 'SHA256':    
                    url = ''.join((server,"/api/bit9platform/v1/filecatalog?q=sha256:",obj['value']))

                else:
                    self._add_result("Service Sucessfully ran", "Indicator type is not searchable in BIT9" )
                    return
            
            elif obj._meta['crits_type'] == 'Sample':
                url = ''.join((server,"/api/bit9platform/v1/filecatalog?q=md5:",obj.md5))

            else:
                return

            headers = {'X-Auth-Token': apikey}
            self._info("Searching Bit9.")
            response = requests.get(url,headers=headers, verify=False)
            self._info("Filecatalog query status code: {0}".format(response.status_code))
            if response.status_code == 200:
                all_json = response.json()
                if all_json:
                    if 'computerId' in all_json[0]:
                        hostname = self.get_computer(server,apikey,all_json[0]['computerId'])
                        if hostname is not None:
                            data = {'State': all_json[0]['effectiveState'],'Filename': all_json[0]['fileName'], 'Path': all_json[0]['pathName'], 'Publisher': all_json[0]['publisher'], 'ProductName': all_json[0]['productName'], 'Threat': all_json[0]['threat'], 'Filesize': all_json[0]['fileSize']}
                            self._add_result('Bit9 Data',hostname,data)
                        else:
                            self._error("Error determining hostname!")
                    else:
                          self._error("\'computerId\' key was not found!")
                else:
                    self._info("No result found!")       
            else:
                  self._error("Error: {0}".format(response.status_code))

        except Exception as e:
            self._error("Error: %s" % str(e))   

    def get_computer(self, server, apikey, id):
        try:
            url = server + "/api/bit9platform/v1/computer?q=id:" + str(id)
            headers = {'X-Auth-Token': apikey}
            response = requests.get(url,headers=headers, verify=False)
            self._info("Computer query status code: {0}".format(response.status_code))
            if response.status_code == 200:
                all_json = response.json()
                if all_json:
                    if 'name' in all_json[0]:
                        return all_json[0]['name']
                    else:
                        self._error("\'name\' key was not found!")
                else:
                    self._info("No result found!") 
            else:
                    self._error("Error: {0}".format(response.status_code))

            return None
    
        except Exception as e:
                self._error("Error: %s" % str(e)) 
