import urlparse
import hashlib
import logging
import requests
import json

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

class ThreatGRIDService(Service):
    """
    ThreatGRID interoperability with CRITS.

    Requires an API key from the specified ThreatGRID applicance.
    """

    name = "threatgrid"
    version = '1.0.0'
    supported_types = ['Sample']
    description = 'Submit a sample to ThreatGRID'

    host = ''
    api_key = ''

    @staticmethod
    def save_runtime_config(config):
        del config['api_key']

    @staticmethod
    def parse_config(config):
        if not config['api_key']:
            raise ServiceConfigError("API key required.")

    @staticmethod
    def get_config(existing_config):
        """
        Retrieve configuration information for ThreatGRID
        """
        config = {}
        fields = forms.ThreatGRIDConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        #If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        """
        Provide the configuration information for ThreatGRID
        """
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatGRIDConfigForm(initial=config),
                                 'config_error': None})
        form = forms.ThreatGRIDConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        """
        Get configuration information from service settings
        """
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.ThreatGRIDConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    def api_request(self, path, req_params, req_type='get'):
        """
        Handle HTTP/HTTPS requests to the API
        - Implement error handling in a single location
        """
        url = urlparse.urljoin(self.host, path)
        req_params['api_key'] = self.api_key
        req_verify = False  #SSL CERT verification

        if req_type == 'get':
            #Complete HTTP GET Request
            response = requests.get(url, params=req_params, verify=req_verify)
            #HTTP error handling
            if response.status_code == 200:
                result = json.loads(response.content)
                return result
            else:
                error = json.loads(response.content)
                for item in error.get('error').get('errors'):
                    code = item.get('code')
                    message = item.get('message')
                    self._error(response.get('HTTP Response {}: {}'.format(code, message)))
                return
        elif req_type == 'post':
            #Complete HTTP POST Request
            if 'sample' in req_params:
                #Submit a sample
                data = req_params.pop('sample')
                response = requests.post(url,
                                 params=req_params,
                                 files={'sample':(req_params.get('filename'), data)},
                                 verify=req_verify)
            else:
                response = requests.post(url,
                                 params=req_params,
                                 verify=req_verify)
            #HTTP error handling
            if response.status_code == 200:
                result = json.loads(response.content)
                return result
            else:
                error = json.loads(response.content)
                for item in error.get('error').get('errors'):
                    code = item.get('code')
                    message = item.get('message')
                    self._error(response.get('HTTP Response {}: {}'.format(code, message)))
                return
        return        

    def md5_search(self, md5):
        """
        Search for results by MD5
        """
        #Set API query parameters and conduct query
        params = {'md5': md5}
        response = self.api_request('/api/v2/samples', params, 'get')
        if response:
            result_count = response.get('data', {}).get('current_item_count', 0)
            self._info('{} results returned from ThreatGRID MD5 search.'.format(result_count))
            #Loop through the page of results (only 1 page requested)
            if result_count > 0:
                for item in response.get('data',{}).get('items'):
                    result = {
                            'id':               item.get('id'),
                            'submitted_at':     item.get('submitted_at'),
                            'tags':             ''.join(item.get('tags',[])),
                            'login':            item.get('login'),
                            'state':            item.get('state'),
                            'status':           item.get('status'),
                            }
                    self._add_result('threatgrid_search ({})'.format(md5), item.get('filename'), result)
                return True
        else:
            self._error('An error occured while looking for sample: {}.'.format(md5))
        return False

    def sample_submit(self, filename, crits_id, data):
        """
        Submit a sample to ThreatGRID
        """
        #Set API query parameters and submit sample
        params = {'tags': 'CRITS',
                    'filename': filename,
                    'os': '',
                    'osver': '',
                    'source': 'CRITS:{}'.format(crits_id),
                    'sample': data}
        response = self.api_request('/api/v2/samples', params, 'post')

        if response:
            self._info("Sample submitted to ThreatGRID.")
            if response.get('data'):
                submitted = response.get('data')
                result = {
                        'id':               submitted.get('id'),
                        'submitted_at':     submitted.get('submitted_at'),
                        'tags':             ''.join(submitted.get('tags',[])),
                        'submission_id':    submitted.get('submission_id'),
                        'state':            submitted.get('state'),
                        'status':           submitted.get('status'),
                        }
                self._add_result('threatgrid_submitted ({})'.format(submitted.get('md5')), submitted.get('filename'), result)

                #Check that ThreatGRID and CRITS MD5's match.
                md5 = hashlib.md5(data).hexdigest()
                if md5 == submitted.get('md5').lower():
                    return True
                else:
                    self._error("MD5 mismatch between ThreatGRID and CRITS.")
        self._error("ThreatGRID sample submission failed.")
        return False


    def run(self, obj, config):
        """
        Begin ThreatGRID service
        """
        self.host = config.get('host', '')
        self.api_key = config.get('api_key', '')

        if obj._meta['crits_type'] == 'Sample':
            #Search for existing results or submit sample
            data = obj.filedata.read()
            md5 = hashlib.md5(data).hexdigest()
            if not self.md5_search(md5):
                self.sample_submit(obj.filename, obj.id, data)
        else:
            self._error("Invalid type passed to ThreatGRID service plugin.")
            return

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
