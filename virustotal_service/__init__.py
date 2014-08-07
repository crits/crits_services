import logging
import simplejson
import urllib
import urllib2

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service

from . import forms

logger = logging.getLogger(__name__)


class VirusTotalService(Service):
    """
    Check the VirusTotal database to see if it contains this sample, domain
    or IP.

    This does not submit the file to VirusTotal, but only performs a
    lookup of the sample's MD5.

    Requires an API key available from virustotal.com
    """

    name = "virustotal_lookup"
    version = '3.0.0'
    supported_types = ['Sample', 'Domain', 'IP']
    required_fields = []
    description = "Look up a Sample, Domain or IP in VirusTotal"

    @staticmethod
    def save_runtime_config(config):
        del config['vt_api_key']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.VirusTotalConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.VirusTotalConfigForm(initial=config),
                                 'config_error': None})
        form = forms.VirusTotalConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.VirusTotalConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        key = config.get('vt_api_key', '')
        sample_url = config.get('vt_query_url', '')
        domain_url = config.get('vt_domain_url', '')
        ip_url = config.get('vt_ip_url', '')
        if not key:
            self._error("No valid VT key found")
            return

        if obj._meta['crits_type'] == 'Sample':
            parameters = {"resource": obj.md5, "apikey": key}
            vt_data = urllib.urlencode(parameters)
            req = urllib2.Request(sample_url, vt_data)
        elif obj._meta['crits_type'] == 'Domain':
            parameters = {'domain': obj.domain, 'apikey': key}
            vt_data = urllib.urlencode(parameters)
            req = urllib2.Request("%s?%s" % (domain_url, vt_data))
        elif obj._meta['crits_type'] == 'IP':
            parameters = {'ip': obj.ip, 'apikey': key}
            vt_data = urllib.urlencode(parameters)
            req = urllib2.Request("%s?%s" % (ip_url, vt_data))

        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'https': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        try:
            response = urllib2.urlopen(req)
            json = response.read()
            response_dict = simplejson.loads(json)
        except Exception as e:
            logger.error("Virustotal: network connection error (%s)" % e)
            self._error("Network connection error checking virustotal (%s)" % e)
            return

        if response_dict.get('response_code', 0) != 1:
            return

        if obj._meta['crits_type'] == 'Sample':
            self._debug(response_dict.get('verbose_msg', 'No message from VT'))
            stats = {
                'scan_date':        response_dict.get('scan_date', ''),
                'positives':        response_dict.get('positives', 0),
                'total':            response_dict.get('total', 0),
            }
            result_string = "%d / %d" % (response_dict.get('positives', 0), response_dict.get('total', 0))
            self._add_result('stats', result_string, stats)
            self._add_result('permalink', response_dict.get("permalink", "No link"))
            scans = response_dict.get('scans', [])
            for scan in scans:
                if scans[scan]["result"]:
                    result = scans[scan]["result"]
                else:
                    result = ''
                detection = {
                    "engine":       scan,
                    "date":         scans[scan].get('update', ''),
                    "detected":     scans[scan].get('detected', ''),
                    "version":      scans[scan].get('version', ''),
                }
                self._add_result('av_result', result, detection)
        elif obj._meta['crits_type'] == 'Domain':
            for detected_url in response_dict.get('detected_urls', []):
                stats = {
                          'scan_date': detected_url.get('scan_date', ''),
                          'total': detected_url.get('total', 0),
                          'positives': detected_url.get('positives', 0),
                        }
                self._add_result('URLs', detected_url.get('url', ''), stats)

            for resolution in response_dict.get('resolutions', []):
                stats = { 'last_resolved': resolution.get('last_resolved', '') }
                self._add_result('A Records', resolution.get('ip_address', ''), stats)

            for category in response_dict.get('categories', []):
                self._add_result('Categories', category, {})
        elif obj._meta['crits_type'] == 'IP':
            for samp in response_dict.get('detected_communicating_samples', []):
                stats = {
                          'date': samp.get('date', ''),
                          'total': samp.get('total', 0),
                          'positives': samp.get('positives', 0)
                        }
                self._add_result('Detected Communicating Samples', samp.get('sha256', ''), stats)

            for samp in response_dict.get('undetected_communicating_samples', []):
                stats = {
                          'date': samp.get('date', ''),
                          'total': samp.get('total', 0),
                          'positives': samp.get('positives', 0)
                        }
                self._add_result('Undetected Communicating Samples', samp.get('sha256', ''), stats)

            for samp in response_dict.get('detected_downloaded_samples', []):
                stats = {
                          'date': samp.get('date', ''),
                          'total': samp.get('total', 0),
                          'positives': samp.get('positives', 0)
                        }
                self._add_result('Detected Downloaded Samples', samp.get('sha256', ''), stats)

            for samp in response_dict.get('undetected_downloaded_samples', []):
                stats = {
                          'date': samp.get('date', ''),
                          'total': samp.get('total', 0),
                          'positives': samp.get('positives', 0)
                        }
                self._add_result('Undetected Downloaded Samples', samp.get('sha256', ''), stats)

            for url in response_dict.get('detected_urls', []):
                stats = {
                          'scan_date': url.get('scan_date', ''),
                          'total': url.get('total', 0),
                          'positives': url.get('positives', 0)
                        }
                self._add_result('Detected URLs', url.get('url', ''), stats)

            for resolution in response_dict.get('resolutions', []):
                stats = {
                          'last_resolved': resolution.get('last_resolved', ''),
                        }
                self._add_result('Resolutions', resolution.get('hostname', ''), stats)
