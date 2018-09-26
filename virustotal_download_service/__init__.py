import logging
import urllib
import urllib2

from django.conf import settings
from django.template.defaultfilters import filesizeformat
from django.template.loader import render_to_string

from crits.services.analysis_result import AnalysisResult
from crits.core.user_tools import get_user_info
from crits.samples.handlers import handle_file
from crits.samples.sample import Sample
from crits.services.core import Service, ServiceConfigError
from crits.services.handlers import run_triage
from crits.vocabulary.acls import SampleACL

from . import forms

logger = logging.getLogger(__name__)


class VirusTotalDownloadService(Service):
    """
    Check the VirusTotal database to see if it contains a sample matching the given md5.

    If VirusTotal has the sample, the sample is downloaded to CRITs.

    Requires an API key available from virustotal.com
    """

    name = "VirusTotal_Download"
    version = '1.1.3'
    description = "Check VT for a given MD5. If a match is found, download the sample to CRITs."
    supported_types = ['Sample']
    required_fields = ['md5']

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.VirusTotalDLConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def valid_for(obj):
        # Check if already running in case of triage re-run
        rezs = AnalysisResult.objects(object_id=str(obj.id),
                                      status='started',
                                      service_name='VirusTotal_Download')
        if rezs:
            raise ServiceConfigError("Service is already running")

    @staticmethod
    def parse_config(config):
        if not config['vt_api_key']:
            raise ServiceConfigError("API key required.")
        if not config['size_limit']:
            raise ServiceConfigError("Maximum binary size limit required.")

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.VirusTotalDLConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.VirusTotalDLConfigForm(initial=config),
                                 'config_error': None})
        form = forms.VirusTotalDLConfigForm
        return form, html

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                'form': forms.VirusTotalDLRunForm(),
                                'crits_type': crits_type,
                                'identifier': identifier})

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values have varied over time, so cover the bases
        replace = config.get('replace_sample', False)
        if isinstance(replace, list):
            replace = replace[0]
        if isinstance(replace, bool):
            config['replace_sample'] = replace
        else:
            config['replace_sample'] = True if replace == 'on' else False

        triage = config.get('run_triage', False)
        if isinstance(triage, list):
            triage = triage[0]
        if isinstance(triage, bool):
            config['run_triage'] = triage
        else:
            config['run_triage'] = True if triage == 'on' else False

        size = config['size_limit']
        if isinstance(size, list):
            size = size[0]
        config['size_limit'] = int(size)
        return forms.VirusTotalDLRunForm(config)

    @staticmethod
    def save_runtime_config(config):
        config['Download URL'] = config.pop('vt_download_url', None)
        size = config.pop('size_limit')
        config['Size Limit'] = "%s (%s)" % (size, filesizeformat(size))
        config['Replace Sample'] = config.pop('replace_sample')
        config['Run Triage'] = config.pop('run_triage')
        del config['vt_api_key']

    def run(self, obj, config):
        key = config.get('vt_api_key', '')
        url = config.get('vt_download_url', '')
        sizeLimit = config.get('size_limit', '')
        replace = config.get('replace_sample', False)
        do_triage = config.get('run_triage', False)

        user = self.current_task.user
        sample = Sample.objects(md5=obj.md5).first()
        if not sample:
            sample = Sample()
            sample.md5 = md5_digest
        self._info("Checking if binary already exists in CRITs.")
        sample.discover_binary()

        if sample.filedata and replace == False: #if we already have this binary and don't have permission to replace
            self._info("CRITs already has this binary. Enable the 'Replace' option to overwrite with data from VirusTotal.")
            self._add_result("Download Canceled", "Binary already exists in CRITs.")
            return

        if not user.has_access_to(SampleACL.WRITE):
            self._info("User does not have permission to add Samples to CRITs")
            self._add_result("Download Canceled", "User does not have permission to add Samples to CRITs")
            return

        parameters = urllib.urlencode({"hash": obj.md5, "apikey": key})
        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'http': settings.HTTP_PROXY, 'https': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)

        try:
            req = url + "?" + parameters
            self._info("Requesting binary with md5 '{0}' from VirusTotal.".format(obj.md5))
            request = urllib2.Request(req)
            response = urllib2.urlopen(request)
            size = response.info().getheaders("Content-Length")[0]
            self._info("Binary size: {0} bytes".format(size))

            if int(size) > sizeLimit: # Check if within size limit
                self._error("Binary size is {0} bytes, which is greater than maximum of {1} bytes. This limit can be changed in options.".format(size, sizeLimit))
                self._add_result("Download Aborted", "Match found, but binary is larger than maximum size limit.")
                return

            data = response.read()
        except urllib2.HTTPError as e:
            if e.code == 404:
                self._info("No results were returned. Either VirusTotal does not have the requested binary, or the request URL is incorrect.")
                self._add_result("Not Found", "Binary was not found in the VirusTotal database")
            elif e.code == 403:
                self._error("Download forbidden. {0}".format(e))
                self._add_result("Download Canceled", "CRITs was forbidden from downloading the binary.")
            else:
                self._error("An HTTP Error occurred: {0}".format(e))
            return
        except Exception as e:
            logger.error("VirusTotal: Failed connection ({0})".format(e))
            self._error("Failed to get data from VirusTotal: {0}".format(e))
            return

        if data: # Retrieved some data from VT
            if replace == True:
                try:
                    self._info("Replace = True. Deleting any previous binary with md5 {0}".format(obj.md5))
                    sample.filedata.delete()
                except Exception as e:
                    logger.error("VirusTotal: Error deleting existing binary ({0})".format(e))
                    self._error("Failed to delete existing binary")
            self._info("Adding new binary to CRITs.")

            try:
                handle_file(filename = obj.md5,
                            data = data,
                            source = "VirusTotal",
                            reference = "Binary downloaded from VT based on MD5",
                            user = "VT Download Service",
                            method = "VirusTotal Download Service",
                            md5_digest = obj.md5 )
            except Exception as e:
                logger.error("VirusTotal: Sample creation failed ({0})".format(e))
                self._error("Failed to create new Sample: {0}".format(e))
                return
            if do_triage:
                self._info("Running sample triage for data-reliant services.")
                sample.reload()
                run_triage(sample, user = "VT Download Service")
            self._add_result("Download Successful", "Binary was successfully downloaded from VirusTotal")
        else:
            self._error("No data returned by VirusTotal.")
