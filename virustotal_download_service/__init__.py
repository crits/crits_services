import hashlib
import logging
import simplejson
import urllib
import urllib2

from django.conf import settings

from crits.services.core import Service, ServiceConfigOption
from crits.samples.sample import Sample

logger = logging.getLogger(__name__)


class VirusTotalDownloadService(Service):
    """
    Check the VirusTotal database to see if it contains a sample matching the given md5.

    If VirusTotal has the sample, the sample is downloaded to CRITs.

    Requires an API key available from virustotal.com
    """

    name = "VirusTotal_Download"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    required_fields = ['md5']
    default_config = [
        ServiceConfigOption('vt_api_key',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from VirusTotal.",
                            required=True,
                            private=True),
        ServiceConfigOption('vt_download_url',
                            ServiceConfigOption.STRING,
                            default='https://www.virustotal.com/intelligence/download',
                            required=True,
                            private=True),
        ServiceConfigOption('size_limit',
                            ServiceConfigOption.INT,
                            description="Maximum size of downloaded binary, in bytes.",
                            default=50000000,
                            required=True),
        ServiceConfigOption('replace',
                            ServiceConfigOption.BOOL,
                            description="Replace sample in CRITs, if exists, with sample from VirusTotal.",
                            default=False,
                            required=False),
    ]

    def _scan(self, context):
        from crits.samples.handlers import handle_file
        from crits.services.handlers import run_triage

        key = self.config.get('vt_api_key', '')
        url = self.config.get('vt_download_url', '')
        sizeLimit = self.config.get('size_limit', '')
        replace = self.config.get('replace', False)
        if not key:
            self._error("No valid VirusTotal key found")
            return
        if sizeLimit == '':
            self._error("No maximum binary size provided.")
            return

        sample = Sample.objects(md5=context.md5).first()
        if not sample:
            sample = Sample()
            sample.md5 = md5_digest
        self._info("Checking if binary already exists in CRITs.")
        sample.discover_binary()
        if sample.filedata and replace == False: #if we already have this binary and don't have permission to replace
            self._info("CRITs already has this binary. Enable the 'Replace' option to overwrite with data from VirusTotal.")
            self._add_result("Download Canceled", "Binary already exists in CRITs.")
            return

        analyst = "VTDownload"
        parameters = urllib.urlencode({"hash": context.md5, "apikey": key})
        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'http': settings.HTTP_PROXY, 'https': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        try:
            req = url + "?" + parameters
            self._info("Requesting binary with md5 '{0}' from VirusTotal.".format(context.md5))
            request = urllib2.Request(req)
            response = urllib2.urlopen(request)
            size = response.info().getheaders("Content-Length")[0]
            self._info("Binary size: {0} bytes".format(size))

            if int(size) <= sizeLimit:
                data = response.read()
                if data:
                    if replace == True:
                        self._info("Replace = True. Deleting any previous binary with md5 {0}".format(context.md5))
                        sample.filedata.delete()
                    self._info("Adding new binary to CRITs.")
                    handle_file(filename = context.filename,
                                data = data,
                                source = "VirusTotal",
                                reference = "Binary downloaded from VT based on MD5",
                                user = analyst,
                                method = "VirusTotal Download Service",
                                md5_digest = context.md5 )
                    self._info("Running sample triage for data-reliant services.")
                    run_triage(data, sample, user = analyst)
                    self._add_result("Download Successful", "Binary was successfully downloaded from VirusTotal")
                else:
                    self._error("No data returned by VirusTotal.")
            else:
                self._error("Binary size is {0} bytes, which is greater than maximum of {1} bytes. This limit can be changed in options.".format(size, sizeLimit))
                self._add_result("Download Aborted", "Match found, but binary is larger than maximum size limit.")
        except urllib2.HTTPError, e:
            if e.code == 404:
                self._info("No results were returned. Either VirusTotal does not have the requested binary, or the request URL is incorrect.")
                self._add_result("Not Found", "Binary was not found in the VirusTotal database")
            elif e.code == 403:
                self._error("Download forbidden. {0}".format(e))
                self._add_result("Download Canceled", "CRITs was forbidden from downloading the binary.")
            else:
                self._error("An HTTP Error occurred: {0}".format(e))
        except:
            logger.error("VirusTotal: network connection error")
            self._error("Network connection error checking VirusTotal")
            return
