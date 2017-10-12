# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# Create analysis URL indicator: screenshot, har, ssl info, code page 
# based on service preview of Adam Polkosnik
# All rights reserved.

import logging
import os
import io
import selenium
import StringIO
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time, json
import socks, ssl, M2Crypto
from urlparse import urlparse

# for computing the MD5
from hashlib import md5
from hashes.simhash import simhash

# for image conversion
from PIL import Image

# for adding the extracted files
from crits.screenshots.handlers import add_screenshot

from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from crits.vocabulary.acls import ScreenshotACL
from crits.vocabulary.acls import RawDataACL
from crits.raw_data.handlers import handle_raw_data_file
from crits.vocabulary.relationships import RelationshipTypes

from . import forms

logger = logging.getLogger(__name__)


class urlanalysisService(Service):

    name = "UrlAnalysis"
    version = '0.0.1'
    supported_types = ['Indicator']
    description = "Analysis URL and get ssl information, HAR, screenshot, code page."

    @staticmethod
    def parse_config(config):
        tlp_value = config.get("tlp_value", "")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.UrlAnalysisConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'tlp_value': config['tlp_value']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.UrlAnalysisConfigForm(initial=config),
                                 'config_error': None})
        form = forms.UrlAnalysisConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        # Only run on URI indictor
        if obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'URI':
            return True
        return False

    def run(self, obj, config):
        self.config = config
        self.obj = obj
        user = self.current_task.user
        tlp_value = self.config.get("tlp_value", "tlp_value")
        url = obj['value']
        if not (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'URI'):
            self._error('This object type cannot use service Url analysis.')
            return False
        #verify url http or https
        if url.startswith('https://') or url.startswith('http://'):
            #put url in file
            dcap = dict(DesiredCapabilities.PHANTOMJS)
            dcap["phantomjs.page.settings.userAgent"] = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122 Safari/537.36")
            driver = webdriver.PhantomJS(desired_capabilities=dcap, service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any', '--web-security=false'])
            driver.set_window_size(1024, 768)
            driver.set_page_load_timeout(30)
            driver.get(url)
            time.sleep(3)
            #driver.save_screenshot('testing1.png')
            screen = driver.get_screenshot_as_png()
            ofile = io.BytesIO()
            im = Image.open(StringIO.StringIO(screen))
            im.save(ofile,'PNG', optimize=True)
            ofile.seek(0)
            res = add_screenshot(description='Render of a website URL',
                                         tags=None,
                                         method=self.name,
                                         source=obj.source,
                                         reference=None,
                                         analyst=self.current_task.user.username,
                                         screenshot=ofile,
                                         screenshot_ids=None,
                                         oid=obj.id,
                                         tlp=tlp_value,
                                         otype="Indicator")
            if res.get('message') and res.get('success') == True:
                self._warning("res-message: %s id:%s" % (res.get('message'), res.get('id') ) )
                self._add_result('ScreenShot URL', res.get('id'), {'Message': res.get('message')})
            #parse HAR
            har = driver.get_log('har')
            if type(har) is list and har:
                if type(har[0]) is dict and 'message' in har[0]:
                    #change unicode to json
                    try:
                        har[0]['message']=json.loads(har[0]['message'])
                    except:
                        self._warning('Har log error to parse json')
                    if type(har[0]['message']) is dict and 'log' in har[0]['message'] and type(har[0]['message']['log']) is dict and 'pages' in har[0]['message']['log']:
                        if type(har[0]['message']['log']['pages']) is list and har[0]['message']['log']['pages'] and type(har[0]['message']['log']['pages'][0]) is dict:
                            title='Result of '
                            if 'id' in har[0]['message']['log']['pages'][0]:
                                title += har[0]['message']['log']['pages'][0]['id']
                            if 'title' in har[0]['message']['log']['pages'][0]:
                                 self._add_result(title, 'Title', {'value': har[0]['message']['log']['pages'][0]['title']})
                        #parse each request and response
                        if 'entries' in har[0]['message']['log'] and type(har[0]['message']['log']['entries']) is list and har[0]['message']['log']['entries']:
                            count=1
                            type_r = ['cookies', 'queryString', 'headers']
                            type_rs = ['content', 'timings', 'cache']
                            for elem_rr in har[0]['message']['log']['entries']:
                                for k,v in elem_rr.iteritems():
                                    if type(v) is not dict:
                                        self._add_result(title + ' -- Informations Request & Response num:'+str(count), k, {'value': v})
                                for k,v in elem_rr.iteritems():
                                    if type(v) is dict:
                                        for kx,vx in v.iteritems():
                                            self._add_result(title + ' -- Informations Request & Response num:'+str(count) + ' -- '+ str(k), kx, {'value': vx})
                                count+=1
            #save page source in rawdata
            if not user.has_access_to(RawDataACL.WRITE):
                self._info(driver.page_source.encode('utf8'))
            else:
                #can write
                result = handle_raw_data_file(
                    driver.page_source.encode('utf8'),
                    obj.source,
                    user=self.current_task.user,
                    description="Code page for URL: %s" % url,
                    title=url,
                    data_type="Text",
                    tool_name=self.name,
                    tool_version=self.version,
                    tool_details=self.description
                )
                if result['success']:
                    obj.add_relationship(
                        result['object'],
                        RelationshipTypes.CONTAINED_WITHIN,
                        analyst=self.current_task.user.username,
                        rel_reason="Extracted from URI"
                    )
                    obj.save()
                self._add_result('Code Page', url, {'RawData TLO ID': result['_id'], 'md5 file': md5(driver.page_source.encode('utf8')).hexdigest(), 'simhash': str(simhash(driver.page_source.encode('utf8')))})
            driver.close()
            driver.service.process.terminate()
            time.sleep(1)
            #get certificat information - ref: https://stackoverflow.com/questions/30862099/how-can-i-get-certificate-issuer-information-in-python
            #because selenium not functionnality
            if url.startswith('https://'):
                try:
                    host = urlparse(url).hostname
                    port = urlparse(url).port
                    if(port is None):
                        port = 443
                    s = socks.socksocket()
                    if settings.HTTP_PROXY:
                        type_proxy = socks.PROXY_TYPE_SOCKS5
                        if settings.HTTP_PROXY.startswith('http://'):
                            type_proxy = socks.PROXY_TYPE_HTTP
                        s.setproxy(type_proxy, urlparse(settings.HTTP_PROXY).hostname, port=urlparse(settings.HTTP_PROXY).port)
                    s.connect((host, port))
                    ss = ssl.wrap_socket(s)
                    pem_data = ssl.DER_cert_to_PEM_cert(ss.getpeercert(True))
                    ss.close()
                    s.close()
                    cert = M2Crypto.X509.load_cert_string(pem_data)
                    #put ssl information
                    self._add_result('SSL informations', 'Subject', {'value': str(cert.get_subject().as_text())})
                    self._add_result('SSL informations', 'Issuer', {'value': str(cert.get_issuer().as_text())})
                    self._add_result('SSL informations', 'Version', {'value': str(cert.get_version())})
                    self._add_result('SSL informations', 'Date before', {'value': str(cert.get_not_before())})
                    self._add_result('SSL informations', 'Date after', {'value': str(cert.get_not_after())})
                    self._add_result('SSL informations', 'Serial Number', {'value': str(cert.get_serial_number())})
                    self._add_result('SSL informations', 'Verify', {'value': str(cert.verify())})
                    self._add_result('SSL informations', 'Fingerprint MD5', {'value': str(cert.get_fingerprint())})
                    for i in range(0, cert.get_ext_count()):
                        self._add_result('SSL informations Extension', str(cert.get_ext_at(i).get_name()), {'value': str(cert.get_ext_at(i).get_value())})
                    #https://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509-module.html
                except:
                    self._error('Error: get certificate informations.')
                self._info(str(cert))
            driver.service.process.kill()
            driver.quit()
            self._info('END')
