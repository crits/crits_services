# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# OTX lookup on indicators/domains/IP/HASH sample (https://otx.alienvault.com)
# based on service preview of Adam Polkosnik
# All rights reserved.

import logging
import os
import io
import StringIO

#OTX
from OTXv2 import OTXv2
import IndicatorTypes

# for adding the extracted files
from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError
from crits.vocabulary.ips import IPTypes

from . import forms

logger = logging.getLogger(__name__)


class OTXService(Service):

    name = "OTX"
    version = '0.0.1'
    supported_types = ['Sample', 'Domain', 'IP', 'Indicator']
    description = "OTX lookup on indicators"

    @staticmethod
    def parse_config(config):
        api_key = config.get("api_key", "")
        if not api_key:
            raise ServiceConfigError("You must specify a valid API key for OTX.")
        otx_server = config.get("otx_server", "")
        if not otx_server:
            raise ServiceConfigError("You must specify a valid URL for OTX serveur.")
    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.OTXConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'api_key': config['api_key'], 'otx_server': config['otx_server']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.OTXConfigForm(initial=config),
                                 'config_error': None})
        form = forms.OTXConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        # Only run on indictors: URI, DOMAIN, IP, FILE HASH
        # or on IP object == IP lookup
        # or on domain object == Domain lookup
        # or sample object == HASH lookup
        if obj._meta['crits_type'] == 'Indicator' and (obj['ind_type'] == 'URI' or obj['ind_type'] == 'Domain' or obj['ind_type'].startswith('IP') or obj['ind_type'] == 'MD5' or obj['ind_type'] == 'SHA1' or obj['ind_type'] == 'SHA256'):
            return True
        elif obj._meta['crits_type'] == 'Domain' or obj._meta['crits_type'] == 'IP' or obj._meta['crits_type'] == 'Sample':
            return True
        return False

    def run(self, obj, config):
        self.config = config
        self.obj = obj
        user = self.current_task.user
        otx_server = self.config.get("otx_server", "https://otx.alienvault.com/")
        if not otx_server:
            self._error("No valid URL for OTX server.")
            return
        api_key = self.config.get("api_key", "")
        if not api_key:
            self._error("No valid OTX API key found")
            return
        #create OTX connect
        self._info('RUN OTX lookup')    
        otx = OTXv2(api_key, server=otx_server)
        self._info('Check obj type')
        IndType = None
        value_obj = None
        if (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'Domain') or obj._meta['crits_type'] == 'Domain':
            if obj._meta['crits_type'] == 'Domain':
                value_obj = obj.domain
            else:
                value_obj = obj['value']
            IndType = IndicatorTypes.DOMAIN
        elif (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'IPv4') or (obj._meta['crits_type'] == 'IP' and obj.ip_type == IPTypes.IPV4_ADDRESS):
            IndType = IndicatorTypes.IPv4
            if obj._meta['crits_type'] == 'IP':
                value_obj = obj.ip
            else:
                value_obj = obj['value']
        elif (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'IPv6') or (obj._meta['crits_type'] == 'IP' and obj.ip_type == IPTypes.IPV6_ADDRESS):
            if obj._meta['crits_type'] == 'IP':
                value_obj = obj.ip
            else:
                value_obj = obj['value']
            IndType = IndicatorTypes.IPv6
        elif (obj._meta['crits_type'] == 'Indicator' and (obj['ind_type'] == 'MD5' or obj['ind_type'] == 'SHA1' or obj['ind_type'] == 'SHA256')) or obj._meta['crits_type'] == 'Sample':
            if obj._meta['crits_type'] == 'Sample':
                IndType = IndicatorTypes.FILE_HASH_MD5
                value_obj = obj.md5
            elif obj['ind_type'] == 'MD5':
                IndType = IndicatorTypes.FILE_HASH_MD5
                value_obj = obj['value']
            elif obj['ind_type'] == 'SHA1':
                IndType = IndicatorTypes.FILE_HASH_SHA1
                value_obj = obj['value']
            elif obj['ind_type'] == 'SHA256':
                IndType = IndicatorTypes.FILE_HASH_SHA256
                value_obj = obj['value']
        elif (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'URI'):
            IndType = IndicatorTypes.URL
            value_obj = obj['value']
            #TODO extract HOST and make second request
        else:
            self._error('This object type cannot use service OTX lookup.')
            return False
        #query OTX
        self._info('Send request to OTX')
        try:
            result = otx.get_indicator_details_full(IndType, value_obj)
        except Exception as e:
            self._error('Query OTX error:' + str(e))
        self._info('Processing results')
        #self._info(str(result))
        #add result
        if type(result) is dict:
            for k,v in result.iteritems():
                if type(v) is dict:
                    for kx,vx in v.iteritems():
                        if type(vx) is dict:
                            self._add_result('Result of OTX on ' + str(IndType) + ' -> ' + value_obj + ' -- Result: ' + k, kx, {'value': vx})
                        elif type(vx) is list:
                            count=1
                            for item in vx:
                                if type(item) is dict:
                                    self._add_result('Result of OTX on ' + str(IndType) + ' -> ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), {'value': item})
                                elif type(item) is list:
                                     self._add_result('Result of OTX on ' + str(IndType) + ' -> ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), {'value': item})
                                else:
                                     self._add_result('Result of OTX on ' + str(IndType) + ' -> ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), {'value': item})
                                count+=1
                        else:
                            self._add_result('Result of OTX on ' + str(IndType) + ' -> ' + value_obj + ' -- Result: ' + k, kx, {'value': vx})
        self._info('END')

