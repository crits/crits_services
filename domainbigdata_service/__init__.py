# (c) 2017, Lionel PRAT <lionel.prat9@gmail.com>
# domainbigdata lookup on indicators email & domaines (https://domainbigdata.com)
# based on service preview of Adam Polkosnik
# use modified source code of Roberto Sponchioni - https://github.com/Ptr32Void/OSTrICa/blob/master/ostrica/Plugins/DomainBigData/__init__.py
# All rights reserved.

import logging
import os
import io
import StringIO

import IndicatorTypes

# for adding the extracted files
from django.conf import settings
from django.template.loader import render_to_string
from crits.services.core import Service, ServiceConfigError

from . import domainbigdata

logger = logging.getLogger(__name__)


class DomainBigDataService(Service):

    name = "DomainBigData"
    version = '0.0.1'
    supported_types = ['Domain', 'Indicator']
    description = "DomainBigData lookup on indicators email & domains"

    @staticmethod
    def valid_for(obj):
        # Only run on indictors: URI, DOMAIN, IP, FILE HASH
        # or on IP object == IP lookup
        # or on domain object == Domain lookup
        # or sample object == HASH lookup
        if obj._meta['crits_type'] == 'Indicator' and (obj['ind_type'] == 'Email Address' or obj['ind_type'] == 'Email Address From' or obj['ind_type'] == 'Email Reply-To' or obj['ind_type'] == 'Domain'):
            return True
        elif obj._meta['crits_type'] == 'Domain':
            return True
        return False

    def run(self, obj, config):
        self.config = config
        self.obj = obj
        user = self.current_task.user
        #create DomainBigData object
        self._info('RUN DomainBigData lookup')    
        dbd = domainbigdata.DomainBigData()
        result = None
        value_obj = None
        if (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'Domain') or obj._meta['crits_type'] == 'Domain':
            if obj._meta['crits_type'] == 'Domain':
                value_obj = obj.domain
            else:
                value_obj = obj['value']
            #run domain information
            try:
                self._info('Send request type domain on DomainBigData')
                result = dbd.domain_information(value_obj, self)
            except Exception as e:
                self._error('Query DomainBigData error:' + str(e))
        elif (obj._meta['crits_type'] == 'Indicator') and (obj['ind_type'] == 'Email Address' or obj['ind_type'] == 'Email Address From' or obj['ind_type'] == 'Email Reply-To' or obj['ind_type'] == 'Domain'):
            value_obj = obj['value']
            #email indicator
            try:
                self._info('Send request type email on DomainBigData')
                result = dbd.email_information(value_obj, self)
            except Exception as e:
                self._error('Query DomainBigData error:' + str(e))
        else:
            self._error('This object type cannot use service DomainBigData lookup.')
            return False
        if not result:
            self._info('Result is empty')
            return
        self._info('Processing results:' + str(result))
        #self._info(str(result))
        #add result
        if type(result) is dict:
            for k,v in result.iteritems():
                if not type(v) is dict:
                        if type(v) is list:
                            count=1
                            for item in v:
                                if type(item) is dict:
                                    self._add_result('Result of DomainBigData on ' + value_obj, k+' -> '+str(count), item)
                                elif type(item) is list:
                                     self._add_result('Result of DomainBigData on ' + value_obj, k+' -> '+str(count), {'value': str(item)})
                                else:
                                     self._add_result('Result of DomainBigData on ' + value_obj, k+' -> '+str(count), {'value': item})
                                count+=1
                        else:
                            self._add_result('Result of DomainBigData on ' + value_obj, k, {'value': v})
        if type(result) is dict:
            for k,v in result.iteritems():
                if type(v) is dict:
                    for kx,vx in v.iteritems():
                        if type(vx) is dict:
                            self._add_result('Result of DomainBigData on ' + value_obj + ' -- Result: ' + k, kx, {'value': vx})
                        elif type(vx) is list:
                            count=1
                            for item in vx:
                                if type(item) is dict:
                                    self._add_result('Result of DomainBigData on ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), item)
                                elif type(item) is list:
                                     self._add_result('Result of DomainBigData on ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), {'value': str(item)})
                                else:
                                     self._add_result('Result of DomainBigData on ' + value_obj + ' -- Result: ' + k, kx+' -> '+str(count), {'value': item})
                                count+=1
                        else:
                            self._add_result('Result of DomainBigData on ' + value_obj + ' -- Result: ' + k, kx, {'value': vx})
        self._info('END')

