# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# Copyright (c) 2016, Jacob Faires, Solutionary SERT.  All rights reserved.

# Source code distributed pursuant to license agreement.
# RAT Decoder code is from Kevin Breen.
# Wrapping into the CRITS module done by Jacob Faires.

from __future__ import division

import os
import sys
import imp
import importlib
import hashlib
import yara
import logging
import subprocess
import tempfile
from optparse import OptionParser

from decoders import JavaDropper

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class RATDecoderService(Service):
    """
    Extract config file from RAT PE files.
    """
    
    
    name = "ratdecoder"
    version = "1.0.1"
    supported_types = ['Sample']
    description = "RAT Config Extractor"
    
#    __author__ = 'Kevin Breen, https://techanarchy.net, https://malwareconfig.com'
#    __date__ = '2016/04'

    @staticmethod
    def valid_for(obj):
        # Only run on PE files
        if not obj.is_pe():
            raise ServiceConfigError("Not a PE.")

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.RATDecoderConfigForm(initial=config),
                                 'config_error': None})
        form = forms.RATDecoderConfigForm
        return form, html


    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.RATDecoderConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
            
        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config
    
    def unpack(self, raw_data):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(raw_data)
        f.close()
        try:
            subprocess.call("(upx -d %s)" %f.name, shell=True)
        except Exception as e:
            logger.error('UPX Error {0}'.format(e))
            return
        new_data = open(f.name, 'rb').read()
        os.unlink(f.name)
        return new_data


    # Yara Scanner Returns the Rule Name
    def yara_scan(self, raw_data, yara_dir):
        rule_file = '{0}yaraRules.yar'.format(yara_dir)
        logger.info(rule_file)
        yara_rules = yara.compile(rule_file)
        matches = yara_rules.match(data=raw_data)
        if len(matches) > 0:
            return str(matches[0])
        else:
            return


    def run(self, obj, config):
        raw_data = obj.filedata.read()

        # Yara Scan
        family = self.yara_scan(raw_data, config['yaradir'])

        # UPX Check and unpack
        if family == 'UPX':
            raw_data = self.unpack(raw_data)
            family = self.yara_scan(raw_data, config['yaradir'])

            if family == 'UPX':
                # Failed to unpack
                logger.error("  [!] Failed to unpack UPX")
                return

        # Java Dropper Check
        if family == 'JavaDropper':
            raw_data = JavaDropper.run(raw_data)
            family = self.yara_scan(raw_data, config['yaradir'])

            if family == 'JavaDropper':
                logger.error("  [!] Failed to unpack JavaDropper")
                return

        if not family:
            logger.error("    [!] Unabel to match your sample to a decoder")
            return
        
        # Import decoder
        try:
            module = imp.load_source(family,'{0}{1}.py'.format(str(config['decodersdir']),family))
        except ImportError:
            logger.error('    [!] Unable to import decoder {0}'.format(family))
            return

        # Get config data
        try:
            config_data = module.config(raw_data)
        except Exception as e:
            logger.error('Conf Data error with {0}. Due to {1}'.format(family, e))
            return

        self._add_result('ratdecoder','Family',{'Value':family})

        for key, value in sorted(config_data.iteritems()):
            self._add_result('ratdecoder',key,{'Value':value})
