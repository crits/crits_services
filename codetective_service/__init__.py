# (c) 2015, Adam Polkosnik, <adam.polkosnik@ny.frb.org> || <apolkosnik@gmail.com>

import logging

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

# This will work if there's an __init__.py inside Codetective folder
from Codetective.codetective import get_type_of, Finding

DEFAULT_END = -1
DEFAULT_START = 0
DEFAULT_ANALYZE = True
DEFAULT_MODULES = ["win", "web", "crypto", "personal", "unix", "db", "other"]

class CodetectiveService(Service):
    """
    A tool to determine the crypto/encoding algorithm used according to traces of its representation
    """

    name = "codetective"
    version = '0.0.5'
    supported_types = ['Sample']
    description = "Find password hashes and so on"

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.CodetectiveServiceConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
        
        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config
    
    @staticmethod
    def parse_config(config):
        try:
            from Codetective.codetective import get_type_of, Finding
            return
        except:
            raise ServiceConfigError("Unable to import Codetective/codetective.py!")
    
    @staticmethod
    def get_config_details(config):
        display_config = {}
        
        # Rename keys so they render nice.
        fields = forms.CodetectiveServiceConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]
        return display_config

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")
        return

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.CodetectiveServiceConfigForm(),
                                 'config_error': None})
        form = forms.CodetectiveServiceConfigForm
        return form, html
    
    @staticmethod
    def bind_runtime_form(analyst, config):
        data = {'start_offset': config['start_offset'],
                'end_offset': config['end_offset'],
                'certainty': config['certainty'],
                'analyze': config['analyze']}
        return forms.CodetectiveServiceRunForm(data)
    
    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.CodetectiveServiceRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
    
    def run(self, obj, config):
        start_offset = config['start_offset']
        end_offset = config['end_offset']
        analyze = config['analyze']
        certainty = config['certainty']
        filters = config['filters']
        data = obj.filedata.read()[start_offset:end_offset]
        if not data:
            self._error("Codetective received no data.")
            raise ("Codetective received no data.")
        else:
            try:
                self._info("Codetective filters:%s analyze:%x, certainty:%d" %(filters, analyze, certainty))
                results = get_type_of(data, filters)
                results = [finding for finding in results if finding.certainty >= certainty]
                for finding in results:
                    self._add_result('Codetective', "%s" % repr(finding.payload), {'Offset': finding.location, 'Type': finding.type, 'Confidence': finding.confidence, 'Certainty': finding.certainty, 'Details':repr(finding.details), 'Datestamp': finding.created_on})
            except Exception as err:
                self._info("Codetective failed on: %s: %s" % (str(obj.id), err))
            self._info("Codetective finished on: %s" % str(obj.id) )
        return
