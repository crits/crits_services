# (c) 2014, Adam Polkosnik <adam.polkosnik@ny.frb.org> 
# 
import logging
import os
import pyclamd


from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)


class clamdService(Service):
    """
    Scan files for known viruses using clamd (ClamAv)..

    It can scan using either the unix scoket(on local host) or the TCP port (on either local or remote host)

    """

    name = "clamd"
    version = '0.0.3'
    #type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    description = "Scan files for known viruses using clamd (ClamAv)."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.clamdServiceConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config


    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.clamdServiceConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        data = {'clamd_sock_path': config['clamd_sock_path'][0],
                'clamd_host_name': config['clamd_host_name'][0],
                'clamd_host_port': config['clamd_host_port'][0],
                'clamd_force_reload': config['clamd_force_reload'][0]}
        return forms.clamdServiceConfigForm(data)

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.clamdServiceConfigForm(initial=config),
                                 'config_error': None})
        form = forms.clamdServiceConfigForm()
        return form, html

#   This will have to move into a place where validation needs to happen
#    @classmethod
#    def _validate(self, config):
#        clamd_sock_path = str(config['clamd_sock_path'])
#        clamd_host_name = str(config['clamd_host_name'])
#        clamd_host_port = int(config['clamd_host_port'])
#        if not clamd_sock_path and (not clamd_host_name or not clamd_host_port):
#            raise ServiceConfigError("Must specify clamd Unix socket path or IP and port.")


    def run(self, obj, config):
        clamd_sock_path = str(config['clamd_sock_path'])
        clamd_host_name = str(config['clamd_host_name'])
        clamd_host_port = int(config['clamd_host_port'])
        clamd_force_reload = config['clamd_force_reload'])

        try:
            self._debug('Attempting Unix socket connection to clamd')
            cd = pyclamd.ClamdUnixSocket(clamd_sock_path)
            result = cd.ping()
        except pyclamd.ConnectionError: 
            try:
                self._debug('Attempting Network connection to clamd')
                cd = pyclamd.ClamdNetworkSocket(clamd_host_name, clamd_host_port)
                result = cd.ping()
            except pyclamd.ConnectionError: 
                logger.error("clamd: Can\'t connect to Clamd\'s network socket.")
                self._error("clamd: Can\'t connect to Clamd\'s network socket.")
                return

        if clamd_force_reload:
            self._debug(cd.reload())
        cd_version = cd.version()
        self._debug(cd_version)
        try:
            output = cd.scan_stream(obj.filedata.read())
        except pyclamd.BufferTooLongError:
                logger.error("clamd: BufferTooLongError.")
                self._error("clamd: BufferTooLongError.")
                return
        except pyclamd.ConnectionError:
                logger.error("clamd: Can\'t connect to Clamd\'s socket.")
                self._error("clamd: Can\'t connect to Clamd\'s  socket.")
                return

        self._debug(output)
        if output: 
            out = output['stream']
            self._add_result('clamd',out[1], {'Status': out[0]})
        else:
            self._add_result('clamd','None' , {'Status': 'NOT FOUND'})

