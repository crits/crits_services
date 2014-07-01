import binascii
import logging
import os.path
import yara

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError
from crits.core.class_mapper import class_from_value
from crits.core.user import CRITsUser
from crits.core.crits_mongoengine import AnalysisConfig

from . import forms

logger = logging.getLogger(__name__)


class YaraService(Service):
    """
    Scan a file using Yara signatures.
    """

    name = "yara"
    version = '2.0.1'
    distributed = True
    supported_types = ['Sample']
    required_fields = ['md5']
    description = "Scan a file using Yara signatures."

    @staticmethod
    def parse_config(config):
        # When editing a config we are given a string.
        # When validating an existing config it will be a list.
        # Convert it to a list of strings.
        sigfiles = config.get('sigfiles', [])
        if isinstance(sigfiles, basestring):
            config['sigfiles'] = [sigfile for sigfile in sigfiles.split('\r\n')]
        # This will raise ServiceConfigError
        YaraService._compile_rules(config['sigdir'], config['sigfiles'])

    @staticmethod
    def get_config(existing_config):
        if existing_config:
            return existing_config

        # Generate default config from form and initial values.
        config = {}
        fields = forms.YaraConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial
        return config

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Convert sigfiles to newline separated strings
        display_config['Signature Files'] = '\r\n'.join(config['sigfiles'])

        # Rename keys so they render nice.
        display_config['Signature Directory'] = config['sigdir']
        display_config['Distribution URL'] = config['distribution_url']
        display_config['Exchange'] = config['exchange']
        display_config['Routing Key'] = config['routing_key']
        return display_config

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        config['sigfiles'] = '\r\n'.join(config['sigfiles'])
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.YaraConfigForm(initial=config),
                                 'config_error': None})
        form = forms.YaraConfigForm
        return form, html

    @staticmethod
    def save_runtime_config(config):
        if config['distribution_url']:
            del config['api_key']
        del config['sigdir']

    @staticmethod
    def _get_api_keys(config, analyst):
        if config.get('distribution_url', ''):
            user = CRITsUser.objects(username=analyst).only('api_keys').first()
            if not user:
                return [] # XXX: Raise exception?

            api_keys = [(k.api_key, k.name) for k in user.api_keys]
            if not api_keys: # XXX: and distributed
                return [] # XXX: Raise exception?
        else:
            api_keys = []

        return api_keys

    @staticmethod
    def validate_runtime(config, db_config):
        # To run, this service _MUST_ have sigfiles and if distribution_url
        # is set it must have api_key.
        if 'sigfiles' not in config:
            raise ServiceConfigError("Need sigfiles to run.")

        if db_config['distribution_url'] and 'api_key' not in config:
            raise ServiceConfigError("Need API key to run.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        api_keys = YaraService._get_api_keys(config, analyst)
        if api_keys:
            # The api_key is a list with only one element.
            config['api_key'] = config['api_key'][0]

        sigfiles = YaraService._tuplize_sigfiles(config['sigfiles'])

        form = forms.YaraRunForm(sigfiles=sigfiles,
                                 api_keys=api_keys,
                                 data=config)
        return form

    @staticmethod
    def _tuplize_sigfiles(sigfiles):
        return [(sig, sig) for sig in sigfiles]

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        api_keys = YaraService._get_api_keys(config, analyst)

        sigfiles = YaraService._tuplize_sigfiles(config['sigfiles'])

        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.YaraRunForm(sigfiles=sigfiles,
                                                           api_keys=api_keys),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    @staticmethod
    def _compile_rules(sigdir, sigfiles):
        if not sigfiles or not sigdir:
            raise ServiceConfigError("No signature files specified.")
        sigsets = []
        for sigfile in sigfiles:
            sigfile = os.path.abspath(os.path.join(sigdir, sigfile.strip()))
            logger.debug("Full path to file file: %s" % sigfile)
            filename = os.path.basename(sigfile)
            try:
                with open(sigfile, "rt") as f:
                    data = f.read()
            except Exception as e:
                logger.exception("File cannot be opened: %s" % sigfile)
                raise ServiceConfigError(str(e))
            try:
                rules = yara.compile(source=data)
            except yara.SyntaxError:
                message = "Not a valid yara rules file: %s" % sigfile
                logger.exception(message)
                raise ServiceConfigError(message)
            sigsets.append({'name': filename, 'rules': rules})

        logger.debug(str(sigsets))
        return sigsets

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    def scan(self, obj, config):
        logger.debug("Scanning...")
        if obj.filedata.grid_id == None:
            self._info("No data to scan, skipping")
            return

        if config['distribution_url']:
            msg = {
                'type': 'fileref',
                'source': {
                    'type': 'crits',
                    'data': settings.INSTANCE_URL
                },
                'destination': {
                    'type': 'crits_api',
                    'data': settings.INSTANCE_URL
                },
                'config': {
                    'sigdir': config['sigdir'],
                    'sigfiles': config['sigfiles']
                },
                'analysis_meta': {
                     'md5': obj.md5,
                     'object_type': obj._meta['crits_type'],
                     'object_id': str(obj.id),
                     'analysis_id': self.current_task.task_id,
                     'start_date': self.current_task.start_date,
                     'username': self.current_task.username
                }
            }

            exch = config['exchange']
            routing_key = config['routing_key']
            try:
                from crits.services.connector import *
                conn = Connector(connector="amqp",
                                 uri=config['distribution_url'])
                conn.send_msg(msg, exch, routing_key)
                conn.release()
            except Exception as e:
                self._error("Distribution error: %s" % e)
                return
            self._info("Submitted job to yara queue.")
        else:
            sigsets = self._compile_rules(config['sigdir'], config['sigfiles'])
            for sigset in sigsets:
                logger.debug("Signature set name: %s" % sigset['name'])
                self._info("Scanning with %s" % sigset['name'])
                matches = sigset['rules'].match(data=obj.filedata.read())
                for match in matches:
                    strings = {}
                    for s in match.strings:
                        s_name = s[1]
                        s_offset = s[0]
                        try:
                            s_data = s[2].decode('ascii')
                        except UnicodeError:
                            s_data = "Hex: " + binascii.hexlify(s[2])
                        s_key = "{0}-{1}".format(s_name, s_data)
                        if s_key in strings:
                            strings[s_key]['offset'].append(s_offset)
                        else:
                            strings[s_key] = {
                                'offset':       [s_offset],
                                'name':         s_name,
                                'data':         s_data,
                                }
                    string_list = []
                    for key in strings:
                        string_list.append(strings[key])
                    self._add_result(self.name, match.rule, {'strings': string_list})
            self.finalize()
