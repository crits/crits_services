import binascii
import logging
import os.path
import yara

from hashlib import md5
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
        YaraService._compile_rules(config['sigfiles'])
        return config

    @staticmethod
    def get_config(existing_config):
        if existing_config:
            return existing_config

        config = { 'sigfiles': [],
                   'distribution_url': '',
                   'exchange': '',
                   'routing_key': '' }
        return config

    @staticmethod
    def get_config_details(config):
        # Convert sigfiles to newline separated strings
        config['sigfiles'] = '\r\n'.join(config['sigfiles'])

        # Rename keys so they render nice.
        config['Signature Files'] = config['sigfiles']
        config['Distribution URL'] = config['distribution_url']
        config['Exchange'] = config['exchange']
        config['Routing Key'] = config['routing_key']
        del config['sigfiles']
        del config['distribution_url']
        del config['exchange']
        del config['routing_key']
        return config

    @staticmethod
    def generate_config_form(name, config):
        # Convert sigfiles to newline separated strings
        config['sigfiles'] = '\r\n'.join(config['sigfiles'])
        html = render_to_string('services_config_form.html',
                                {'name': name,
                                 'form': forms.YaraConfigForm(initial=config),
                                 'config_error': None})
        form = forms.YaraConfigForm
        return form, html

    @staticmethod
    def generate_runtime_form(analyst, name, config, crits_type,
                              identifier):
        user = CRITsUser.objects(username=analyst).only('api_keys').first()
        if not user:
            return None, None # XXX: Raise an exception...
        choices = [(k.api_key, k.name) for k in user.api_keys]
        if not choices:
            return None, None # XXX: Raise an exception

        html = render_to_string('services_config_form.html',
                                {'name': name,
                                 'form': forms.YaraConfigForm(),
                                 'config_error': None})
        return None, html
        #fields['api_key'] = forms.ChoiceField(widget=forms.Select,
        #                                      choices=choices,
        #                                      required=False,
        #                                      help_text="API key to use.")

        #form = type("ServiceRunConfigForm",
        #            (forms.BaseForm,),
        #            {'base_fields': fields})
        #form_data = form(config)
        #html = render_to_string("services_run_form.html",
        #                        {'name': name,
        #                         'form': form_data,
        #                         'crits_type': crits_type,
        #                         'identifier': identifier})
        #return form, html
        return None, None

    @staticmethod
    def _compile_rules(sigfiles):
        if not sigfiles:
            raise ServiceConfigError("No signature files specified.")
        sigsets = []
        for sigfile in sigfiles:
            sigfile = sigfile.strip()
            logger.debug("Sigfile: %s" % sigfile)
            logger.debug("Full path to file file: %s" % sigfile)
            filename = os.path.basename(sigfile)
            version = sigfile.split('.')[0]
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
            sigsets.append({'name': filename,
                            'rules': rules,
                            'version': version})

        logger.debug(str(sigsets))
        return sigsets

    def _scan(self, obj):
        logger.debug("Scanning...")
        if obj.filedata.grid_id == None:
            self._info("No data to scan, skipping")
            return

        if self.config['distribution_url']:
            print self.config
            return
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
                    'sigfiles': self.config['sigfiles']
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

            exch = self.config['distribution_exchange']
            routing_key = self.config['distribution_routing_key']
            try:
                from crits.services.connector import *
                conn = Connector(connector="amqp",
                                 uri=self.config['distribution_url'])
                conn.send_msg(msg, exch, routing_key)
                conn.release()
            except Exception as e:
                self._error("Distribution error: %s" % e)
                return
            self._info("Submitted job to yara queue.")
        else:
            self.sigsets = self._compile_rules(self.config['sigfiles'])
            for sigset in self.sigsets:
                logger.debug("Signature set name: %s" % sigset['name'])
                self._info("Scanning with %s (%s)" % (sigset['name'], sigset['md5']))
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
