import binascii
import logging
import os.path
import yara

from hashlib import md5
from django.conf import settings

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError
from crits.core.class_mapper import class_from_value

logger = logging.getLogger(__name__)


class YaraService(Service):
    """
    Scan a file using Yara signatures.
    """

    name = "yara"
    version = '2.0.1'
    distributed = True
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    required_fields = ['md5']
    default_config = [
        ServiceConfigOption('sigdir',
                            ServiceConfigOption.STRING,
                            description=
    "A base directory where all the signature files exist. It is prepended to "
    "each sigfile to determine the complete path to the signature file.",
                            private=True),
        ServiceConfigOption('sigfiles',
                            ServiceConfigOption.LIST,
                            description=
    "A list of signature files. If `sigdir` is defined, each "
    "sigfile should relative to this directory; otherwise it should be an "
    "absolute path. Do not put quotes around file names.",
                            required=True),
        ServiceConfigOption('distribution_url',
                            ServiceConfigOption.STRING,
                            description=
    "URL to use if distributing to multiple workers. "
    "Leave empty to run locally.",
                            private=True),
        ServiceConfigOption('distribution_exchange',
                            ServiceConfigOption.STRING,
                            description= "Exchange to use for distribution.",
                            default='my_exchange',
                            private=True),
        ServiceConfigOption('distribution_routing_key',
                            ServiceConfigOption.STRING,
                            description= "Routing key to use for distribution.",
                            default='file.crits',
                            private=True),
    ]

    @staticmethod
    def validate(config):
        #Try to compile the rules files.
        YaraService._compile_rules(config['sigdir'], config['sigfiles'])

    @staticmethod
    def _compile_rules(sigdir, sigfiles):
        if not sigfiles:
            raise ServiceConfigError("No signature files specified.")
        logger.debug("Sigdir: %s" % sigdir)
        sigsets = []
        for sigfile in sigfiles:
            sigfile = sigfile.strip()
            logger.debug("Sigfile: %s" % sigfile)
            if sigdir:
                abspath = os.path.abspath(os.path.join(sigdir, sigfile))
            else:
                abspath = sigfile
            logger.debug("Full path to file file: %s" % abspath)
            filename = os.path.basename(abspath)
            version = sigfile.split('.')[0]
            try:
                with open(abspath, "rt") as f:
                    data = f.read()
            except:
                logger.exception("File cannot be opened: %s" % abspath)
                raise
            sig_md5 = md5(data).hexdigest()
            try:
                rules = yara.compile(source=data)
            except yara.SyntaxError:
                message = "Not a valid yara rules file: %s" % abspath
                logger.exception(message)
                raise ServiceConfigError(message)
            sigsets.append({'name': filename,
                            'md5': sig_md5,
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
            self.sigsets = self._compile_rules(self.config['sigdir'],
                                               self.config['sigfiles'])
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
