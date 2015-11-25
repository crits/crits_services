import hashlib
import base64

from django.template.loader import render_to_string

from crits.samples.handlers import handle_file
from crits.services.core import Service, ServiceConfigError
from crits.vocabulary.relationships import RelationshipTypes

from . import forms

class CarverService(Service):
    name = "carver"
    version = '0.0.2'
    supported_types = ['Sample']
    description = "Carve a chunk out of a sample."

    @staticmethod
    def get_config(existing_config):
        # This service no longer uses config options, so blow away any existing
        # configs.
        return {}

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        if config:
            # The values are submitted as a list for some reason.
            data = {'start': config['start'][0], 'end': config['end'][0],
                     'ops': config['ops'][0], 'ops_parm': config['ops_parm'][0]
                       }
        else:
            data = {}
            fields = forms.CarverRunForm().fields
            for name, field in fields.iteritems():
                data[name] = field.initial
        return forms.CarverRunForm(data)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.CarverRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def run(self, obj, config):
        start_offset = config['start']
        end_offset = config['end']
        ops = config['ops']
        try:
            if config['ops_parm']:
                parm_sign=str(config['ops_parm'])[0]
                if parm_sign not in ('+', '-'):
                    ops_parm = int(str(config['ops_parm']), 16)
                    parm_sign = '+'
                else:
                    ops_parm = int(str(config['ops_parm'])[1:], 16)
                if ops_parm > 0xff:
                    ops_parm = 0xff
                if ops_parm < 0x00:
                    ops_parm = 0x00
            else:
                ops_parm = 0x00
        except Exception as exc:
            self._error("Error: %s" % exc)
        # Start must be 0 or higher. If end is greater than zero it must
        # also be greater than start_offset.
        if start_offset < 0 or (end_offset > 0 and start_offset > end_offset):
            self._error("Invalid offsets.")
            return

        data = obj.filedata.read()[start_offset:end_offset]
        if not data:
            self._error("No data.")
        else:
            if ops == 'B64D':
                try:
                    data=base64.decode(data)
                except Exception as exc:
                    self._error("Error: %s" % exc)
            elif ops == 'XORB':
                if ops_parm > 0:
                    for k in range(len(data)):
                        data[k] ^= ops_parm
            elif ops == 'ROLB':
               if parm_sign == '+':
                    for k in range(len(data)):
                        val = data[k]
                        max_bits = 8
                        ror = lambda val, ops_parm, max_bits: ((val & (2**max_bits-1)) >> ops_parm%max_bits) | (val << (max_bits-(ops_parm%max_bits)) & (2**max_bits-1))
                        data[k] = ror
                else:
                    for k in range(len(data)):
                        val = data[k]
                        max_bits = 8
                        rol = lambda val, ops_parm, max_bits: (val << ops_parm%max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(ops_parm%max_bits)))
                        data[k] = rol
            elif ops == 'SHLB':
               if parm_sign == '+':
                    for k in range(len(data)):
                        data[k] >>= ops_parm
                else:
                    for k in range(len(data)):
                        data[k] <<= ops_parm
            elif ops == 'ADDB':
                if parm_sign == '+':
                    for k in range(len(data)):
                        data[k] += ops_parm
                else:
                    for k in range(len(data)):
                        data[k] -= ops_parm
            filename = hashlib.md5(data).hexdigest()
            handle_file(filename, data, obj.source,
                        related_id=str(obj.id),
                        campaign=obj.campaign,
                        method=self.name,
                        relationship=RelationshipTypes.CONTAINS,
                        user=self.current_task.username)
            # Filename is just the md5 of the data...
            self._add_result("file_added", filename, {'md5': filename})
        return
