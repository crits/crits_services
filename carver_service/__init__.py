import hashlib

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from . import forms

DEFAULT_START = 0
DEFAULT_END = 0

class CarverService(Service):
    name = "carver"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Carve a chunk out of a sample."

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        data = {'start': config['start'][0], 'end': config['end'][0]}
        return forms.CarverRunForm(data)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.CarverRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def scan(self, obj, config):
        start_offset = config['start']
        end_offset = config['end']
        # Start must be 0 or higher. If end is greater than zero it must
        # also be greater than start_offset.
        if start_offset < 0 or (end_offset > 0 and start_offset > end_offset):
            self._error("Invalid offsets.")
            return

        data = obj.filedata.read()[start_offset:end_offset]
        if not data:
            self._error("No data.")
        else:
            self._add_file(data, filename=hashlib.md5(data).hexdigest(), log_msg="Carved file with MD5: {0}", relationship="Contains")
        return
