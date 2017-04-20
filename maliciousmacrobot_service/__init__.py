from mmbot import MaliciousMacroBot
import tempfile

from crits.services.core import Service, ServiceConfigError
from django.template.loader import render_to_string
from . import forms
from crits.samples.handlers import handle_file

class MMBotService(Service):
    """
    This service runs the Malicious Macro Bot Project created by Evan Gaustad.
    """

    name = 'mmbot'
    version = '1.0.0'
    supported_types = ['Sample']
    description = "Takes a sample with a macro and run it against your define model/vocab set. Service uses Malicious Macro Bot Project created by Evan Gaustad"

    @staticmethod
    def parse_config(config):
        errors = []
        if not config['model']:
            errors.append("Path to modeldata.pickle/vocab.txt is required.")
        if errors:
            raise ServiceConfigError(errors)

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.MMBotConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                'form': forms.MMBotConfigForm(initial=config),
                                'config_error': None})
        form = forms.MMBotConfigForm
        return form, html

    @property
    def model(self):
        return self.config.get('model')

    def run(self, obj, config):
        mmb = MaliciousMacroBot()
        mmb.mmb_init_model()
        mmb.set_model_paths(benign_path=None, malicious_path=None, model_path=self.model)
        f = tempfile.NamedTemporaryFile()
        f.write(obj.filedata.read())
        result = mmb.mmb_predict(f.name, datatype='filepath')
        f.close()
        json = mmb.mmb_prediction_to_json(result)[0]
        for k,v in json.iteritems():
            self._add_result("Prediction", k, {"value": v})
        
         
        
