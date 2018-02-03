from mmbot import MaliciousMacroBot

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
    description = "Runs Evan Gaustad Malicious Macro Bot Project against samples with macros." 
                   

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
   
    @staticmethod
    def valid_for(obj):
        # Only run on Office files
        if not (obj.is_office() or obj.mimetype.startswith('application/vnd.openxmlformats-officedocument')):
            raise ServiceConfigError("Not a valid Office file.")

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
        fc =(obj.filedata.read())
        result = mmb.mmb_predict(fc, datatype='filecontents')
        json = mmb.mmb_prediction_to_json(result)[0]
        for k,v in json.iteritems():
            if k == 'prediction':
                self._add_result("Prediction", v, {"name": k})
        for k,v in json.iteritems():
            if k != 'prediction': 
                self._add_result("Features", v, {"name": k})
        
         
        
