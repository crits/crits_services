from crits.services.core import Service, ServiceConfigError

from django.template.loader import render_to_string

from . import forms


class ThreatExchange(Service):
    """
    Mockup for ThreatExchange.
    """

    name = "ThreatExchaFnge"
    version = '0.0.2'
    template = None
    description = "Share data via Facebook's ThreatExchange."
    supported_types = []
    compatability_mode = True

    @staticmethod
    def parse_config(config):
        app_id = config.get('app_id', None)
        app_secret = config.get('app_secret', None)
        if not app_id or not app_secret:
            raise ServiceConfigError("Must specify an App ID and App Secret.")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.ThreatExchangeConfigForm().fields
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
        fields = forms.ThreatExchangeConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.ThreatExchangeConfigForm(
                                     initial=config),
                                 'config_error': None})
        form = forms.ThreatExchangeConfigForm
        return form, html

    def run(self, obj, config):
        pass
