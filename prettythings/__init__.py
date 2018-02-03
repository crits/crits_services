from crits.services.core import Service

class PrettyThings(Service):
    """
    Mockup for PrettyThings.
    """

    name = "PrettyThings"
    version = '0.0.1'
    template = None
    description = "Pretty Things for wonderful people."
    supported_types = []
    compatability_mode = True

    @staticmethod
    def parse_config(config):
        pass

    @staticmethod
    def get_config(existing_config):
        return {}

    @staticmethod
    def get_config_details(config):
        return {}

    @classmethod
    def generate_config_form(self, config):
        pass

    def run(self, obj, config):
        pass
