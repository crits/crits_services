from crits.services.core import Service

class SnugglefishService(Service):
    """ Perform search on snugglefish indices. """

    name = "snugglefish_service"
    version = "0.3"
    type_ = Service.TYPE_CUSTOM
    supported_types = []
    default_config = []

    @classmethod
    def _validate(cls, config):
        pass

    def __init__(self, *args, **kwargs):
        super(SnugglefishService, self).__init__(*args, **kwargs)

    def _scan(self, context):
        pass
