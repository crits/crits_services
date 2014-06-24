# (c) 2014, Adam Polkosnik, <adam.polkosnik@ny.frb.org> || <apolkosnik@gmail.com>
# Permission is granted for inclusion/distribution by The MITRE Corporation.
# All rights reserved.
# Source code distributed pursuant to license agreement.


from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError
from codetective import get_type_of, show


DEFAULT_END = -1
DEFAULT_START = 0
DEFAULT_ANALYZE = False

class CodetectiveService(Service):
    """
    a tool to determine the crypto/encoding algorithm used according to traces of its representation
    """

    name = "codetective"
    version = '0.0.1'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('start_offset',
                            ServiceConfigOption.INT,
                            description="Start offset",
                            required=False,
                            private=False,
                            default=DEFAULT_START),

        ServiceConfigOption('end_offset',
                            ServiceConfigOption.INT,
                            description="End offset",
                            required=True,
                            private=False,
                            default=DEFAULT_END),

        ServiceConfigOption('analyze',
                            ServiceConfigOption.Boolean,
                            description="show more details whenever possible (expands shadow files fields,...)",
                            required=True,
                            private=False,
                            default=False),                            
        
    ]

    @staticmethod
    def valid_for(context):
        # Only run if there's data
        return context.has_data()

    def _doit(self, data, analyze):
        get_type_of(data, analyze)
        return results

    def _scan(self, context):
        start_offset = self.config.get("start_offset", DEFAULT_START)
        end_offset = self.config.get("end_offset", DEFAULT_END)
        analyze = self.config.get("analyze", DEFAULT_ANALYZE)
        output = self._doit(context.data[start_offset:end_offset], analyze )
        self._add_result('Codetective', "%.1f" % output, {'Value': output})
