# (c) 2013, Adam Polkosnik, <adam.polkosnik@ny.frb.org>
# Permission is granted for inclusion/distribution by The MITRE Corporation.
# All rights reserved.
# Source code distributed pursuant to license agreement.

import array
import math

from crits.services.core import Service, ServiceConfigOption

DEFAULT_END = -1
DEFAULT_START = 0

class EntropycalcService(Service):
    """
    Calculate entropy over data.
    """

    name = "entropycalc"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Calculate entropy of a sample."
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
    ]

    @staticmethod
    def valid_for(obj):
        # Only run if there's data
        return not obj.filedata.grid_id == None

    def _calculate_entropy(self, data):

	entropy = 0.0
        if len(data) == 0:
            return entropy

        occurences = array.array('L', [0]*256)

        for x in data:
            occurences[ord(x)] += 1

        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x*math.log(p_x, 2)

        return entropy


    def _scan(self, obj):
        start_offset = self.config.get("start_offset", DEFAULT_START)
        end_offset = self.config.get("end_offset", DEFAULT_END)
	output = self._calculate_entropy(obj.filedata.read()[start_offset:end_offset])
        self._add_result('Entropy calculation', "%.1f" % output, {'Value': output})
