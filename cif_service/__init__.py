import logging
import json
import requests
import re

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class CIFService(Service):
    """
    Check a CIF database to see if it contains this domain or IP

    Requires a CIF API key
    """

    name = "cif_lookup"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = [ 'Domain', 'IP' ]
    required_fields = []
    default_config = [
        ServiceConfigOption('cif_api_key',
                            ServiceConfigOption.STRING,
                            description="Required.",
                            required=True,
                            private=True),
        ServiceConfigOption('cif_query_url',
                            ServiceConfigOption.STRING,
                            default='https://cif.server/api?apikey=',
                            required=True,
                            private=True),
    ]

    def _scan(self, context):
        apikey = self.config.get('cif_api_key', '')
        queryUrl = self.config.get('cif_query_url', '')
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        if not apikey:
            self._error("CIF API key is invalid or blank")

        if context.crits_type == 'Domain':
          indicator = context.domain_dict['domain']
        elif context.crits_type == 'IP':
          indicator = context.ip_dict['ip']
        else:
            logger.error("CIF: Invalid type.")
            self._error("Invalid type.")
            return

        try:
            response = requests.get(queryUrl + apikey + "&q=" + indicator, headers=headers, verify=False)
        except Exception as e:
            logger.error("CIF: network connection error (%s)" % e)
            self._error("Network connection error checking CIF (%s)" % e)
            return

        # CIFs json output isnt great, need to work some magic
        loaded = [ json.loads(z) for z in re.split(r'[\r\n]+', response.content) ]

        for results in loaded:
          if results['assessment'] == 'search':
            continue
          else: 
            stats = {
              'relatedid_restriction': results['relatedid_restriction'],
              'purpose': results['purpose'],
              'asn': results['asn'],
              'rir': results['rir'],
              'alternativeid': results['alternativeid'],
              'cc': results['cc'],
              'detecttime': results['detecttime'],
              'address': results['address'],
              'alternativeid_restriction': results['alternativeid_restriction'],
              'id': results['id'],
              'guid': results['guid'],
              'severity': results['severity'],
              'assessment': results['assessment'],
              'rdata': results['rdata'],
              'description': results['description'],
              'asn_desc': results['asn_desc'],
              'relatedid': results['relatedid'],
              'reporttime': results['reporttime'],
              'confidence': results['confidence'],
              'restriction': results['restriction'],
              'prefix': results['prefix']
            }
            self._add_result('Enrichment Data', results['address'], stats)

