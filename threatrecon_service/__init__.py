import logging
import json
import requests

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class ThreatreconService(Service):
    """
    Check the Threatrecon database to see if it contains this domain or IP

    Requires an API key available from threatrecon.co
    """

    name = "threatrecon_lookup"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = [ 'Domain', 'IP' ]
    required_fields = []
    default_config = [
        ServiceConfigOption('tr_api_key',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from Threatrecon.",
                            required=True,
                            private=True),
        ServiceConfigOption('tr_query_url',
                            ServiceConfigOption.STRING,
                            default='https://api.threatrecon.co/api/v1/search',
                            required=True,
                            private=True),
    ]

    def _scan(self, context):
        apikey = self.config.get('tr_api_key', '')
        queryUrl = self.config.get('tr_query_url', '')

        if not apikey:
            self._error("Threatrecon API key is invalid or blank")

        if context.crits_type == 'Domain':
            params = { 'indicator': context.domain_dict['domain'], 'api_key': apikey }
        elif context.crits_type == 'IP':
            params = { 'indicator': context.ip_dict['ip'], 'api_key': apikey }
        else:
            logger.error("Threatrecon: Invalid type.")
            self._error("Invalid type.")
            return

        try:
            response = requests.post(queryUrl, params=params)
        except Exception as e:
            logger.error("Threatrecon: network connection error (%s)" % e)
            self._error("Network connection error checking Threatrecon (%s)" % e)
            return

        loaded = json.loads(response.content) # handling a valid response

        if loaded['ResponseCode'] == -1:
            logger.error("Threatrecon: query error (%s)" % loaded['Msg'])
            self._error("Threatrecon: query error (%s)" % loaded['Msg'])
            return

        if loaded['Results'] is None:
            return

        for results in loaded['Results']:
          stats = {
            'indicator': results['Indicator'],
            'attribution': results['Attribution'],
            'reference': results['Reference'],
            'confidence': results['Confidence'],
            'killchain': results['KillChain'],
            'id': results['Id'],
            'comment': results['Comment'],
            'processtype': results['ProcessType'],
            'source': results['Source'],
            'country': results['Country'],
            'rrname': results['Rrname'],
            'rrdata': results['Rdata'],
            'root_node': results['RootNode'],
            'first_seen': results['FirstSeen'],
            'last_seen': results['LastSeen'],
            'tags': results['Tags']
          }
          self._add_result('Enrichment Data', results['Indicator'], stats)
