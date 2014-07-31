import logging
import json
import requests

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class PassiveTotalService(Service):
    """
    Check the PassiveTotal database to see if it contains this domain or IP

    This service reliess on a user's allowed searches within the PassiveTotal
    system which are earned through accurate domain/IP classifications

    Requires an API key available from passivetotal.org
    """

    name = "passivetotal_lookup"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = [ 'Domain', 'IP' ]
    required_fields = []
    default_config = [
        ServiceConfigOption('pt_api_key',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from PassiveTotal.",
                            required=True,
                            private=True),
        ServiceConfigOption('pt_query_url',
                            ServiceConfigOption.STRING,
                            default='https://www.passivetotal.org/api/passive',
                            required=True,
                            private=True),
    ]

    def _scan(self, context):
        apikey = self.config.get('pt_api_key', '')
        queryUrl = self.config.get('pt_query_url', '')

        if not apikey:
            self._error("PassiveTotal API key is invalid or blank")

        if context.crits_type == 'Domain':
            params = { 'value': context.domain_dict['domain'], 'apikey': apikey }
        elif context.crits_type == 'IP':
            params = { 'value': context.ip_dict['ip'], 'apikey': apikey }
        else:
            logger.error("PassiveTotal: Invalid type.")
            self._error("Invalid type.")
            return

        try:
            response = requests.post(queryUrl, params=params)
        except Exception as e:
            logger.error("PassiveTotal: network connection error (%s)" % e)
            self._error("Network connection error checking PassiveTotal (%s)" % e)
            return

        loaded = json.loads(response.content) # handling a valid response

        if not loaded['success']:
            logger.error("PassiveTotal: query error (%s)" % loaded['error'])
            self._error("PassiveTotal: query error (%s)" % loaded['error'])
            return

        if loaded['result_count'] == 0:
            return

        results = loaded['results']
        if context.crits_type == 'Domain':
            for resolve in results['resolutions']:
                stats = {
                    'value': results['focus'],
                    'first_seen': resolve['firstSeen'],
                    'last_seen': resolve['lastSeen'],
                    'source': ','.join(resolve['source']),
                    'as_name': resolve['as_name'],
                    'asn': resolve['asn'],
                    'country': resolve['country'],
                    'network': resolve['network']
                }
                self._add_result('Passive DNS Data', resolve['value'], stats)
        elif context.crits_type == 'IP':
            stats = {
                'as_name': results['as_name'],
                'asn': results['asn'],
                'country': results['country'],
                'firstSeen': results['firstSeen'],
                'lastSeen': results['lastSeen'],
                'network': results['network']
            }
            self._add_result('Metadata', results['focus'], stats)
            for resolve in results['resolutions']:
                stats = {
                    'firstSeen': resolve['firstSeen'],
                    'lastSeen': resolve['lastSeen'],
                    'source': ','.join(resolve['source']),
                    'whois': resolve.get('whois', {})
                }
                self._add_result('Passive DNS Data', resolve['value'], stats)
