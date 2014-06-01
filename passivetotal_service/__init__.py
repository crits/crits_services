import logging
import json
import requests

from django.conf import settings

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class PassiveTotalService(Service):
	"""
	Check the PassiveTotal database to see if it contains this domain or IP
	
	This service relys on a user's allowed searches within the PassiveTotal system of which are earned through accurate domain/IP classifications
	
	Requires an API key available from passivetotal.org
	"""
	
	name = "passivetotal_lookup"
	version = '1.0.0'
	type_ = Service.TYPE_PDNS
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
							default='https://www.passivetotal.org/api/query/',
							required=True,
							private=True),
	]

	def _scan(self, context):
		
		headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
		apiKey = self.config.get('pt_api_key', '')
		queryUrl = self.config.get('pt_query_url', '')
		
		if not key:
			self._error("PassiveTotal API key is invalid or blank")
		
		if context.crits_type in [ 'Domain', 'IP' ]:
			params = json.dumps({ 'value': value, 'apiKey': self.__apiKey })
			
			try:
				response = requests.post( queryUrl, data=params, headers=headers, verify=False )
			except Exception as e:
				logger.error("PassiveTotal: network connection error (%s)" % e)
				self._error("Network connection error checking PassiveTotal (%s)" % e)
				return
			
			loaded = json.loads(response.content) # handling a valid response
			requestType = loaded['focusType']
			
			if len(loaded['errors']) > 0:
				logger.error("PassiveTotal: query error (%s)" % str(loaded['errors']) )
				self._error("PassiveTotal: query error (%s)" % str(loaded['errors']) )
				
			if loaded['resultCount'] == 0:
				return 
			
			for resolve in loaded['resolutions']:
				stats = {
					'resolve': resolve['value'],
					'first_seen': resolve['firstSeen'],
					'last_seen': resolve['lastSeen'],
					'source': resolve['source']
				}
				
				self._add_result('Passive DNS Data', loaded['focusPoint'], stats)
			
