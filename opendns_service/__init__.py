import logging
import json
import requests
from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)

class OpenDNSService(Service):
    """
    Request more information about an artifacts from OpenDNS
    """

    name = "opendns_investigate"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = [ 'Domain', 'IP' ]
    required_fields = []
    default_config = [
        ServiceConfigOption('Investigate_API_Token',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from OpenDNS.",
                            required=True,
                            private=True),
        ServiceConfigOption('Investigate_URI',
                            ServiceConfigOption.STRING,
                            default='https://investigate.api.opendns.com',
                            required=True,
                            private=True),
    ]

    def _scan(self, context):
        token = self.config.get('Investigate_API_Token', '')
        uri = self.config.get('Investigate_URI', '')
        headers = {'Authorization': 'Bearer ' + token}
        reqs = {}
        resps = {}
        scores = {u'-1': 'Bad', u'0': 'Unknown', u'1': 'Good'}

        if not token:
            self._error("A valid API token is required to use this service.")

        if context.crits_type == 'Domain':
            thing = context.domain_dict['domain']
            reqs["categorization"] = "/domains/categorization/" + context.domain_dict['domain'] + "?showLabels"
            reqs["score"] = "/domains/score/" + context.domain_dict['domain']
            reqs["recommendations"] = "/recommendations/name/" + context.domain_dict['domain'] + ".json"
            reqs["links"] = "/links/name/" + context.domain_dict['domain'] + ".json"
            reqs["security"] = "/security/name/" + context.domain_dict['domain'] + ".json"
            reqs["latest_tags"] = "/domains/" + context.domain_dict['domain'] + "/latest_tags"
            reqs["dnsdb"] = "/dnsdb/name/a/" + context.domain_dict['domain'] + ".json"

        elif context.crits_type == 'IP':
            thing = context.ip_dict['ip']
            reqs["dnsdb"] = "/dnsdb/ip/a/" + context.ip_dict['ip'] + ".json"
            reqs["latest_domains"] = "/ips/" + context.ip_dict['ip'] + "/latest_domains"

        else:
            logger.error("Unsupported type.")
            self._error("Unsupported type.")
            return

        try:
            for r in reqs.keys():
                resp = requests.get(uri + reqs[r], headers=headers)

                if resp.status_code == 204:
                    logger.error("No content status returned from request: %s" % (r))
                    self._error("No content status returned from request: %s" % (r))
                    resps[r] = "No content status returned from request: %s" % (r)
                elif resp.status_code != 200:
                    logger.error("Request: %s, error, %s" % (r, resp.reason))
                    self._error("Request: %s, error, %s" % (r, resp.reason))
                    resps[r] = "Request: %s, error, %s" % (r, resp.reason)
                else:
                    resps[r] = json.loads(resp.content)

        except Exception as e:
            logger.error("Network connection or HTTP request error (%s)" % e)
            self._error("Network connection or HTTP request error (%s)" % e)
            return

        for r in resps.keys():
            if r == 'categorization':
                self._add_result(r, thing, resps[r][thing])       
            elif r == 'score':
                self._add_result(r, thing, {'Score': scores[resps[r][thing]]}) 
            elif r == 'dnsdb':
                self._add_result(r, thing, resps[r]['features'])       
            elif r == 'security':
                self._add_result(r, thing, resps[r])
            elif r == 'latest_tags':
                for tag in resps[r]:
                    self._add_result(r, thing, tag)
            elif r == 'recommendations':
                self._add_result(r, thing, resps[r])
            elif r == 'links':
                self._add_result(r, thing, resps[r])
            elif r == 'latest_domains':
                for domain in resps[r]:
                    self._add_result(r, domain['name'], domain)

            else:
                self._add_result(r, thing, {str(type(resps[r])): str(resps[r])})  
                logger.error("Unsure how to handle %s" % (str(resps[r])))
                self._error("Unsure how to handle %s" % (str(resps[r])))
           
