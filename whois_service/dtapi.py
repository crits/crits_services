"""
NOTE: This file was provided by Mark Kendrick at DomainTools to make our lives
easier when using their API. Thanks Mark!

In the interest of making it work better with CRITs I modified it. It relied
upon a global apiconfig variable and other things. It now exposes a class
that must be instiated and configured.

I also removed the command line portion of it.
"""

"""
Interface and command line utility for the DomainTools.com API.
Learn more at domaintools.com/api/

Requires:
    requests
    unicodecsv (if you use the command line utility)

Example Usage:
    import dtapi

    # Sample queries require no authentication
    parsed = dtapi.whois_parsed('domaintools.com')
    org = parsed.json()['response']['parsed_whois']['contact']['registrant']['org']
    print(org)

    revwho = dtapi.reverse_whois('memberservices@domaintools.com')
    for domain in dtapi.domainlist_reversewhois(revwho):
        print(domain)

    # Configure the module with your API credentials
    dtapi.configure('your_api_username','your_api_key')
    whois = dtapi.whois('google.com')

Command Line:
    python dtapi.py --help
    python dtapi.py -p whois -f text domaintools.com
    python dtapi.py -u api_username -k api_key -p whois -f text domaintools.net reversewhois.com dailychanges.com
    python dtapi.py -p reversewhois -f list memberservices@domaintools.com
    cat list_of_domains.csv | python dtapi.py -u api_username -k api_key --nossl -p parsed -f csv -

License:
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Copyright (c) 2015 DomainTools, LLC
"""

from datetime import datetime
import hmac
import hashlib
import re
import json
import itertools
from collections import OrderedDict
import requests

# Exceptions
class DTError(Exception):
    """Base class for exceptions in this module."""
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
    def __str__(self):
        return '{0.code}: {0.msg}'.format(self)

class CannotParseError(DTError):
    pass

class BadRequestError(DTError):
    pass

class NotAuthorizedError(DTError):
    pass

class ForbiddenError(DTError):
    pass

class NotFoundError(DTError):
    pass

class ServerError(DTError):
    pass

class UnavailableError(DTError):
    pass

class UnexpectedError(DTError):
    pass

class dtapi(object):
    def __init__(self, username, key, *args, **kwargs):
        self.config = {
            'username': str(username),
            'key': str(key),
            'host': 'https://api.domaintools.com',
            'dataformat': 'json',
        }

    def apiquery(self, product_url, params={}):
        """Make an API query and return Requests response object."""
        requesturl = self.config['host'] + product_url
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        signature = hmac.new(self.config['key'],
                             ''.join([self.config['username'], timestamp, product_url]),
                             digestmod=hashlib.sha1).hexdigest()
        params['timestamp'] = timestamp
        params['signature'] = signature
        params['api_username'] = self.config['username']
        if 'format' not in params.keys():
            params['format'] = self.config['dataformat']
        req = requests.get(requesturl, params=params)
        if req.status_code != requests.codes.ok:
            try:
                json_response = req.json()
                self.raise_best_exception(json_response)
            except KeyError:
                raise UnexpectedError(req.status_code, req.text)
        return req

    def domain_profile(self, domain):
        """Get basic info and stats on a domain name."""
        return self.apiquery('/v1/{}'.format(domain))

    def whois(self, domain_or_ip):
        """Get current (cached) Whois lookup on a domain name or IP address."""
        return self.apiquery('/v1/{}/whois/'.format(domain_or_ip))

    def whois_live(self, domain):
        """Get live Whois lookup on a domain name."""
        return self.apiquery('/v1/{}/whois/live/'.format(domain))

    def whois_parsed(self, domain):
        """Get current (cached) parsed Whois lookup on a domain name."""
        return self.apiquery('/v1/{}/whois/parsed/'.format(domain))

    def whois_parsed_live(self, domain):
        """Get live parsed Whois lookup on a domain name."""
        return self.apiquery('/v1/{}/whois/parsed/live/'.format(domain))

    def reverse_ip(self, domain_or_ip, limit=None):
        """Find domains sharing the same web host."""
        params = {}
        if limit:
            params = {'limit':limit}
        if re.search('^(\d{1,3}\.){3}(\d{1,3})$',domain_or_ip):
            uri = '/v1/{}/host-domains/'
        else:
            uri = '/v1/{}/reverse-ip/'
        return self.apiquery(uri.format(domain_or_ip), params)

    def reverse_ns(self, nameserver, limit=None):
        """Find domains that share the same name server."""
        params = {}
        if limit:
            params = {'limit':limit}
        return self.apiquery('/v1/{}/name-server-domains/'.format(nameserver), params)

    def whois_history(self, domain):
        """Get Whois history on a domain."""
        return self.apiquery('/v1/{}/whois/history/'.format(domain))

    def hosting_history(self, domain):
        """Get ns, ip and registrar history on a domain."""
        return self.apiquery('/v1/{}/hosting-history/'.format(domain))

    def reverse_whois(self, terms, exclude='', scope='current', mode='purchase'):
        """Find related domains by terms in their Whois records."""
        params = {'terms':terms, 'exclude':exclude,'scope':scope, 'mode':mode}
        return self.apiquery('/v1/reverse-whois/', params=params)

    def registrant_alert(self, terms, exclude='', days_back=None, limit=None):
        """Newly-discovered domains with keywords in their Whois records."""
        params = {'query':terms, 'exclude':exclude}
        if days_back:
            params['days_back'] = days_back
        if limit:
            params['limit'] = limit
        return self.apiquery('/v1/registrant-alert/', params=params)

    def brand_monitor(self, terms, exclude='', days_back=None, domain_status=None):
        """Newly-discovered domains with keywords in the domain name."""
        params = {'query':terms, 'exclude':exclude}
        if days_back:
            params['days_back'] = days_back
        if domain_status:
            params['domain_status'] = domain_status
        return self.apiquery('/v1/mark-alert/', params=params)

    def ns_monitor(self, nameserver, days_back=None, page=1):
        """Domains added or removed from a name server."""
        params = {'query':nameserver, 'page':page}
        if days_back:
            params['days_back'] = days_back
        return self.apiquery('/v1/name-server-monitor/', params=params)

    def ip_monitor(self, ip_address, days_back=None, page=1):
        """Domains added or removed from an IP address."""
        params = {'query':ip_address, 'page':page}
        if days_back:
            params['days_back'] = days_back
        return self.apiquery('/v1/ip-monitor/', params=params)

    def domain_search(self, terms, page=1, exclude='', max_length=25, min_length=1, has_hyphen='true',
                      has_number='true', active_only='false', deleted_only='false', anchor_left='false',
                      anchor_right='false'):
        """Find domains that contain one or more search terms."""
        params = {'query':terms,
                  'page':page,
                  'exclude_query':exclude,
                  'max_length':max_length,
                  'min_legnth':min_length,
                  'has_hyphen':has_hyphen,
                  'has_number':has_number,
                  'active_only':active_only,
                  'deleted_only':deleted_only,
                  'anchor_left':anchor_left,
                  'anchor_right':anchor_right}
        return self.apiquery('/v2/domain-search/', params=params)

    def domain_suggestions(self, query):
        """Find similar domains to a search query."""
        params = {'query':query}
        return self.apiquery('/v1/domain-suggestions/', params=params)

    def raise_best_exception(self, json_response):
        """Raises the best exception for a json response."""
        exceptions = {
                206: CannotParseError,
                400: BadRequestError,
                401: NotAuthorizedError,
                403: ForbiddenError,
                404: NotFoundError,
                500: ServerError,
                503: UnavailableError,
        }
        try:
            err = json_response['response']['error']
            raise exceptions[err['code']](err['code'],err['message'])
        except IndexError:
            raise UnexpectedError('','Unexpected error.')

    # Helper functions for various data access needs
    def flatten_parsed_whois(self, response):
        data = response.json()
        """Flatten a parsed Whois result into a single-level dictionary."""
        try:
            w = data['response']['parsed_whois']
        except KeyError:
            return {}
        flat = OrderedDict()
        flat['domain'] =                         w['domain']
        flat['created_date'] =                   w['created_date']
        flat['updated_date'] =                   w['updated_date']
        flat['expired_date'] =                   w['expired_date']
        flat['statuses'] =                       ' | '.join(w['statuses'])
        flat['name_servers'] =                   ' | '.join(w['name_servers'])
        flat['registrar_name'] =                 w['registrar']['name']
        flat['registrar_abuse_contact_phone'] =  w['registrar']['abuse_contact_phone']
        flat['registrar_abuse_contact_email'] =  w['registrar']['abuse_contact_email']
        flat['registrar_iana_id'] =              w['registrar']['iana_id']
        flat['registrar_url'] =                  w['registrar']['url']
        flat['registrar_whois_server'] =         w['registrar']['whois_server']
        flat['registrant_name'] =                w['contacts']['registrant']['name']
        flat['registrant_email'] =               w['contacts']['registrant']['email']
        flat['registrant_org'] =                 w['contacts']['registrant']['org']
        flat['registrant_street'] =              ' '.join(w['contacts']['registrant']['street'])
        flat['registrant_city'] =                w['contacts']['registrant']['city']
        flat['registrant_state'] =               w['contacts']['registrant']['state']
        flat['registrant_postal'] =              w['contacts']['registrant']['postal']
        flat['registrant_country'] =             w['contacts']['registrant']['country']
        flat['registrant_phone'] =               w['contacts']['registrant']['phone']
        flat['registrant_fax'] =                 w['contacts']['registrant']['fax']
        flat['admin_name'] =                     w['contacts']['admin']['name']
        flat['admin_email'] =                    w['contacts']['admin']['email']
        flat['admin_org'] =                      w['contacts']['admin']['org']
        flat['admin_street'] =                   ' '.join(w['contacts']['admin']['street'])
        flat['admin_city'] =                     w['contacts']['admin']['city']
        flat['admin_state'] =                    w['contacts']['admin']['state']
        flat['admin_postal'] =                   w['contacts']['admin']['postal']
        flat['admin_country'] =                  w['contacts']['admin']['country']
        flat['admin_phone'] =                    w['contacts']['admin']['phone']
        flat['admin_fax'] =                      w['contacts']['admin']['fax']
        flat['tech_name'] =                      w['contacts']['tech']['name']
        flat['tech_email'] =                     w['contacts']['tech']['email']
        flat['tech_org'] =                       w['contacts']['tech']['org']
        flat['tech_street'] =                    ' '.join(w['contacts']['tech']['street'])
        flat['tech_city'] =                      w['contacts']['tech']['city']
        flat['tech_state'] =                     w['contacts']['tech']['state']
        flat['tech_postal'] =                    w['contacts']['tech']['postal']
        flat['tech_country'] =                   w['contacts']['tech']['country']
        flat['tech_phone'] =                     w['contacts']['tech']['phone']
        flat['tech_fax'] =                       w['contacts']['tech']['fax']
        flat['billing_name'] =                   w['contacts']['billing']['name']
        flat['billing_email'] =                  w['contacts']['billing']['email']
        flat['billing_org'] =                    w['contacts']['billing']['org']
        flat['billing_street'] =                 ' '.join(w['contacts']['billing']['street'])
        flat['billing_city'] =                   w['contacts']['billing']['city']
        flat['billing_state'] =                  w['contacts']['billing']['state']
        flat['billing_postal'] =                 w['contacts']['billing']['postal']
        flat['billing_country'] =                w['contacts']['billing']['country']
        flat['billing_phone'] =                  w['contacts']['billing']['phone']
        flat['billing_fax'] =                    w['contacts']['billing']['fax']
        return flat

    def recordlist_whoishistory(self, response):
        """Yield a simplified list of historical Whois records."""
        data = response.json()
        for record in data['response']['history']:
            emails = set(re.findall('[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}',record['record']))
            yield { 'date':  record['date'],
                    'registrant': record['whois'].get('registrant'),
                    'emails': ', '.join(emails),
                    'created': record.get('created'),
                   }

    def domainlist_reverseip(self, response):
        """Yields domains from a reverse IP response (generator)."""
        data = response.json()
        for ip in data['response']['ip_addresses']:
            for domain in ip['domain_names']:
                yield(domain.lower())

    def domainlist_reversens(self, response):
        """Yields domains from a reverse NS response (generator)."""
        data = response.json()
        for domain in itertools.chain(data['response']['primary_domains'], data['response']['primary_domains']):
            yield(domain.lower())

    def domainlist_reversewhois(self, response):
        """Yields domains from a reverse whois response (generator)."""
        data = response.json()
        for domain in data['response']['domains']:
            yield(domain.lower())

    def domainlist_regalert(self, response, match_type=''):
        """Yields domains from a regalert response (generator)."""
        data = response.json()
        for alert in data['response']['alerts']:
            if alert['match_type']==match_type or match_type=='':
                yield(alert['domain'].lower())

    def domainlist_brandmon(self, response, match_type=''):
        """Yields domains from a brandmon response (generator)."""
        data = response.json()
        for alert in data['response']['alerts']:
            if alert['status']==match_type or match_type=='':
                yield(alert['domain'].lower())
