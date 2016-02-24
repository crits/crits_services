from pytx import (
    access_token,
    ThreatDescriptor,
    ThreatIndicator,
    Malware,
    MalwareFamily
)

from pytx.errors import pytxFetchError

from django.template.loader import render_to_string
from django.template import RequestContext

from crits.services.handlers import get_config


def submit_query(request, type_, params=None):
    klass = None
    template = None
    if type_ == "Threat Descriptors":
        klass = ThreatDescriptor
        template = "tx_threat_descriptor.html"
    elif type_ == "Threat Indicators":
        klass = ThreatIndicator
        template = "tx_threat_indicator.html"
    elif type_ == "Malware Analyses":
        klass = Malware
        template = "tx_malware.html"
    elif type_ == "Malware Families":
        klass = MalwareFamily
        template = "tx_malware_family.html"
    else:
        return {'success': False,
                'message': "Invalid Type"}
    for k, v in params.iteritems():
        if len(params[k]) < 1 or params[k] == '':
            params[k] = None
    sc = get_config('ThreatExchange')
    access_token.access_token(app_id=sc['app_id'], app_secret=sc['app_secret'])
    try:
        results = klass.objects(full_response=True, fields=klass._fields, **params)
    except pytxFetchError, e:
        return {'success': False,
                'message': e.message['message']}
    data = results.get('data', None)
    html = ''
    if data:
        for d in data:
            html += render_to_string("tx_common.html",
                                     {
                                         'custom_template': template,
                                         'data': d,
                                     },
                                     RequestContext(request))
    return {'success': True,
            'html': html}
