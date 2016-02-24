from pytx import (
    access_token,
    ThreatDescriptor,
    ThreatIndicator,
    Malware,
    MalwareFamily
)

from pytx.errors import pytxFetchError
from pytx.vocabulary import (
    ThreatDescriptor as td,
    Malware as m
)

from django.template.loader import render_to_string
from django.template import RequestContext

from crits.indicators.handlers import handle_indicator_ind
from crits.indicators.indicator import Indicator
from crits.samples.sample import Sample
from crits.services.handlers import get_config
from crits.vocabulary.indicators import (
    IndicatorCI,
    IndicatorThreatTypes,
    IndicatorTypes
)


def submit_query(request, type_, params=None):
    klass = None
    template = None
    if type_ == "Threat Descriptors":
        klass = ThreatDescriptor
        lookup = Indicator
        lookup_value = "value"
        ref_value = td.RAW_INDICATOR
        template = "tx_threat_descriptor.html"
    elif type_ == "Threat Indicators":
        klass = ThreatIndicator
        lookup = Indicator
        lookup_value = "value"
        ref_value = td.RAW_INDICATOR
        template = "tx_threat_indicator.html"
    elif type_ == "Malware Analyses":
        klass = Malware
        lookup = Sample
        lookup_value = "md5"
        ref_value = m.MD5
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
            exists = False
            if lookup.objects(**{lookup_value: d[ref_value]}).first() is not None:
                exists = True
            html += render_to_string("tx_common.html",
                                     {
                                         'custom_template': template,
                                         'data': d,
                                         'type': type_,
                                         'exists': exists,
                                     },
                                     RequestContext(request))
    return {'success': True,
            'html': html}

def build_ci(confidence):
    if confidence < 1:
        confidence = IndicatorCI.UNKNOWN
    elif confidence < 50:
        confidence = IndicatorCI.LOW
    elif confidence < 75:
        confidence = IndicatorCI.MEDIUM
    elif confidence <= 100:
        confidence = IndicatorCI.HIGH
    else:
        confidence = IndicatorCI.UNKNOWN
    return confidence

def import_object(request, type_, id_):
    if type_ == "Threat Descriptors":
        obj = ThreatDescriptor(id=id_)
        obj.details(
            fields=[f for f in ThreatDescriptor._default_fields if f not in
                    (td.PRIVACY_MEMBERS, td.SUBMITTER_COUNT, td.METADATA)]
        )
        itype = getattr(IndicatorTypes, obj.get(td.TYPE))
        ithreat_type = getattr(IndicatorThreatTypes, obj.get(td.THREAT_TYPE))
        results = handle_indicator_ind(
            obj.get(td.RAW_INDICATOR),
            "ThreatExchange",
            itype,
            ithreat_type,
            None,
            request.user.username,
            method="ThreatExchange Service",
            reference="id: %s, owner: %s" % (obj.get(td.ID),
                                             obj.get(td.OWNER)['name']),
            add_domain=True,
            add_relationship=True,
            confidence=build_ci(obj.get(td.CONFIDENCE)),
        )
        return results
    elif type_ == "Threat Indicators":
        obj = ThreatIndicator(id=id_)
    elif type_ == "Malware Analyses":
        obj = Malware(id=id_)
    elif type_ == "Malware Families":
        obj = MalwareFamily(id=id_)
    else:
        return {'success': False,
                'message': "Invalid Type"}
    return {'success': True}
