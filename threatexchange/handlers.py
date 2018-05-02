import urllib
from urlparse import (
    urlparse,
    parse_qsl
)

from pytx import (
    access_token,
    connection,
    Broker,
    Malware,
    MalwareFamily,
    ThreatDescriptor,
    ThreatExchangeMember,
    ThreatIndicator,
    ThreatPrivacyGroup,
)

from pytx.errors import pytxFetchError
from pytx.vocabulary import (
    Malware as m,
    MalwareAnalysisTypes,
    MalwareFamilies as mf,
    Precision,
    PrivacyType,
    ReviewStatus,
    Severity,
    ShareLevel,
    Status,
    ThreatDescriptor as td,
    ThreatIndicator as ti,
    ThreatPrivacyGroup as tpg,
    Types
)

from django.template.loader import render_to_string

from crits.config.config import CRITsConfig
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.backdoors.backdoor import Backdoor
from crits.indicators.handlers import handle_indicator_ind
from crits.indicators.indicator import Indicator
from crits.samples.handlers import handle_file
from crits.samples.sample import Sample
from crits.services.handlers import get_config
from crits.vocabulary.acls import IndicatorACL, SampleACL
from crits.vocabulary.indicators import (
    IndicatorCI,
    IndicatorThreatTypes,
    IndicatorAttackTypes,
    IndicatorTypes
)


def setup_access():
    sc = get_config('ThreatExchange')
    config = CRITsConfig.objects().first()
    access_token.access_token(app_id=sc['app_id'],
                              app_secret=sc['app_secret'])
    headers = None
    if len(sc['headers']) > 0:
        hlist = sc['headers'].split(',')
        headers = {}
        for h in hlist:
            tmp = h.split(':')
            if len(tmp) == 2:
                headers[tmp[0].strip()] = tmp[1].strip()
    proxies = {'http': config.http_proxy,
               'https': config.http_proxy}
    connection(headers=headers,
               proxies=proxies,
               verify=sc['verify'])
    return

def submit_query(request, url, type_, params=None):
    klass = None
    template = None
    setup_access()

    if url is not None and len(url) > 0:
        if url[-1] == "/":
            url = url + "?access_token=" + access_token.get_access_token()
        else:
            url = url + "&access_token=" + access_token.get_access_token()
        try:
            results = Broker.get(url)
        except pytxFetchError, e:
            return {'success': False,
                    'message': e.message['message']}
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
        ref_value = ti.INDICATOR
        template = "tx_threat_indicator.html"
    elif type_ == "Malware Analyses":
        klass = Malware
        lookup = Sample
        lookup_value = "md5"
        ref_value = m.MD5
        template = "tx_malware.html"
    elif type_ == "Malware Families":
        klass = MalwareFamily
        lookup = Backdoor
        lookup_value = "name,aliases"
        ref_value = mf.NAME
        template = "tx_malware_family.html"
    else:
        return {'success': False,
                'message': "Invalid Type"}
    if url is None:
        for k, v in params.iteritems():
            if len(params[k]) < 1 or params[k] == '':
                params[k] = None
        try:
            results = klass.objects(full_response=True, fields=klass._fields, **params)
        except pytxFetchError, e:
            return {'success': False,
                    'message': e.message['message']}
        except Exception, e:
            return {'success': False,
                    'message': str(e)}
    data = results.get('data', None)
    next_url = results.get('paging', {}).get('next', '')
    if len(next_url) > 0:
        params = dict(parse_qsl(urlparse(next_url).query, keep_blank_values=True))
        if 'access_token' in params:
            del params['access_token']
        next_url = next_url.split('?')[0] + "/?"+ urllib.urlencode(params)
    html = ''
    if data:
        for d in data:
            exists = False
            no_import = False
            objectid = None
            if d.get(ref_value):
                ld = {l:d[ref_value] for l in lookup_value.split(',')}
                tmp = lookup.objects(**ld).first()
                if tmp is not None:
                    exists = True
                    objectid = str(tmp.id)
            else:
                no_import = True
            html += render_to_string("tx_common.html",
                                     {
                                         'custom_template': template,
                                         'data': d,
                                         'type': type_,
                                         'exists': exists,
                                         'no_import': no_import,
                                         'objectid': objectid
                                     },
                                     request=request)
    return {'success': True,
            'html': html,
            'next_url': next_url}

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

def get_members():
    setup_access()
    try:
        members = ThreatExchangeMember.objects(full_response=True)
    except pytxFetchError, e:
        return {'success': False,
                'message': e.message.message}
    mlist = members.get('data', [])
    html = ''
    for member in mlist:
        html += render_to_string("tx_member.html",
                                    {
                                        'member': member
                                    })
    return {'success': True,
            'html': html}

def get_groups(manage=None):
    setup_access()
    owner_groups = ''
    member_groups = ''
    owner = ThreatPrivacyGroup.mine(role="owner")
    member = ThreatPrivacyGroup.mine(role="member")
    owner_template = "tx_group.html"
    member_template = "tx_group.html"
    if manage:
        owner_template = "tx_group_owner.html"
        member_template = "tx_group_member.html"
    for o in owner:
        members = o.get_members()
        o = o.to_dict()
        o['members'] = ",".join(x['name'] for x in members)
        owner_groups += render_to_string(owner_template,
                                         {
                                             'group': o
                                         })
    for mem in member:
        members = mem.get_members()
        mem = mem.to_dict()
        mem['members'] = ",".join(x['name'] for x in members)
        if mem.get(tpg.MEMBERS_CAN_USE) or manage:
            member_groups += render_to_string(member_template,
                                              {
                                                  'group': mem
                                              })
    if manage:
        return {'success': True,
                'owner': owner_groups,
                'member': member_groups}
    else:
        html = owner_groups + member_groups
        return {'success': True,
                'html': html}

def get_class_attribute_values(klass):
    result = []
    for k,v in klass.__dict__.iteritems():
        if not k.startswith('__') and not k.endswith('__'):
            result.append(v)
    return sorted(result)

def get_dropdowns():
    result = {}
    result['precision'] = get_class_attribute_values(Precision)
    result['privacy_type'] = get_class_attribute_values(PrivacyType)
    result['review_status'] = get_class_attribute_values(ReviewStatus)
    result['sample_type'] = get_class_attribute_values(MalwareAnalysisTypes)
    result['severity'] = get_class_attribute_values(Severity)
    result['share_level'] = get_class_attribute_values(ShareLevel)
    result['status'] = get_class_attribute_values(Status)
    result['types'] = get_class_attribute_values(Types)
    return result

def get_mapped_itype(type_):
    try:
        itype = getattr(IndicatorTypes, type_)
        return itype
    except AttributeError:
        pass
    if type_ == Types.IP_ADDRESS:
        # Really should validate that it's IPv4 and not IPv6
        return IndicatorTypes.IPV4_ADDRESS
    elif type_ == Types.IP_SUBNET:
        # Really should validate that it's IPv4 and not IPv6
        return IndicatorTypes.IPV4_SUBNET
    else:
        return None

def export_object(request, type_, id_, params):
    setup_access()
    if type_ == "Indicator":
        klass = ThreatDescriptor
    elif type_ == "Sample":
        klass = Malware
    else:
        return {'success': False,
                'message': "Invalid Type"}
    try:
        result = klass.new(params=params)
        note = result.get('id', None)
        add_releasability(type_, id_, "ThreatExchange", request.user.username)
        add_releasability_instance(type_, id_, "ThreatExchange",
                                   request.user.username, note=note)
        return {'success': True,
                'results': result}
    except pytxFetchError, e:
        return {'success': False,
                'message': e.message['message']}

def import_object(request, type_, id_):
    setup_access()
    user = request.user

    if type_ == "Threat Descriptors":
        obj = ThreatDescriptor(id=id_)
        obj.details(
            fields=[f for f in ThreatDescriptor._default_fields if f not in
                    (td.PRIVACY_MEMBERS, td.METADATA)]
        )
        itype = get_mapped_itype(obj.get(td.TYPE))
        tags = obj.get(td.TAGS)
        if itype is None:
            return {'success': False,
                    'message': "Descriptor type is not supported by CRITs"}

        if not user.has_access_to(IndicatorACL.WRITE):
            return {'success': False,
                    'message': "User does not have permission to add Indicators to CRITs"}

        ithreat_type = getattr(IndicatorThreatTypes, obj.get(td.THREAT_TYPE))
        results = handle_indicator_ind(
            obj.get(td.RAW_INDICATOR),
            "ThreatExchange",
            itype,
            IndicatorThreatTypes.UNKNOWN,
            IndicatorAttackTypes.UNKNOWN,
            request.user.username,
            method="ThreatExchange Service",
            reference="id: %s, owner: %s, share_level: %s" % (obj.get(td.ID),
                                                              obj.get(td.OWNER)['name'],
                                                              obj.get(td.SHARE_LEVEL)),
            add_domain=True,
            add_relationship=True,
            confidence=build_ci(obj.get(td.CONFIDENCE)),
            description=obj.get(td.DESCRIPTION),
            bucket_list=tags
        )
        return results
    elif type_ == "Malware Analyses":
        if not user.has_access_to(SampleACL.WRITE):
            return {'success': False,
                    'message': "User does not have permission to add Sample to CRITs"}
        obj = Malware(id=id_)
        obj.details(
            fields=[f for f in Malware._fields if f not in
                    (m.METADATA)]
        )
        filename = obj.get(m.MD5)
        tags = obj.get(m.TAGS)
        try:
            data = obj.rf
        except:
            data = None
        results = handle_file(
            filename,
            data,
            "ThreatExchange",
            method="ThreatExchange Service",
            reference="id: %s, share_level: %s" % (obj.get(td.ID),
                                                   obj.get(td.SHARE_LEVEL)),
            user=request.user.username,
            md5_digest = obj.get(m.MD5),
            sha1_digest = obj.get(m.SHA1),
            sha256_digest = obj.get(m.SHA256),
            size = obj.get(m.SAMPLE_SIZE),
            mimetype = obj.get(m.SAMPLE_TYPE),
            bucket_list=tags,
        )
        return {'success': True,
                'md5': results}
    else:
        return {'success': False,
                'message': "Invalid Type"}
    return {'success': True}

def add_edit_privacy_group(id_=None, name=None, description=None, members=None,
                           members_can_see=False, members_can_use=False):
    setup_access()
    results = {'success': False}
    if name is None:
        results['html'] = "Must provide a name!"
        return results
    if not members_can_see and members_can_use:
        results['html'] = "Members must be able to see if they are able to use!"
        return results
    d = {
        'name': name,
        'description': description,
        'members': members,
        'members_can_see': 1 if members_can_see else 0,
        'members_can_use': 1 if members_can_use else 0,
    }
    if id_ is not None:
        try:
            tpg = ThreatPrivacyGroup(id=id_)
            tpg.save(params=d)
            results['success'] = True
            results['html'] = "Success!"
        except Exception, e:
            results['html'] = e.message['message']
    else:
        try:
            ThreatPrivacyGroup.new(params=d)
            results['success'] = True
            results['html'] = "Success!"
        except Exception, e:
            results['html'] = e.message['message']
    return results
