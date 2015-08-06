import logging
import os
import pytz
import socket
import uuid

from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzutc
from io import BytesIO
from M2Crypto import BIO, SMIME, X509, Rand

import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages as tm
import libtaxii.messages_11 as tm11

from django.conf import settings

from cybox.common import String, DateTime, Hash, UnsignedLong
from cybox.common.object_properties import CustomProperties, Property
from cybox.core import Observable
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.artifact_object import Artifact, Base64Encoding, ZlibCompression
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailHeader, EmailMessage, Attachments
from cybox.objects.file_object import File

from stix.threat_actor import ThreatActor

from . import taxii
from . import formats
from .parsers import STIXParser, STIXParserException
from .object_mapper import make_cybox_object

from crits.events.event import Event
from crits.core.class_mapper import class_from_id, class_from_type
from crits.core.crits_mongoengine import Releasability
from crits.services.handlers import get_config

from crits.vocabulary.ips import IPTypes
from crits.vocabulary.relationships import RelationshipTypes

logger = logging.getLogger(__name__)

def execute_taxii_agent(hostname=None, https=None, feed=None, keyfile=None,
                        certfile=None, start=None, end=None, analyst=None,
                        method=None):
    ret = {
            'Certificate': [],
            'Domain': [],
            'Email': [],
            'Event': [],
            'Indicator': [],
            'IP': [],
            'PCAP': [],
            'RawData': [],
            'Sample': [],
            'successes': 0,
            'failures': [],
            'status': False,
            'reason': ''
          }

    sc = get_config('taxii_service')
    # XXX: Validate these!
    if not hostname:
        hostname = str(sc['hostname'])
    if not keyfile:
        keyfile = str(sc['keyfile'])
    if not certfile:
        certfile = str(sc['certfile'])
    if not feed:
        feed = str(sc['data_feed'])
    if https == None:
        https = sc['https']
    create_events = sc['create_events']


    # Last document's end time is our start time.
    if not start:
        last = taxii.Taxii.get_last()
        if last:
            start = pytz.utc.localize(last.end)

    # If start is a string, convert it to a datetime
    # YYYY-MM-DD HH:MM:SS
    if isinstance(start, str):
        start = pytz.utc.localize(parse(start, fuzzy=True))

    # store the current time as the time of this request
    runtime = datetime.now(tzutc())

    # End time is always now, unless specified.
    if not end:
        end = runtime

    # If end is a string, convert it to a datetime
    # YYYY-MM-DD HH:MM:SS
    if isinstance(end, str):
        end = pytz.utc.localize(parse(end, fuzzy=True))

    # compare start and end to make sure:
    # 1) start time is before end time
    # 2) end time is not in the future
    if (start != None and start >= end) and end > runtime:
        ret['reason'] = "Bad timestamp(s)"
        return ret

    client = tc.HttpClient()
    if https:
        client.setUseHttps(True)
        client.setAuthType(tc.HttpClient.AUTH_CERT)
        client.setAuthCredentials({'key_file': keyfile, 'cert_file': certfile})

    if settings.HTTP_PROXY:
        proxy = settings.HTTP_PROXY
        if not proxy.startswith('http://'):
            proxy = 'http://' + proxy
        client.setProxy(proxy)

    crits_taxii = taxii.Taxii()
    crits_taxii.runtime = runtime
    crits_taxii.end = end

    # Poll using 1.1 then 1.0 if that fails.
    poll_msg = tm11.PollRequest(message_id=tm11.generate_message_id(),
                                collection_name=feed,
                                poll_parameters=tm11.PollRequest.PollParameters(),
                                exclusive_begin_timestamp_label=start,
                                inclusive_end_timestamp_label=end)

    response = client.callTaxiiService2(hostname, '/poll/', t.VID_TAXII_XML_11,
                                        poll_msg.to_xml())
    taxii_msg = t.get_message_from_http_response(response, poll_msg.message_id)

    if response.getcode() != 200 or taxii_msg.message_type == tm11.MSG_STATUS_MESSAGE:
        # Check if this is a TAXII 1.0 server and try again
        if response.info().getheader('X-TAXII-Content-Type') == t.VID_TAXII_XML_10:
            poll_msg = tm.PollRequest(message_id=tm.generate_message_id(),
                                    feed_name=feed,
                                    exclusive_begin_timestamp_label=start,
                                    inclusive_end_timestamp_label=end)

            response = client.callTaxiiService2(hostname, '/poll/', t.VID_TAXII_XML_10,
                                            poll_msg.to_xml())
            taxii_msg = t.get_message_from_http_response(response, poll_msg.message_id)
            if response.getcode() != 200 or taxii_msg.message_type == tm.MSG_STATUS_MESSAGE:
                ret['reason'] = "%s: %s" % (taxii_msg.status_type,
                                            taxii_msg.message)
                return ret
        else:
            ret['reason'] = "%s: %s" % (taxii_msg.status_type,
                                        taxii_msg.message)
            return ret


    valid = tm.validate_xml(taxii_msg.to_xml())
    if valid != True:
        ret['reason'] = "Invalid XML: %s" % valid
        return ret

    if taxii_msg.message_type != tm.MSG_POLL_RESPONSE:
        ret['reason'] = "No poll response. Unexpected message type: %s" % taxii_msg.message_type
        return ret

    ret['status'] = True

    if not taxii_msg.content_blocks:
        crits_taxii.save()
        return ret

    mid = taxii_msg.message_id
    for content_block in taxii_msg.content_blocks:
        data = parse_content_block(content_block, keyfile, certfile)
        if not data:
            ret['failures'].append(('No data found in content block', 'Data'))
            continue

        objs = import_standards_doc(data, analyst, method, ref=mid,
                                    make_event=create_events)

        for k in objs['imported']:
            ret['successes'] += 1
            ret[objs['imported'][k][0]].append(objs['imported'][k][1])
        for k in objs['failed']:
            ret['failures'].append(k)


    crits_taxii.save()
    return ret

def parse_content_block(content_block, privkey=None, pubkey=None):
    if content_block.content_binding == 'application/x-pks7-mime':
        if not privkey and not pubkey:
            return None

        inbuf = BIO.MemoryBuffer(BytesIO(content_block.content).read())
        s = SMIME.SMIME()
        try:
            s.load_key(privkey, pubkey)
            p7, data = SMIME.smime_load_pkcs7_bio(inbuf)
            buf = s.decrypt(p7)
        except SMIME.PKCS7_Error:
            return None
        f = BytesIO(buf)
        new_block = f.read()
        f.close()
        return parse_content_block(tm.ContentBlock.from_xml(new_block), privkey, pubkey)
    elif content_block.content_binding == t.CB_STIX_XML_111:
        f = BytesIO(content_block.content)
        data = f.read()
        f.close()
        return data
    else:
        return None


def to_cybox_observable(obj, exclude=None, bin_fmt="raw"):
    """
    Convert a CRITs TLO to a CybOX Observable.

    :param obj: The TLO to convert.
    :type obj: :class:`crits.core.crits_mongoengine.CRITsBaseAttributes`
    :param exclude: Attributes to exclude.
    :type exclude: list
    :param bin_fmt: The format for the binary (if applicable).
    :type bin_fmt: str
    """

    type_ = obj._meta['crits_type']
    if type_ == 'Certificate':
        custom_prop = Property() # make a custom property so CRITs import can identify Certificate exports
        custom_prop.name = "crits_type"
        custom_prop.description = "Indicates the CRITs type of the object this CybOX object represents"
        custom_prop._value = "Certificate"
        obje = File() # represent cert information as file
        obje.md5 = obj.md5
        obje.file_name = obj.filename
        obje.file_format = obj.filetype
        obje.size_in_bytes = obj.size
        obje.custom_properties = CustomProperties()
        obje.custom_properties.append(custom_prop)
        obs = Observable(obje)
        obs.description = obj.description
        data = obj.filedata.read()
        if data: # if cert data available
            a = Artifact(data, Artifact.TYPE_FILE) # create artifact w/data
            a.packaging.append(Base64Encoding())
            obje.add_related(a, "Child_Of") # relate artifact to file
        return ([obs], obj.releasability)
    elif type_ == 'Domain':
        obje = DomainName()
        obje.value = obj.domain
        obje.type_ = obj.record_type
        return ([Observable(obje)], obj.releasability)
    elif type_ == 'Email':
        if exclude == None:
            exclude = []

        observables = []

        obje = EmailMessage()
        # Assume there is going to be at least one header
        obje.header = EmailHeader()

        if 'message_id' not in exclude:
            obje.header.message_id = String(obj.message_id)

        if 'subject' not in exclude:
            obje.header.subject = String(obj.subject)

        if 'sender' not in exclude:
            obje.header.sender = Address(obj.sender, Address.CAT_EMAIL)

        if 'reply_to' not in exclude:
            obje.header.reply_to = Address(obj.reply_to, Address.CAT_EMAIL)

        if 'x_originating_ip' not in exclude:
            obje.header.x_originating_ip = Address(obj.x_originating_ip,
                                                  Address.CAT_IPV4)

        if 'x_mailer' not in exclude:
            obje.header.x_mailer = String(obj.x_mailer)

        if 'boundary' not in exclude:
            obje.header.boundary = String(obj.boundary)

        if 'raw_body' not in exclude:
            obje.raw_body = obj.raw_body

        if 'raw_header' not in exclude:
            obje.raw_header = obj.raw_header

        #copy fields where the names differ between objects
        if 'helo' not in exclude and 'email_server' not in exclude:
            obje.email_server = String(obj.helo)
        if ('from_' not in exclude and 'from' not in exclude and
            'from_address' not in exclude):
            obje.header.from_ = EmailAddress(obj.from_address)
        if 'date' not in exclude and 'isodate' not in exclude:
            obje.header.date = DateTime(obj.isodate)

        obje.attachments = Attachments()

        observables.append(Observable(obje))
        return (observables, obj.releasability)
    elif type_ == 'Indicator':
        observables = []
        obje = make_cybox_object(obj.ind_type, obj.value)
        observables.append(Observable(obje))
        return (observables, obj.releasability)
    elif type_ == 'IP':
        obje = Address()
        obje.address_value = obj.ip
        if obj.ip_type == IPTypes.IPv4_ADDRESS:
            obje.category = "ipv4-addr"
        elif obj.ip_type == IPTypes.IPv6_ADDRESS:
            obje.category = "ipv6-addr"
        elif obj.ip_type == IPTypes.IPv4_SUBNET:
            obje.category = "ipv4-net"
        elif obj.ip_type == IPTypes.IPv6_SUBNET:
            obje.category = "ipv6-subnet"
        return ([Observable(obje)], obj.releasability)
    elif type_ == 'PCAP':
        obje = File()
        obje.md5 = obj.md5
        obje.file_name = obj.filename
        obje.file_format = obj.contentType
        obje.size_in_bytes = obj.length
        obs = Observable(obje)
        obs.description = obj.description
        art = Artifact(obj.filedata.read(), Artifact.TYPE_NETWORK)
        art.packaging.append(Base64Encoding())
        obje.add_related(art, "Child_Of") # relate artifact to file
        return ([obs], obj.releasability)
    elif type_ == 'RawData':
        obje = Artifact(obj.data.encode('utf-8'), Artifact.TYPE_FILE)
        obje.packaging.append(Base64Encoding())
        obs = Observable(obje)
        obs.description = obj.description
        return ([obs], obj.releasability)
    elif type_ == 'Sample':
        if exclude == None:
            exclude = []

        observables = []
        f = File()
        for attr in ['md5', 'sha1', 'sha256']:
            if attr not in exclude:
                val = getattr(obj, attr, None)
                if val:
                    setattr(f, attr, val)
        if obj.ssdeep and 'ssdeep' not in exclude:
            f.add_hash(Hash(obj.ssdeep, Hash.TYPE_SSDEEP))
        if 'size' not in exclude and 'size_in_bytes' not in exclude:
            f.size_in_bytes = UnsignedLong(obj.size)
        if 'filename' not in exclude and 'file_name' not in exclude:
            f.file_name = obj.filename
        # create an Artifact object for the binary if it exists
        if 'filedata' not in exclude and bin_fmt:
            data = obj.filedata.read()
            if data: # if sample data available
                a = Artifact(data, Artifact.TYPE_FILE) # create artifact w/data
                if bin_fmt == "zlib":
                    a.packaging.append(ZlibCompression())
                    a.packaging.append(Base64Encoding())
                elif bin_fmt == "base64":
                    a.packaging.append(Base64Encoding())
                f.add_related(a, "Child_Of") # relate artifact to file
        if 'filetype' not in exclude and 'file_format' not in exclude:
            #NOTE: this doesn't work because the CybOX File object does not
            #   have any support built in for setting the filetype to a
            #   CybOX-binding friendly object (e.g., calling .to_dict() on
            #   the resulting CybOX object fails on this field.
            f.file_format = obj.filetype
        observables.append(Observable(f))
        return (observables, obj.releasability)
    else:
        return (None, None)

def to_stix_indicator(obj):
    """
    Creates a STIX Indicator object from a CybOX object.

    Returns the STIX Indicator and the original CRITs object's
    releasability list.
    """
    from stix.indicator import Indicator as S_Ind
    from stix.common.identity import Identity
    ind = S_Ind()
    obs, releas = to_cybox_observable(obj)
    for ob in obs:
        ind.add_observable(ob)
    #TODO: determine if a source wants its name shared. This will
    #   probably have to happen on a per-source basis rather than a per-
    #   object basis.
    identity = Identity(name=settings.COMPANY_NAME)
    ind.set_producer_identity(identity)

    return (ind, releas)

def to_stix_actor(obj):
    """
    Create a STIX Actor.
    """

    ta = ThreatActor()
    ta.title = obj.name
    ta.description = obj.description
    for tt in obj.threat_types:
        ta.add_type(tt)
    for m in obj.motivations:
        ta.add_motivation(m)
    for ie in obj.intended_effects:
        ta.add_intended_effect(ie)
    for s in obj.sophistications:
        ta.add_sophistication(s)
    #for i in self.identifiers:
    return (ta, obj.releasability)

def to_stix_incident(obj):
    """
    Creates a STIX Incident object from a CRITs Event.

    Returns the STIX Incident and the original CRITs Event's
    releasability list.
    """
    from stix.incident import Incident
    inc = Incident(title=obj.title, description=obj.description)

    return (inc, obj.releasability)

def has_cybox_repr(obj):
    """
    Determine if this indicator is of a type that can
    successfully be converted to a CybOX object.

    :return The CybOX representation if possible, else False.
    """
    try:
        rep = make_cybox_object(obj)
        return rep
    except:
        return False

def to_stix(obj, items_to_convert=[], loaded=False, bin_fmt="raw"):
    """
    Converts a CRITs object to a STIX document.

    The resulting document includes standardized representations
    of all related objects noted within items_to_convert.

    :param items_to_convert: The list of items to convert to STIX/CybOX
    :type items_to_convert: Either a list of CRITs objects OR
                            a list of {'_type': CRITS_TYPE, '_id': CRITS_ID} dicts
    :param loaded: Set to True if you've passed a list of CRITs objects as
                    the value for items_to_convert, else leave False.
    :type loaded: bool
    :param bin_fmt: Specifies the format for Sample data encoding.
                    Options: None (don't include binary data in STIX output),
                                "raw" (include binary data as is),
                                "base64" (base64 encode binary data)

    :returns: A dict indicating which items mapped to STIX indicators, ['stix_indicators']
                which items mapped to STIX observables, ['stix_observables']
                which items are included in the resulting STIX doc, ['final_objects']
                and the STIX doc itself ['stix_obj'].
    """

    from cybox.common import Time, ToolInformationList, ToolInformation
    from stix.common import StructuredText, InformationSource
    from stix.core import STIXPackage, STIXHeader
    from stix.common.identity import Identity

    # These lists are used to determine which CRITs objects
    # go in which part of the STIX document.
    ind_list = ['Indicator']
    obs_list = ['Certificate',
                'Domain',
                'Email',
                'IP',
                'PCAP',
                'RawData',
                'Sample']
    actor_list = ['Actor']

    # Store message
    stix_msg = {
                    'stix_incidents': [],
                    'stix_indicators': [],
                    'stix_observables': [],
                    'stix_actors': [],
                    'final_objects': []
                }

    if not loaded: # if we have a list of object metadata, load it before processing
        items_to_convert = [class_from_id(item['_type'], item['_id'])
                                for item in items_to_convert]

    # add self to the list of items to STIXify
    if obj not in items_to_convert:
        items_to_convert.append(obj)

    # add any email attachments
    attachments = []
    for obj in items_to_convert:
        if obj._meta['crits_type'] == 'Email':
            for rel in obj.relationships:
                if rel.relationship == RelationshipTypes.CONTAINS:
                    atch = class_from_id('Sample', rel.object_id)
                    if atch not in items_to_convert:
                        attachments.append(atch)
    items_to_convert.extend(attachments)

    # grab ObjectId of items
    refObjs = {key.id: 0 for key in items_to_convert}

    relationships = {}
    stix = []
    from stix.indicator import Indicator as S_Ind
    for obj in items_to_convert:
        obj_type = obj._meta['crits_type']
        if obj_type == class_from_type('Event')._meta['crits_type']:
            stx, release = to_stix_incident(obj)
            stix_msg['stix_incidents'].append(stx)
        elif obj_type in ind_list: # convert to STIX indicators
            stx, releas = to_stix_indicator(obj)
            stix_msg['stix_indicators'].append(stx)
            refObjs[obj.id] = S_Ind(idref=stx.id_)
        elif obj_type in obs_list: # convert to CybOX observable
            if obj_type == class_from_type('Sample')._meta['crits_type']:
                stx, releas = to_cybox_observable(obj, bin_fmt=bin_fmt)
            else:
                stx, releas = to_cybox_observable(obj)

            # wrap in stix Indicator
            ind = S_Ind()
            for ob in stx:
                ind.add_observable(ob)
            ind.title = "CRITs %s Top-Level Object" % obj_type
            ind.description = ("This is simply a CRITs %s top-level "
                                "object, not actually an Indicator. "
                                "The Observable is wrapped in an Indicator"
                                " to facilitate documentation of the "
                                "relationship." % obj_type)
            ind.confidence = 'None'
            stx = ind
            stix_msg['stix_indicators'].append(stx)
            refObjs[obj.id] = S_Ind(idref=stx.id_)
        elif obj_type in actor_list: # convert to STIX actor
            stx, releas = to_stix_actor(obj)
            stix_msg['stix_actors'].append(stx)

        # get relationships from CRITs objects
        for rel in obj.relationships:
            if rel.object_id in refObjs:
                relationships.setdefault(stx.id_, {})
                relationships[stx.id_][rel.object_id] = (rel.relationship,
                                                            rel.rel_confidence.capitalize(),
                                                            rel.rel_type)

        stix_msg['final_objects'].append(obj)
        stix.append(stx)

    # set relationships on STIX objects
    for stix_obj in stix:
        for rel in relationships.get(stix_obj.id_, {}):
            if isinstance(refObjs.get(rel), S_Ind): # if is STIX Indicator
                stix_obj.related_indicators.append(refObjs[rel])
                rel_meta = relationships.get(stix_obj.id_)[rel]
                stix_obj.related_indicators[-1].relationship = rel_meta[0]
                stix_obj.related_indicators[-1].confidence = rel_meta[1]

                # Add any Email Attachments to CybOX EmailMessage Objects
                if isinstance(stix_obj, S_Ind):
                    if 'EmailMessage' in stix_obj.observable.object_.id_:
                        if rel_meta[0] == 'Contains' and rel_meta[2] == 'Sample':
                            email = stix_obj.observable.object_.properties
                            email.attachments.append(refObjs[rel].idref)

    tool_list = ToolInformationList()
    tool = ToolInformation("CRITs", "MITRE")
    tool.version = settings.CRITS_VERSION
    tool_list.append(tool)
    i_s = InformationSource(
        time=Time(produced_time= datetime.now()),
        identity=Identity(name=settings.COMPANY_NAME),
        tools=tool_list)

    if obj._meta['crits_type'] == "Event":
        stix_desc = obj.description()
        stix_int = obj.event_type()
        stix_title = obj.title()
    else:
        stix_desc = "STIX from %s" % settings.COMPANY_NAME
        stix_int = "Collective Threat Intelligence"
        stix_title = "Threat Intelligence Sharing"
    header = STIXHeader(information_source=i_s,
                        description=StructuredText(value=stix_desc),
                        package_intents=[stix_int],
                        title=stix_title)

    stix_msg['stix_obj'] = STIXPackage(incidents=stix_msg['stix_incidents'],
                    indicators=stix_msg['stix_indicators'],
                    threat_actors=stix_msg['stix_actors'],
                    stix_header=header,
                    id_=uuid.uuid4())

    return stix_msg

def run_taxii_service(analyst, obj, rcpts, preview, relation_choices=[], confirmed=False):
    """
    :param analyst The analyst triggering this TAXII service call
    :param obj The context object being shared
    :param rcpts The list of sources to which the TAXII message is being sent
    :param preview If true, generate and return the STIX doc, rather than sending via TAXII
    :param relation_choices The list of items related to OBJ that have been chosen for sharing
    :param confirmed True if user has accepted & approved releasability updates
    """
    ret = {
            'success': False, # tells client whether any message was sent successfully
            'rcpts': [], # list of sources the message was sent
            'failed_rcpts': [], # list of sources to which the message failed to be sent
          }

    if not obj: # no item (shouldn't occur unless someone is really trying to break things.)
        ret['reason'] = "No object found."
        return ret

    if not rcpts: # no sources selected in TAXII form (validation prevents this, anyway)
        ret['reason'] = "No recipients selected."
        return ret

    # If dealing with an event context, make sure at least one related item is
    # selected. Events have no real sharing value without related information.
    if obj._meta['crits_type'] == Event._meta['crits_type'] and len(relation_choices) == 0:
        ret['reason'] = "Need at least one related item to send."
        return ret

    # Get config and grab some stuff we need.
    sc = get_config('taxii_service')
    hostname = sc['hostname']
    https = sc['https']
    keyfile = sc['keyfile']
    certfile = sc['certfile']
    certfiles = sc['certfiles']

    # collect the list of destination data feeds for the message
    destination_feeds = []
    for crtfile in certfiles:
        (source, feed, filepath) = crtfile.split(',')
        src = source.strip()
        if src in rcpts:
            destination_feeds.append((src, feed.strip(), filepath.strip()))

    if not destination_feeds or len(destination_feeds) != len(rcpts):
        # TAXII form ensures that this shouldn't happen, but just in case...
        ret['reason'] = "Misconfigured TAXII service -- contact an administrator."
        return ret

    # The minimum required info has been provided by user via the TAXII form.
    # Form configuration and validation ensures the form is valid.
    # The TAXII service has also been confirmed to have config information
    # for each selected recipient.
    #
    # NOTE: this does not guarantee that the message will send to
    # each/any recipient feed successfully.

    # Convert object and chosen related items to STIX/CybOX
    stix_msg = to_stix(obj, relation_choices, bin_fmt="base64")
    stix_doc = stix_msg['stix_obj']

    # if doing a preview of content, return content now
    if preview:
        ret['preview'] = stix_doc.to_xml()
        return ret
    elif not confirmed: # if user has not accepted responsibility for releasability
        release = verify_releasability(rcpts, stix_msg['final_objects'], analyst, False)
        if release: # if releasability needs to change
            ret['release_changes'] = release
            return ret # make user confirm changes, instead of sending messages

    #TODO: this doesn't confirm that 'hostname' is a TAXII server...
    if not resolve_taxii_server(hostname):
        ret['reason'] = "Cannot contact TAXII Server at: %s" % hostname
        return ret

    client = tc.HttpClient()
    if https:
        client.setUseHttps(True)
        client.setAuthType(tc.HttpClient.AUTH_CERT)
        client.setAuthCredentials({'key_file': keyfile, 'cert_file': certfile})

    if settings.HTTP_PROXY:
        proxy = settings.HTTP_PROXY
        if not proxy.startswith('http://'):
            proxy = 'http://' + proxy
        client.setProxy(proxy)

    # generate and send inbox messages
    # one message per feed, with appropriate TargetFeed header specified
    # Store each TAXII message in a list.
    for feed in destination_feeds:
        rcpt = feed[0]
        # Create encrypted block
        encrypted_block = encrypt_block(
            tm.ContentBlock(
                content_binding = t.CB_STIX_XML_111,
                content = stix_doc.to_xml()).to_xml(),
            feed[2])
        # Try TAXII 1.1 first:
        try_10 = False
        current_status_type = None
        failed = True
        result = gen_send(tm11, client, encrypted_block, hostname,
                          t.VID_TAXII_XML_11,
                          dcn = [feed[1]],
                          url = "/services/inbox/")
        if len(result) == 2:
            res = result[1]
            if res.status_type == tm11.ST_SUCCESS:
                failed = False
                ret['rcpts'].append(rcpt)
            else:
                try_10 = True
                current_status_type = "<br>tm11: " + res.status_type
        else:
            try_10 = True
            current_status_type = "<br>tm11: " + result[0]

        # Try TAXII 1.0 since 1.1 seems to have failed.
        if try_10:
            result = gen_send(tm, client, encrypted_block, hostname,
                            t.VID_TAXII_XML_10,
                            eh = {'TargetFeed': feed[1]},
                            url = "/inbox/")
            if len(result) == 2:
                res = result[1]
                if res.status_type == tm11.ST_SUCCESS:
                    failed = False
                    ret['rcpts'].append(rcpt)
                else:
                    err = "tm10: " + res.status_type
                    current_status_type += "<br>%s" % err
            else:
                err = "tm10: " + result[0]
                current_status_type += "<br>%s" % err

        if failed:
            ret['failed_rcpts'].append((rcpt, current_status_type))

    if ret['rcpts']: # update releasability for successful TAXII messages
        verify_releasability(ret['rcpts'], stix_msg['final_objects'], analyst, True)

    ret['success'] = True
    return ret

def gen_send(tm_, client, encrypted_block, hostname, t_xml, dcn=None, eh=None,
             url="/inbox/"):
    """
    Generate and send a TAXII message.

    :param tm_: The TAXII version imported that we should use.
    :type tm_: TAXII message class.
    :param client: The TAXII client to use.
    :type client: TAXII Client.
    :param encrypted_block: The encrypted block to use.
    :type encrypted_block: TAXII Encrypted Block
    :param hostname: The TAXII server hostname to connect to.
    :type hostname: str
    :param t_xml: The TAXII XML Schema version we used.
    :type t_xml: str
    :param dcn: Destination Collection Names we are using.
    :type dcn: list
    :param eh: Extended Headers to use.
    :type eh: dict
    :param url: The URL suffix to locate the inbox service.
    :type url: str
    :returns: tuple (response, taxii_message) or (exception message)
    """

    # Wrap encrypted block in content block
    content_block = tm_.ContentBlock(
        content_binding = "application/x-pks7-mime",
        content = encrypted_block
    )
    # Create inbox message
    if dcn:
        inbox_message = tm_.InboxMessage(
            message_id = tm_.generate_message_id(),
            content_blocks = [content_block],
            destination_collection_names = dcn
        )
    elif eh:
        inbox_message = tm.InboxMessage(
            message_id = tm.generate_message_id(),
            content_blocks = [content_block],
            extended_headers = eh
        )
    else:
        #TODO: return better
        return None

    # send inbox message via TAXII service
    try:
        response = client.callTaxiiService2(
            hostname,
            url,
            t_xml,
            inbox_message.to_xml()
        )
        taxii_message = t.get_message_from_http_response(response,
                                                         inbox_message.message_id)
        return (response, taxii_message)
    # can happen if 'hostname' is reachable, but is not a TAXII server, etc
    except Exception, e:
        return (e)

def verify_releasability(rcpts, items, analyst, update=False):
    """
    Given the list of items being sent to a list of recipients via TAXII,
    determine what releasability changes (if any) are necessary for the
    TAXII message to be sent.

    :param rcpts List of sources to which all items in ITEMS must be releasable
    :param items List of items to ensure have proper releasability within RCPTS
    :param analyst Name of the analyst triggering the releasability update
    :param update If true, execute the changes
    :return Dict mapping item to list of necessary releasability additions
    """
    date = datetime.now() # timestamp to use for updates, if updating
    releaseable = Releasability.ReleaseInstance(analyst=analyst, date=date)
    changes = []
    for item in items: # for each item
        updates = [] # track sources that need releasability update
        curr_rel = [rel.name for rel in item['releasability']] # current item releasability
        for rcpt in rcpts: # check each source
            if not rcpt in curr_rel: # if ITEM is not releasable to source RCPT
                updates.append(rcpt) # note necessary releasability update
                if update: # if processing updates, add releasability to item
                    item.add_releasability(name=rcpt, instances=[releaseable],
                                           analyst=analyst)
            elif update: # if updating and already releasable, add a release instance
                item.add_releasability_instance(name=rcpt, instance=releaseable,
                                                analyst=analyst)
        if update:
            # if updating, the item will always be changed, so save it
            item.save(username=analyst)
        if updates:
            item_type = item._meta['crits_type']
            formatted = formats.get_format(item_type).format(item)
            changes.append((item_type, str(item.id), formatted, updates))
    return changes


def resolve_taxii_server(hostname):
    """
    Attempt to verify availability of the server at the given hostname.

    :return 1 if server was reachable, 0 otherwise.
    """
    try:
        socket.gethostbyname(hostname)
        return 1
    except socket.error:
        return 0

def encrypt_block(blob, pubkey):
    """
    Encrypt the given blob of data, given the public key provided.

    :return The encrypted blob.
    """
    # Make a MemoryBuffer of the message.
    inbuf = BIO.MemoryBuffer(blob)

    # Seed the PRNG.
    Rand.rand_seed(os.urandom(1024))

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert(pubkey)
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Set cipher: AES 256 bit in CBC mode.
    s.set_cipher(SMIME.Cipher('aes_256_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(inbuf)
    temp_buff = BIO.MemoryBuffer()
    s.write(temp_buff, p7)
    x = temp_buff.read()
    return x

def import_standards_doc(data, analyst, method, ref=None, make_event=False,
                         source=None):
    """
    Import a standards document into CRITs.

    :param data: The document data to feed into
                 :class:`crits.standards.parsers.STIXParser`
    :type data: str
    :param analyst: The user importing the document.
    :type analyst: str
    :param method: The method of acquiring this document.
    :type method: str
    :param ref: The reference to this document.
    :type ref: str
    :param make_event: Whether or not we should make an Event for this document.
    :type make_event: bool
    :param source: The name of the source who provided this document.
    :type source: str
    :returns: dict with keys:
              "success" (boolean),
              "reason" (str),
              "imported" (list),
              "failed" (list)
    """

    ret = {
            'success': False,
            'reason': '',
            'imported': [],
            'failed': []
          }

    try:
        parser = STIXParser(data, analyst, method)
        parser.parse_stix(reference=ref, make_event=make_event, source=source)
        parser.relate_objects()
    except STIXParserException, e:
        logger.exception(e)
        ret['reason'] = str(e.message)
        return ret
    except Exception, e:
        logger.exception(e)
        ret['reason'] = str(e)
        return ret

    ret['imported'] = parser.imported
    ret['failed'] = parser.failed
    ret['success'] = True
    return ret
