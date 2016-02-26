import datetime

from contextlib import closing
from copy import copy
from io import StringIO

from .object_mapper import (
    make_crits_object,
    get_crits_actor_tags,
    get_crits_ip_type,
    get_crits_event_type
)

from crits.actors.actor import Actor
from crits.actors.handlers import add_new_actor, update_actor_tags
from crits.certificates.handlers import handle_cert_file
from crits.domains.handlers import upsert_domain
from crits.emails.handlers import handle_email_fields
from crits.events.handlers import add_new_event
from crits.indicators.indicator import Indicator
from crits.indicators.handlers import handle_indicator_ind
from crits.ips.handlers import ip_add_update
from crits.pcaps.handlers import handle_pcap_file
from crits.raw_data.handlers import handle_raw_data_file
from crits.samples.handlers import handle_file
from crits.core.crits_mongoengine import EmbeddedSource
from crits.core.handlers import does_source_exist

from crits.vocabulary.events import EventTypes
from crits.vocabulary.indicators import (
    IndicatorAttackTypes,
    IndicatorThreatTypes
)
from crits.vocabulary.ips import IPTypes
from crits.vocabulary.relationships import RelationshipTypes

from cybox.objects.artifact_object import Artifact
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.http_session_object import HTTPSession
from cybox.objects.uri_object import URI
from cybox.objects.whois_object import WhoisEntry

import ramrod
import stix
from stix.common import StructuredText
from stix.core import STIXPackage, STIXHeader
from stix.indicator.indicator import CompositeIndicatorExpression
from stix.utils.parser import UnsupportedVersionError

class STIXParserException(Exception):
    """
    General exception for STIX Parsing.
    """

    def __init__(self, message):
        self.message = message

class STIXParser():
    """
    STIX Parser class.
    """

    def __init__(self, data, analyst, method, preview_only=False):
        """
        Instantiation of the STIXParser can take the data to parse, the analyst
        doing the parsing, and the method of data aquisition.

        :param data: The data to parse.
        :type data: str
        :param analyst: The analyst parsing the document.
        :type analyst: str
        :param method: The method of acquiring this data.
        :type method: str
        :param preview_only: If True, nothing is imported and a preview is returned
        :type preview_only: boolean
        """

        self.data = data
        self.preview = preview_only

        self.package = None
        self.stix_version = None

        self.source = EmbeddedSource() # source.name comes from the stix header.
        self.source_instance = EmbeddedSource.SourceInstance()
        # The reference attribute and appending it to the source is
        # done after the TAXII message ID is determined.
        self.source_instance.analyst = analyst
        self.source_instance.method = method
        self.information_source = None

        self.event = None # the Event TLO
        self.event_rels = {} # track relationships to the event
        self.relationships = [] # track other relationships that need forming
        self.ind2obj = {} # map STIX Indicator IDs to CybOX Object IDs
        self.obj2ind = {} # map CybOX Object IDs to STIX Indicator IDs
        self.imported = {} # track items that are imported
        self.updates = {} # track new/updated CRITs TLOs
        self.parsed = [] # track items that have been parsed, but not necessarily imported
        self.failed = [] # track STIX/CybOX items that failed import
        self.saved_artifacts = {}

    def parse_stix(self, reference='', make_event=False, source=''):
        """
        Parse the document.

        :param reference: The reference to the data.
        :type reference: str
        :param make_event: Whether or not to create an Event for this document.
        :type make_event: bool
        :param source: The source of this document.
        :type source: str
        :raises: :class:`taxii_service.parsers.STIXParserException`

        Until we have a way to map source strings in a STIX document to
        a source in CRITs, we are being safe and using the source provided
        as the true source.
        """

        with closing(StringIO(self.data)) as f:
            try:
                try:
                    self.package = STIXPackage.from_xml(f)
                    if not self.package:
                        raise STIXParserException("STIX package failure")
                except UnsupportedVersionError:
                    v = stix.__version__
                    v = v[0:-2] if len(v.split('.')) > 3 else v
                    updated = ramrod.update(f, to_=v)
                    doc = updated.document.as_stringio()
                    self.package = STIXPackage.from_xml(doc)
            except Exception as e:
                msg = "Failed to create STIX/CybOX from XML"
                self.failed.append((e.message,
                                    "STIX Package (%s)" % msg,
                                    '')) # note for display in UI
                return

        if not self.preview:
            self.stix_version = self.package.version
            stix_header = self.package.stix_header
            if stix_header and stix_header.information_source and stix_header.information_source.identity:
                self.information_source = stix_header.information_source.identity.name
                if self.information_source:
                    info_src = "STIX Source: %s" % self.information_source
                    if not reference:
                        reference = ''
                    else:
                        reference += ", "
                    reference += info_src
            if source:
                if does_source_exist(source):
                    self.source.name = source
                else:
                    raise STIXParserException('Source "%s" does not exist in CRITs.' % source)
            elif does_source_exist(self.information_source):
                self.source.name = self.information_source
            else:
                raise STIXParserException("No source to attribute data to.")

            self.source_instance.reference = reference
            self.source.instances.append(self.source_instance)

        if make_event:
            title = "STIX Document %s" % self.package.id_
            event_type = EventTypes.INTEL_SHARING
            date = datetime.datetime.now()
            description = str(date)
            header = self.package.stix_header
            if isinstance(header, STIXHeader):
                if header.title:
                    title = header.title
                if header.package_intents:
                    try:
                        stix_type = str(header.package_intents[0])
                        event_type = get_crits_event_type(stix_type)
                    except:
                        pass
                if header.description:
                    description = header.description
                    if isinstance(description, StructuredText):
                        try:
                            description = description.to_dict()
                        except:
                            pass
            if self.preview:
                self.imported[self.package.id_] = ('Event',
                                                   None,
                                                   title)
            else:
                res = add_new_event(title,
                                    description,
                                    event_type,
                                    self.source.name,
                                    self.source_instance.method,
                                    self.source_instance.reference,
                                    date,
                                    self.source_instance.analyst)
                self.parsed.append(self.package.id_)
                if res['success']:
                    self.event = res['object']
                    self.imported[self.package.id_] = ('Event',
                                                       res['object'].id,
                                                       title or res['object'].id)
                    self.updates[res['object'].id] = res['object']

                    # Get relationships to the Event
                    if self.package.incidents:
                        incdnts = self.package.incidents
                        for rel in getattr(incdnts[0], 'related_indicators', ()):
                            if rel.relationship or rel.confidence:
                                r = rel.relationship.value or RelationshipTypes.RELATED_TO
                                c = getattr(rel.confidence.value, 'value', 'Unknown')
                                self.event_rels[rel.item.idref] = (r, c)
                else:
                    self.failed.append((res['message'],
                                        "Event (%s)" % title,
                                        self.package.id_))

        if self.package.indicators:
            self.parse_indicators(self.package.indicators)

        if self.package.observables and self.package.observables.observables:
            self.parse_observables(self.package.observables.observables)

        if self.package.threat_actors:
            self.parse_threat_actors(self.package.threat_actors)

    def parse_threat_actors(self, threat_actors):
        """
        Parse list of Threat Actors.

        :param threat_actors: List of STIX ThreatActors.
        :type threat_actors: List of STIX ThreatActors.
        """
        from stix.threat_actor import ThreatActor
        analyst = self.source_instance.analyst
        for threat_actor in threat_actors: # for each STIX ThreatActor
            try: # create CRITs Actor from ThreatActor
                if isinstance(threat_actor, ThreatActor):
                    name = str(threat_actor.title)
                    if not self.preview:
                        description = str(threat_actor.description)
                        res = add_new_actor(name=name,
                                            description=description,
                                            source=[self.source],
                                            analyst=analyst)
                        self.parsed.append(threat_actor.id_)
                        if res['success']:
                            sl = ml = tl = il = []
                            for s in threat_actor.sophistications:
                                v = get_crits_actor_tags(str(s.value))
                                if v:
                                    sl.append(v)
                            update_actor_tags(res['id'],
                                                'ActorSophistication',
                                                sl,
                                                analyst)
                            for m in threat_actor.motivations:
                                v = get_crits_actor_tags(str(m.value))
                                if v:
                                    ml.append(v)
                            update_actor_tags(res['id'],
                                                'ActorMotivation',
                                                ml,
                                                analyst)
                            for t in threat_actor.types:
                                v = get_crits_actor_tags(str(t.value))
                                if v:
                                    tl.append(v)
                            update_actor_tags(res['id'],
                                                'ActorThreatType',
                                                tl,
                                                analyst)
                            for i in threat_actor.intended_effects:
                                v = get_crits_actor_tags(str(i.value))
                                if v:
                                    il.append(v)
                            update_actor_tags(res['id'],
                                                'ActorIntendedEffect',
                                                il,
                                                analyst)
                            obj = Actor.objects(id=res['id']).first()
                            self.updates[obj.id] = obj
                            self.imported[threat_actor.id_] = (Actor._meta['crits_type'],
                                                               obj.id, name or obj.id)
                        else: #preview only
                            self.imported[threat_actor.id_] = (Actor._meta['crits_type'],
                                                               None, name)
                    else:
                        self.failed.append((res['message'],
                                            "Threat Actor (%s)" % name,
                                            threat_actor.id_)) # note for display in UI
            except Exception, e:
                self.failed.append((e.message,
                                    "Threat Actor (%s)" % name,
                                    threat_actor.id_)) # note for display in UI

    def parse_indicators(self, indicators, parent_description=''):
        """
        Parse list of indicators.

        :param indicators: List of STIX indicators.
        :type indicators: List of STIX indicators.
        :param parent_description: The description of the parent indicator.
        :type parent_description: str.
        """

        for indicator in indicators: # for each STIX indicator
            if indicator.composite_indicator_expression: # parse indicator composition.
                # CRITs doesn't support complex boolean relationships like
                # ((A OR B) AND C). This code simply imports all indicators
                # and forms "Related_To" relationships between them

                # grab description while keeping any parent description
                p_description = ''
                if parent_description:
                    p_description = parent_description + '\n'
                if indicator.indicator_types:
                    p_description += ('STIX Indicator Type: ' +
                                  indicator.indicator_types[0].value + '\n')
                if indicator.description:
                    p_description += indicator.description.value

                cie = indicator.composite_indicator_expression
                self.parse_indicators(cie, p_description)
                rel_ids = []

                if self.preview: # no need to store relationship if just a preview
                    continue

                for com_ind in cie:
                    if com_ind.observables: # this contains an indicator
                        rel_ids.append(com_ind.id_)
                    else: # this contains another composition
                        if com_ind.id_ in self.ind2obj:
                            rel_ids.extend(self.ind2obj.pop(com_ind.id_))
                        else:
                            rel_ids.append(com_ind.id_)
                if isinstance(indicators, CompositeIndicatorExpression):
                    self.ind2obj.setdefault(indicator.id_, []).extend(rel_ids)
                else: # This is the top level, so form relationships
                    for iid in rel_ids:
                        for iid2 in rel_ids:
                            if iid != iid2:
                                self.relationships.append((iid,
                                                           RelationshipTypes.RELATED_TO,
                                                           iid2, "High"))
                continue

            # store relationships
            if not self.preview:
                for rel in getattr(indicator, 'related_indicators', ()):
                    if rel.confidence:
                        conf = rel.confidence.value.value
                    else:
                        conf = 'Unknown'
                    self.relationships.append((indicator.id_,
                                               rel.relationship.value,
                                               rel.item.idref,
                                               conf))

            try: # create CRITs Indicator from observable
                # handled indicator-wrapped observable
                if getattr(indicator, 'title', ""):
                    if "Top-Level Object" in indicator.title:
                        self.parse_observables(indicator.observables)
                        continue

                description = ''
                if parent_description:
                    description += '\n' + parent_description
                if indicator.indicator_types:
                    description += ('STIX Indicator Type: ' +
                                    indicator.indicator_types[0].value + '\n')
                if indicator.description:
                    description += indicator.description.value

                self.parse_observables(indicator.observables,
                                       description, indicator.id_)

            except Exception, e:
                self.failed.append((e.message,
                                    "Indicator (%s)" % indicator.id_,
                                    indicator.id_)) # note for display in UI


    def parse_observables(self, observables, description='', ind_id=None):
        """
        Parse list of observables in STIX doc.

        :param observables: List of STIX observables.
        :type observables: List of STIX observables.
        :param description: Parent-level (e.g. Indicator) description.
        :type description: str
        :param ind_id: The ID of a parent STIX Indicator.
        :type ind_id: str
        """

        for ob in observables: # for each STIX observable
            if not ob.object_:
                if ob._observable_composition: # parse observable composition.
                    # CRITs doesn't support complex boolean relationships like
                    # ((A OR B) AND C). This code simply imports all observables
                    # and forms "Related_To" relationships between them
                    self.parse_observables(ob._observable_composition.observables,
                                           description, ind_id)
                    rel_ids = []

                    if self.preview: # no need to store relationship if just a preview
                        continue

                    for com_ob in ob._observable_composition.observables:
                        if com_ob.object_:
                            rel_ids.append(com_ob.object_.id_)
                        else:
                            if com_ob.id_ in self.ind2obj:
                                rel_ids.extend(self.ind2obj.pop(com_ob.id_))
                            else:
                                rel_ids.append(com_ob.id_)
                    if len(observables) > 1:
                        self.ind2obj.setdefault(ob.id_, []).extend(rel_ids)
                    else: # This is the top level, so form relationships
                        for oid in rel_ids:
                            for oid2 in rel_ids:
                                if oid != oid2:
                                    self.relationships.append((oid,
                                                               RelationshipTypes.RELATED_TO,
                                                               oid2, "High"))
                    continue

                self.failed.append(("No valid CybOX object_ found!",
                                    "Observable (%s)" % ob.id_,
                                    ob.id_)) # note for display in UI
                continue

            description = ob.description or description
            self.parse_cybox_object(ob.object_, description, ind_id)


    def parse_cybox_object(self, cbx_obj, description='', ind_id=None):
        """
        Parse a CybOX object form a STIX doc. An object can contain
        multiple related_objects, which in turn can have their own
        related_objects, so this handles those recursively.

        :param cbx_obj: The CybOX object to parse.
        :type cbx_obj: A CybOX object.
        :param description: Parent-level (e.g. Observable) description.
        :type description: str
        :param ind_id: The ID of a parent STIX Indicator.
        :type ind_id: str
        """

        # check for missing attributes
        if not cbx_obj or not cbx_obj.properties:
            if cbx_obj.idref: # just a reference, so nothing to parse
                return
            else:
                cbx_id = getattr(cbx_obj, 'id_', 'None')
                self.failed.append(("No valid object_properties was found!",
                                    "Observable (%s)" % cbx_id,
                                    cbx_id)) # note for display in UI
                return

        # Don't parse if already been parsed
        # This is for artifacts that are related to CybOX File Objects
        if cbx_obj.id_ in self.parsed:
            return

        try: # try to create CRITs object from Cybox Object
            analyst = self.source_instance.analyst
            item = cbx_obj.properties
            val = cbx_obj.id_
            if isinstance(item, Address) and not ind_id:
                if item.category in ('cidr', 'ipv4-addr', 'ipv4-net',
                                     'ipv4-netmask', 'ipv6-addr',
                                     'ipv6-net', 'ipv6-netmask'):
                    imp_type = "IP"
                    for value in item.address_value.values:
                        val = str(value).strip()
                        if self.preview:
                            res = None
                        else:
                            iptype = get_crits_ip_type(item.category)
                            if iptype:
                                res = ip_add_update(val,
                                                    iptype,
                                                    [self.source],
                                                    analyst=analyst,
                                                    is_add_indicator=True)
                            else:
                                res = {'success': False, 'reason': 'No IP Type'}
                        self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            if (not ind_id and (isinstance(item, DomainName) or
                (isinstance(item, URI) and item.type_ == 'Domain Name'))):
                imp_type = "Domain"
                for val in item.value.values:
                    if self.preview:
                        res = None
                    else:
                        res = upsert_domain(str(val),
                                            [self.source],
                                            username=analyst)
                    self.parse_res(imp_type, str(val), cbx_obj, res, ind_id)

            elif isinstance(item, HTTPSession):
                imp_type = "RawData"
                val = cbx_obj.id_
                try:
                    c_req = item.http_request_response[0].http_client_request
                    hdr = c_req.http_request_header
                    if hdr.raw_header:
                        data = hdr.raw_header.value
                        title = "HTTP Header from STIX: %s" % self.package.id_
                        method = self.source_instance.method
                        ref = self.source_instance.reference
                        if self.preview:
                            res = None
                            val = title
                        else:
                            res = handle_raw_data_file(data,
                                                    self.source.name,
                                                    user=analyst,
                                                    description=description,
                                                    title=title,
                                                    data_type="HTTP Header",
                                                    tool_name="STIX",
                                                    tool_version=None,
                                                    method=method,
                                                    reference=ref)
                    else:
                        imp_type = "Indicator"
                        ind_type = "HTTP Request Header Fields - User-Agent"
                        val = hdr.parsed_header.user_agent.value
                        val = ','.join(val) if isinstance(val, list) else val
                        if self.preview:
                            res = None
                        else:
                            res = handle_indicator_ind(val,
                                                    self.source,
                                                    ind_type,
                                                    IndicatorThreatTypes.UNKNOWN,
                                                    IndicatorAttackTypes.UNKNOWN,
                                                    analyst,
                                                    add_relationship=True,
                                                    description=description)
                except:
                    msg = "Unsupported use of 'HTTPSession' object."
                    res = {'success': False, 'reason': msg}

                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif isinstance(item, WhoisEntry):
                # No sure where else to put this
                imp_type = "RawData"
                val = cbx_obj.id_
                if item.remarks:
                    data = item.remarks.value
                    title = "WHOIS Entry from STIX: %s" % self.package.id_
                    if self.preview:
                        res = None
                        val = title
                    else:
                        res = handle_raw_data_file(data,
                                                self.source.name,
                                                user=analyst,
                                                description=description,
                                                title=title,
                                                data_type="Text",
                                                tool_name="WHOIS",
                                                tool_version=None,
                                                method=self.source_instance.method,
                                                reference=self.source_instance.reference)
                else:
                    msg = "Unsupported use of 'WhoisEntry' object."
                    res = {'success': False, 'reason': msg}

                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif isinstance(item, Artifact):
                # Not sure if this is right, and I believe these can be
                # encoded in a couple different ways.
                imp_type = "RawData"
                val = cbx_obj.id_
                rawdata = item.data.decode('utf-8')
                # TODO: find out proper ways to determine title, datatype,
                #       tool_name, tool_version
                title = "Artifact for Event: STIX Document %s" % self.package.id_
                if self.preview:
                    res = None
                    val = title
                else:
                    res = handle_raw_data_file(rawdata,
                                            self.source.name,
                                            user=analyst,
                                            description=description,
                                            title=title,
                                            data_type="Text",
                                            tool_name="STIX",
                                            tool_version=None,
                                            method=self.source_instance.method,
                                            reference=self.source_instance.reference)
                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif (isinstance(item, File) and
                  item.custom_properties and
                  item.custom_properties[0].name == "crits_type" and
                  item.custom_properties[0]._value == "Certificate"):
                imp_type = "Certificate"
                val = str(item.file_name)
                data = None
                if self.preview:
                    res = None
                else:
                    for rel_obj in item.parent.related_objects:
                        if isinstance(rel_obj.properties, Artifact):
                            data = rel_obj.properties.data
                            self.parsed.append(rel_obj.id_)
                    res = handle_cert_file(val,
                                           data,
                                           self.source,
                                           user=analyst,
                                           description=description)
                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif isinstance(item, File) and self.has_network_artifact(item):
                imp_type = "PCAP"
                val = str(item.file_name)
                data = None
                if self.preview:
                    res = None
                else:
                    for rel_obj in item.parent.related_objects:
                        if (isinstance(rel_obj.properties, Artifact) and
                            rel_obj.properties.type_ == Artifact.TYPE_NETWORK):
                            data = rel_obj.properties.data
                            self.parsed.append(rel_obj.id_)
                    res = handle_pcap_file(val,
                                           data,
                                           self.source,
                                           user=analyst,
                                           description=description)
                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif isinstance(item, File):
                imp_type = "Sample"
                md5 = item.md5
                if md5:
                    md5 = md5.lower()
                val = str(item.file_name or md5)
                # add sha1/sha256/ssdeep once handle_file supports it
                size = item.size_in_bytes
                data = None
                if item.file_path:
                    path = "File Path: " + str(item.file_path)
                    description += "\n" + path
                for rel_obj in item.parent.related_objects:
                    if (isinstance(rel_obj.properties, Artifact) and
                        rel_obj.properties.type_ == Artifact.TYPE_FILE):
                        data = rel_obj.properties.data
                        self.parsed.append(rel_obj.id_)
                if not md5 and not data and val and val != "None":
                    imp_type = "Indicator"
                    if self.preview:
                        res = None
                    else:
                        res = handle_indicator_ind(val,
                                                   self.source,
                                                   "Win File",
                                                   IndicatorThreatTypes.UNKNOWN,
                                                   IndicatorAttackTypes.UNKNOWN,
                                                   analyst,
                                                   add_domain=True,
                                                   add_relationship=True,
                                                   description=description)
                elif md5 or data:
                    if self.preview:
                        res = None
                    else:
                        res = handle_file(val,
                                          data,
                                          self.source,
                                          user=analyst,
                                          md5_digest=md5,
                                          is_return_only_md5=False,
                                          size=size,
                                          description=description)
                else:
                    val = cbx_obj.id_
                    msg = "CybOX 'File' object has no MD5, data, or filename"
                    res = {'success': False, 'reason': msg}
                self.parse_res(imp_type, val, cbx_obj, res, ind_id)
            elif isinstance(item, EmailMessage):
                imp_type = 'Email'
                id_list = []
                data = {}
                val = cbx_obj.id_
                get_attach = False
                data['raw_body'] = str(item.raw_body)
                data['raw_header'] = str(item.raw_header)
                data['helo'] = str(item.email_server)
                if item.header:
                    data['subject'] = str(item.header.subject)
                    if item.header.date:
                        data['date'] = item.header.date.value
                    val = "Date: %s, Subject: %s" % (data.get('date', 'None'),
                                                     data['subject'])
                    data['message_id'] = str(item.header.message_id)
                    data['sender'] = str(item.header.sender)
                    data['reply_to'] = str(item.header.reply_to)
                    data['x_originating_ip'] = str(item.header.x_originating_ip)
                    data['x_mailer'] = str(item.header.x_mailer)
                    data['boundary'] = str(item.header.boundary)
                    data['from_address'] = str(item.header.from_)
                    if item.header.to:
                        data['to'] = [str(r) for r in item.header.to.to_list()]

                if data.get('date'): # Email TLOs must have a date
                    data['source'] = self.source.name
                    data['source_method'] = self.source_instance.method
                    data['source_reference'] = self.source_instance.reference
                    if self.preview:
                        res = None
                    else:
                        res = handle_email_fields(data,
                                                  analyst,
                                                  "STIX")
                    self.parse_res(imp_type, val, cbx_obj, res, ind_id)
                    if not self.preview and res.get('status'):
                        id_list.append(cbx_obj.id_) # save ID for atchmnt rels
                        get_attach = True
                else: # Can't be an Email TLO, so save fields
                    for x, key in enumerate(data):
                        if data[key] and data[key] != "None":
                            if key in ('raw_header', 'raw_body'):
                                if key == 'raw_header':
                                    title = "Email Header from STIX Email: %s"
                                    d_type = "Email Header"
                                else:
                                    title = "Email Body from STIX Email: %s"
                                    d_type = "Email Body"
                                imp_type = 'RawData'
                                title = title % cbx_obj.id_
                                if self.preview:
                                    res = None
                                else:
                                    res = handle_raw_data_file(data[key],
                                                               self.source,
                                                               analyst,
                                                               description,
                                                               title,
                                                               d_type,
                                                               "STIX",
                                                               self.stix_version)
                                self.parse_res(imp_type, title, cbx_obj,
                                               res, ind_id)
                            elif key == 'to':
                                imp_type = 'Target'
                                for y, addr in enumerate(data[key]):
                                    tgt_dict = {'email_address': addr}
                                    if self.preview:
                                        res = None
                                    else:
                                        res = upsert_target(tgt_dict, analyst)
                                        if res['success']:
                                            get_attach = True
                                    tmp_obj = copy(cbx_obj)
                                    tmp_obj.id_ = '%s-%s-%s' % (cbx_obj.id_,
                                                                x, y)
                                    self.parse_res(imp_type, addr, tmp_obj,
                                                   res, ind_id)
                                    self.ind2obj.setdefault(cbx_obj.id_,
                                                            []).append(tmp_obj.id_)
                                    id_list.append(tmp_obj.id_)
                            else:
                                imp_type = 'Indicator'
                                if key in ('sender', 'reply_to', 'from_address'):
                                    ind_type = "Address - e-mail"
                                elif 'ip' in key:
                                    ind_type = "Address - ipv4-addr"
                                elif key == 'raw_body':
                                    ind_type = "Email Message"
                                else:
                                    ind_type = "String"
                                if self.preview:
                                    res = None
                                else:
                                    res = handle_indicator_ind(data[key],
                                                          self.source,
                                                          ind_type,
                                                          IndicatorThreatTypes.UNKNOWN,
                                                          IndicatorAttackTypes.UNKNOWN,
                                                          analyst,
                                                          add_domain=True,
                                                          add_relationship=True,
                                                          description=description)
                                    if res['success']:
                                        get_attach = True
                                tmp_obj = copy(cbx_obj)
                                tmp_obj.id_ = '%s-%s' % (cbx_obj.id_, x)
                                self.parse_res(imp_type, data[key], tmp_obj,
                                               res, ind_id)
                                self.ind2obj.setdefault(cbx_obj.id_,
                                                        []).append(tmp_obj.id_)
                                id_list.append(tmp_obj.id_)

                if not self.preview:
                    # Setup relationships between all Email attributes
                    for oid in id_list:
                        for oid2 in id_list:
                            if oid != oid2:
                                self.relationships.append((oid,
                                                           RelationshipTypes.RELATED_TO,
                                                           oid2, "High"))

                    # Should check for attachments and add them here.
                    if get_attach and item.attachments:
                        for attach in item.attachments:
                            rel_id = attach.to_dict()['object_reference']
                            for oid in id_list:
                                self.relationships.append((oid,
                                                           RelationshipTypes.CONTAINS,
                                                           rel_id, "High"))

            else: # try to parse all other possibilities as Indicator
                imp_type = "Indicator"
                val = cbx_obj.id_
                c_obj = make_crits_object(item)

                # Ignore what was already caught above
                if (ind_id or c_obj.object_type not in IPTypes.values()):
                    ind_type = c_obj.object_type
                    for val in [str(v).strip() for v in c_obj.value if v]:
                        if ind_type:
                            # handle domains mislabeled as URLs
                            if c_obj.object_type == 'URI' and '/' not in val:
                                ind_type = "Domain"

                            if self.preview:
                                res = None
                            else:
                                res = handle_indicator_ind(val,
                                                        self.source,
                                                        ind_type,
                                                        IndicatorThreatTypes.UNKNOWN,
                                                        IndicatorAttackTypes.UNKNOWN,
                                                        analyst,
                                                        add_domain=True,
                                                        add_relationship=True,
                                                        description=description)
                            self.parse_res(imp_type, val, cbx_obj, res, ind_id)

        except Exception, e: # probably caused by cybox object we don't handle
            self.failed.append((e.message,
                                "%s (%s)" % (imp_type, val),
                                cbx_obj.id_)) # note for display in UI

        # parse any related CybOX object(s)
        for rel_obj in cbx_obj.related_objects:
            self.parse_cybox_object(rel_obj, description, ind_id)
            self.relationships.append((cbx_obj.id_, rel_obj.relationship.value,
                                       rel_obj.id_ or rel_obj.idref, "High"))


    def parse_res(self, imp_type, val, obj, res, ind_id=None):
        if res is None: #this is likely part of a preview
            self.imported[obj.id_] = (imp_type, None, val)
            return

        self.parsed.append(obj.id_)
        s = res.get('success', None)
        if s is None:
            s = res.get('status', None)
        if s:
            if not val:
                val = res['object'].id
            elif len(val) > 100:
                val = val[0:100] + "..."
            self.imported[obj.id_] = (imp_type, res['object'].id, val)
            self.updates[res['object'].id] = res['object']
            self.ind2obj.setdefault(ind_id, []).append(obj.id_)
            self.obj2ind[obj.id_] = ind_id
        else:
            if 'reason' in res:
                msg = res['reason']
            elif 'message' in res:
                msg = res['message']
            else:
                msg = "Failed for unknown reason."
            self.failed.append((msg,
                                "%s (%s)" % (imp_type, val),
                                obj.id_)) # note for display in UI

    def has_network_artifact(self, file_obj):
        """
        Determine if the CybOX File object has a related Artifact of
        'Network' type.

        :param file_obj: A CybOX File object
        :return: True if the File has a Network Traffic Artifact
        """
        if not file_obj or not file_obj.parent or not file_obj.parent.related_objects:
            return False
        for obj in file_obj.parent.related_objects: # attempt to find data in cybox
            if isinstance(obj.properties, Artifact) and obj.properties.type_ == Artifact.TYPE_NETWORK:
                return True
        return False

    def relate_objects(self):
        """
        If an Incident was included in the STIX package, its
        related_indicators attribute is used to relate objects to the event.
        Any objects without an explicit relationship to the event are
        related using type "Related_To".

        Objects are related to each other using the relationships listed in
        their related_indicators attribute.
        """
        if self.preview: # Previews don't include relationships
            return

        analyst = self.source_instance.analyst

        # relate objects to Event
        if self.event:
            evt = self.event
            for id_ in self.imported:
                if id_ in self.event_rels:
                    rel_type = self.event_rels[id_][0]
                    confidence = self.event_rels[id_][1]
                elif self.obj2ind.get(id_, '') in self.event_rels:
                    rel_type = self.event_rels[self.obj2ind[id_]][0]
                    confidence = self.event_rels[self.obj2ind[id_]][1]
                elif self.imported[id_][0] != 'Event':
                    rel_type = RelationshipTypes.RELATED_TO
                    confidence='Unknown'
                else:
                    continue
                evt.add_relationship(self.updates[self.imported[id_][1]],
                                     rel_type=rel_type,
                                     rel_confidence=confidence,
                                     analyst=analyst)

            evt.save(username=analyst)

        # relate objects to each other
        for rel in self.relationships:
            for l_id in self.ind2obj.get(rel[0], [rel[0]]):
                for r_id in self.ind2obj.get(rel[2], [rel[2]]):
                    if (l_id in self.imported and r_id in self.imported and
                        l_id != r_id):
                        left = self.updates[self.imported[l_id][1]]
                        right = self.updates[self.imported[r_id][1]]
                        if left != right:
                            left.add_relationship(right,
                                                  rel_type=rel[1],
                                                  rel_confidence=rel[3],
                                                  analyst=analyst)

        # save objects
        for id_ in self.imported:
            self.updates[self.imported[id_][1]].save(username=analyst)
