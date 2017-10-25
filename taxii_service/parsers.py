import datetime
import pytz

from contextlib import closing
from copy import copy
from io import BytesIO
from lxml.etree import XMLSyntaxError

from .object_mapper import (
    make_crits_object,
    get_crits_actor_tags,
    get_crits_ip_type,
    get_crits_event_type
)

from crits.actors.actor import Actor
from crits.actors.handlers import add_new_actor, update_actor_tags
from crits.certificates.handlers import handle_cert_file
from crits.core.data_tools import validate_md5_checksum
from crits.core.data_tools import validate_sha1_checksum, validate_sha256_checksum
from crits.core.user_tools import get_user_info
from crits.domains.handlers import upsert_domain
from crits.emails.handlers import handle_email_fields
from crits.events.handlers import add_new_event
from crits.indicators.indicator import Indicator
from crits.indicators.handlers import handle_indicator_ind
from crits.ips.handlers import ip_add_update
from crits.pcaps.handlers import handle_pcap_file
from crits.raw_data.handlers import handle_raw_data_file
from crits.raw_data.raw_data import RawData, RawDataType
from crits.samples.handlers import handle_file
from crits.signatures.handlers import handle_signature_file
from crits.signatures.signature import Signature
from crits.signatures.signature import SignatureType
from crits.core.crits_mongoengine import EmbeddedSource
from crits.core.handlers import does_source_exist

from crits.vocabulary.acls import (
    CertificateACL,
    EmailACL,
    IndicatorACL,
    PCAPACL,
    RawDataACL,
    SampleACL,
    SignatureACL,
)
from crits.vocabulary.events import EventTypes
from crits.vocabulary.indicators import (
    IndicatorAttackTypes,
    IndicatorThreatTypes,
    IndicatorTypes,
)
from crits.vocabulary.indicators import IndicatorCI
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
from stix.common.related import RelatedTTP
from stix.core import STIXPackage, STIXHeader
import stix.extensions.marking.ais
from stix.extensions.test_mechanism.generic_test_mechanism import GenericTestMechanism
from stix.extensions.test_mechanism.open_ioc_2010_test_mechanism import OpenIOCTestMechanism
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.indicator.indicator import CompositeIndicatorExpression
from stix.threat_actor import ThreatActor
from stix.utils.parser import UnsupportedVersionError

from . import taxii

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

    def __init__(self, data, analyst, method, def_ci=None, preview_only=False):
        """
        Instantiation of the STIXParser can take the data to parse, the analyst
        doing the parsing, and the method of data aquisition.

        :param data: The data to parse.
        :type data: str
        :param analyst: The analyst parsing the document.
        :type analyst: str
        :param method: The method of acquiring this data.
        :type method: str
        :param def_ci: The default Indicator (confidence, impact).
        :type def_ci: tuple
        :param preview_only: If True, nothing is imported and a preview is returned
        :type preview_only: boolean
        """

        self.data = data
        self.def_ci = def_ci or (None, None)
        self.obs_as_ind = False
        self.preview = preview_only

        self.package = None
        self.stix_version = None

        self.source = EmbeddedSource() # source.name comes from the stix header.
        self.source_instance = EmbeddedSource.SourceInstance()
        # The reference attribute and appending it to the source is
        # done after the TAXII message ID is determined.
        self.source_instance.analyst = analyst
        self.source_instance.method = method

        self.pkg_event = None # optional Event TLO relating to all pkg objects
        self.event_rels = {} # track relationships to the event
        self.relationships = [] # track other relationships that need forming
        self.pkg_rels = {} # track relationships between packages, if any
        self.idMap = {} # map child IDs to parent IDs for relationship building
        self.importedByPkg = {} # track which items were imported from which package
        self.imported = {} # track items that are imported
        self.updates = {} # track new/updated CRITs TLOs
        self.parsed = [] # track items that have been parsed, but not necessarily imported
        self.failed = [] # track STIX/CybOX items that failed import
        self.saved_artifacts = {}

    def parse_stix(self, reference='', hdr_events=False, source='',
                   use_hdr_src=False, obs_as_ind=False):
        """
        Parse the document.

        :param reference: The reference to the data.
        :type reference: str
        :param hdr_events: Whether to create an Event for each Package Header.
        :type hdr_events: bool
        :param source: The source of this document.
        :type source: str
        :param use_hdr_src: If True, try to use the STIX Header Information
                             Source instead of the value in "source" parameter
        :type use_hdr_src: boolean
        :param obs_as_ind: If True, create indicators for all qualifying
                           observables instead of Domain and IP TLOs
        :type obs_as_ind: boolean
        :raises: :class:`taxii_service.parsers.STIXParserException`

        Until we have a way to map source strings in a STIX document to
        a source in CRITs, we are being safe and using the source provided
        as the true source.
        """

        self.obs_as_ind = obs_as_ind
        if isinstance(self.data, unicode): # BytesIO requires str
            self.data = self.data.encode('utf-8')
            encoding = 'utf-8'
        else: # String has unknown encoding
            encoding = None
        with closing(BytesIO(self.data)) as f:
            try:
                try:
                    self.package = STIXPackage.from_xml(f, encoding)
                    if not self.package:
                        raise STIXParserException("STIX package failure")
                except UnsupportedVersionError:
                    v = stix.__version__
                    if len(v.split('.')) > 3:
                        v = v[0:-2]
                        if v[-1] == '0':
                            v = v[0:-2]
                    updated = ramrod.update(f, to_=v)
                    doc = updated.document.as_stringio()
                    self.package = STIXPackage.from_xml(doc)
                except XMLSyntaxError:
                    self.package = STIXPackage.from_json(f)
            except Exception as e:
                msg = "Failed to create STIX/CybOX from XML or JSON"
                self.failed.append((e.message,
                                    "STIX Package (%s)" % msg,
                                    '')) # note for display in UI
                return

            # Parse any related packages
            if self.package.related_packages:
                for rel_pkg in self.package.related_packages:
                    pkg = rel_pkg.item
                    self.pkg_rels[pkg.id_] = (str(rel_pkg.relationship),
                                              str(rel_pkg.confidence))
                    self.imported = self.importedByPkg.setdefault(pkg.id_, {})
                    self.parse_package(pkg, reference, hdr_events, source,
                                       use_hdr_src)

            self.imported = self.importedByPkg.setdefault(self.package.id_, {})
            self.parse_package(self.package, reference, hdr_events, source,
                               use_hdr_src) # parse the top-level package
            self.imported = {k: v for d in self.importedByPkg.itervalues() for k, v in d.items()}


    def parse_package(self, package, reference='', hdr_events=False, source='',
                      use_hdr_src=False):
        """
        Parse a STIX package.

        :param package: A STIX package
        :type package: :class:`stix.core.STIXPackage`
        :param reference: The reference to the data.
        :type reference: str
        :param hdr_events: Whether to create an Event for each Package header.
        :type hdr_events: bool
        :param source: The source of this document.
        :type source: str
        :param use_hdr_src: If True, try to use the STIX Header Information
                             Source instead of the value in "source" parameter
        :type use_hdr_src: boolean
        """

        header = package.stix_header
        if not self.preview:
            self.stix_version = package.version
            try:
                hdr_source = header.information_source.identity.name
            except:
                hdr_source = None
            try:
                hdr_ref = ", ".join(header.information_source.references)
            except:
                hdr_ref = None

            # if STIX src is preferred and valid, use it
            if use_hdr_src and hdr_ref:
                reference = hdr_ref # use STIX Header references
            if use_hdr_src and does_source_exist(hdr_source):
                self.source.name = hdr_source # use STIX header source identity
            elif does_source_exist(source): # else use given source if valid
                self.source.name = source
                if hdr_source and source != hdr_source:
                    refs = [reference, "STIX Source: %s" % hdr_source]
                    reference = ", ".join(x for x in refs if x)
            elif does_source_exist(hdr_source): # else use STIX src if valid
                self.source.name = hdr_source
            else: # else error because a valid source is required
                msg = 'No valid source provided ("%s", "%s")'
                raise STIXParserException(msg  % (source, hdr_source))

            self.source_instance.reference = reference
            self.source.instances.append(self.source_instance)

        # If hdr_events is True, add Event based on the STIX_Header,
        # unless this package came from a CRITs instance. Packages generated
        # by CRITs have limited valuable header data.
        # This event will have relationships to everything in the STIX Package
        if hdr_events:
            title = "STIX Package %s" % package.id_
            event_type = None
            event_date = datetime.datetime.now()
            description = ""
            is_from_crits = False
            if isinstance(header, STIXHeader):
                if header.title == "CRITs Generated STIX Package":
                    is_from_crits = True
                else:
                    title = header.title or title
                    if header.package_intents:
                        try:
                            intent = str(header.package_intents[0])
                            event_type = get_crits_event_type(intent)
                        except:
                            pass
                    info_src = header.information_source
                    if (info_src and info_src.time
                        and info_src.time.produced_time):
                        event_date = info_src.time.produced_time.value
                        if event_date.tzinfo:
                            event_date = event_date.astimezone(pytz.utc)
                            event_date = event_date.replace(tzinfo=None)
                    description = getattr(header.description, 'value', "")

            if self.preview and not is_from_crits:
                self.imported[package.id_] = ('Event', None, title)
            elif not is_from_crits:
                res = add_new_event(title,
                                    description,
                                    event_type or EventTypes.INTEL_SHARING,
                                    self.source.name,
                                    self.source_instance.method,
                                    self.source_instance.reference,
                                    event_date,
                                    self.source_instance.analyst)
                self.parsed.append(package.id_)
                if res['success']:
                    self.pkg_event = res['object']
                    self.imported[package.id_] = ('Event',
                                                  res['object'].id, title)
                    self.updates[res['object'].id] = res['object']
                else:
                    self.failed.append((res['message'],
                                        "Event (%s)" % title,
                                        package.id_))

        if package.indicators:
            self.parse_indicators(package.indicators)

        if package.observables and package.observables.observables:
            self.parse_observables(package.observables.observables,
                                   is_ind=self.obs_as_ind)

        if package.threat_actors:
            self.parse_threat_actors(package.threat_actors)

        if package.ttps:
            self.parse_ttps(package.ttps)

        if package.incidents:
            self.parse_incidents(package.incidents)

    def parse_incidents(self, incidents):
        """
        Parse list of Incidents.

        :param incidents: List of STIX Incidents.
        :type incidents: list
        """
        for incident in incidents:
            if incident.title:
                title = incident.title
            else:
                title = "STIX Incident: %s" % incident.id_
            description = str(incident.description or "")
            if incident.short_description in EventTypes.values():
                event_type = incident.short_description
            elif incident.categories and incident.categories[0].value:
                event_type = get_crits_event_type(incident.categories[0].value)
            else:
                event_type = EventTypes.INTEL_SHARING
            if getattr(incident.time, 'incident_discovery', None):
                event_date = incident.time.incident_discovery.value
            elif getattr(incident.time, 'incident_reported', None):
                event_date = incident.time.incident_reported.value
            else:
                event_date = datetime.datetime.now()
            if event_date.tzinfo:
                event_date = event_date.astimezone(pytz.utc)
                event_date = event_date.replace(tzinfo=None)

        if self.preview:
            self.imported[incident.id_] = ('Event', None, title)
            for rel in incident.related_indicators or ():
                if rel.item.id_:
                    self.parse_indicators([rel.item])
            for rel in incident.related_observables or ():
                if rel.item.id_:
                    self.parse_observables([rel.item], is_ind=self.obs_as_ind)
        else:
            res = add_new_event(title,
                                description,
                                event_type,
                                self.source.name,
                                self.source_instance.method,
                                self.source_instance.reference,
                                event_date,
                                self.source_instance.analyst)
            self.parsed.append(incident.id_)
            if res['success']:
                self.imported[incident.id_] = ('Event',
                                               res['object'].id, title)
                self.updates[res['object'].id] = res['object']

                # Get relationships to the Event
                for rel in incident.related_indicators or ():
                    r = rel.relationship or RelationshipTypes.RELATED_TO
                    c = getattr(rel.confidence, 'value', None) or 'Unknown'
                    if rel.item.id_:
                        self.parse_indicators([rel.item])
                        ind_idref = rel.item.id_
                    else:
                        ind_idref = rel.item.idref
                    for ind_id in self.idMap.get(ind_idref, [ind_idref]):
                        self.relationships.append((incident.id_, str(r),
                                                   ind_id, str(c)))
                for rel in incident.related_observables or ():
                    r = rel.relationship or RelationshipTypes.RELATED_TO
                    c = getattr(rel.confidence, 'value', None) or 'Unknown'
                    if rel.item.id_:
                        self.parse_observables([rel.item],
                                               is_ind=self.obs_as_ind)
                        obs_idref = rel.item.id_
                    else:
                        obs_idref = rel.item.idref
                    for obs_id in self.idMap.get(obs_idref, [obs_idref]):
                        self.relationships.append((incident.id_, str(r),
                                                   obs_id, str(c)))
            else:
                self.failed.append((res['message'],
                                    "Event (%s)" % title,
                                    incident.id_))

    def parse_ttps(self, ttps):
        """
        Parse list of TTPs. This is not currently supported by CRITs
        because it isn't clear where this data should go.

        :param ttps: List of STIX TTPs.
        :type ttps: list
        """
        for ttp in ttps:
            if isinstance(ttp, RelatedTTP):
                ttp = ttp.item
            title = getattr(ttp, "title", "")
            id_ = ttp.id_ or ttp.idref
            self.failed.append(("STIX TTPs are not currently supported",
                                "TTP (%s)" % (title or id_),
                                id_))

    def parse_threat_actors(self, threat_actors):
        """
        Parse list of Threat Actors.

        :param threat_actors: List of STIX ThreatActors.
        :type threat_actors: List of STIX ThreatActors.
        """
        analyst = self.source_instance.analyst
        for threat_actor in threat_actors: # for each STIX ThreatActor
            try: # create CRITs Actor from ThreatActor
                if isinstance(threat_actor, ThreatActor):
                    name = str(threat_actor.title)
                    if not self.preview:
                        description = threat_actor.description
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
                        else: #failed
                            self.failed.append((res['message'],
                                                "Threat Actor (%s)" % name,
                                                threat_actor.id_)) # note for display in UI

                    else: #preview_only
                        self.imported[threat_actor.id_] = (Actor._meta['crits_type'],
                                                           None, name)
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
                    for stix_ind_type in indicator.indicator_types:
                        p_description += ('STIX Indicator Type: ' +
                                          stix_ind_type.value + '\n')
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
                        if com_ind.id_ in self.idMap:
                            rel_ids.extend(self.idMap.pop(com_ind.id_))
                        else:
                            rel_ids.append(com_ind.id_)
                self.idMap.setdefault(indicator.id_, []).extend(rel_ids)

                # This is the top level, so form relationships
                if not isinstance(indicators, CompositeIndicatorExpression):
                    for iid in rel_ids:
                        for iid2 in rel_ids:
                            if iid != iid2:
                                self.relationships.append((iid,
                                                           RelationshipTypes.RELATED_TO,
                                                           iid2, "High"))
                continue

            # store relationships
            if not self.preview:
                for rel in getattr(indicator, 'related_indicators', ()) or ():
                    if rel.confidence:
                        conf = rel.confidence.value.value
                    else:
                        conf = 'Unknown'
                    self.relationships.append((indicator.id_,
                                               rel.relationship.value,
                                               rel.item.idref,
                                               conf))

            try: # create CRITs Indicator from observable
                description = [parent_description]
                # handled indicator-wrapped observable
                if getattr(indicator, 'title', ""):
                    if "Top-Level Object" in indicator.title:
                        self.parse_observables(indicator.observables,
                                               ind_id=indicator.id_)
                        continue
                    elif indicator.title:
                        title = indicator.title
                        description.append('STIX Indicator Title: %s' % title)
                if indicator.indicator_types and indicator.indicator_types[0]:
                    itype = indicator.indicator_types[0]
                    description.append('STIX Indicator Type: %s' % itype)
                if indicator.description:
                    desc = indicator.description
                    description.append('STIX Indicator Description: %s' % desc)
                description = '\n'.join(x for x in description if x)

                ci_vals = IndicatorCI.values()
                if (indicator.confidence
                    and indicator.confidence.value.value.lower() in ci_vals):
                    conf = indicator.confidence.value.value.lower()
                else:
                    conf = self.def_ci[0]
                if (indicator.likely_impact
                    and indicator.likely_impact.value.value.lower() in ci_vals):
                    impact = indicator.likely_impact.value.value.lower()
                else:
                    impact = self.def_ci[1]

                self.parse_observables(indicator.observables, description,
                                       True, indicator.id_, (conf, impact))

            except Exception as e:
                self.failed.append((e.message or str(e),
                                    "Indicator (%s)" % indicator.id_,
                                    indicator.id_)) # note for display in UI

            if indicator.indicated_ttps: # These aren't currently supported
                self.parse_ttps(indicator.indicated_ttps)

            if indicator.test_mechanisms:
                for tmech in indicator.test_mechanisms:
                    if isinstance(tmech, GenericTestMechanism):
                        kind = 'GENERIC'
                    elif isinstance (tmech, OpenIOCTestMechanism):
                        kind = 'OPEN IOC'
                    elif isinstance (tmech, SnortTestMechanism):
                        kind = 'SNORT'
                    elif isinstance (tmech, YaraTestMechanism):
                        kind = 'YARA'

                    ref = ', '.join(tmech.producer.references)

                    for rule in tmech.rules:
                        if not self.preview and user.has_access_to(SignatureACL.WRITE):
                            analyst = self.source_instance.analyst
                            res = handle_signature_file(str(rule),
                                                        self.source.name,
                                                        analyst,
                                                        title=tmech.id_,
                                                        data_type=kind.title(),
                                                        method='STIX Import',
                                                        reference=ref)
                            self.parsed.append(tmech.id_)
                            if res['success']:
                                oid = res['_id']
                                self.updates[oid] = res['object']
                                self.imported[tmech.id_] = (Signature._meta['crits_type'],
                                                            oid, "%s - %s" % (kind, rule))
                                self.relationships.append((tmech.id_,
                                                           RelationshipTypes.RELATED_TO,
                                                           indicator.id_, "High"))
                            elif 'Invalid data type' in res['message']:
                                msg = 'Add new Signature Type "%s" and try again'
                                self.failed.append((msg % kind.title(),
                                                    "Signature (%s)" % tmech.id_,
                                                    tmech.id_)) # note for display in UI
                            else:
                                self.failed.append((res['message'],
                                                    "Signature (%s)" % tmech.id_,
                                                    tmech.id_)) # note for display in UI
                        else: # preview only
                            stype = SignatureType.objects(name=kind.title()).first()
                            if not stype:
                                 msg = 'Add new Signature Type "%s" and try again'
                                 self.failed.append((msg % kind.title(),
                                                    "Signature (%s)" % tmech.id_,
                                                    tmech.id_)) # note for display in UI
                            else:
                                self.imported[tmech.id_] = (Signature._meta['crits_type'],
                                                            None, "%s - %s" % (kind, rule))

    def parse_observables(self, observables, description='',
                          is_ind=False, ind_id=None, ind_ci=None):
        """
        Parse list of observables in STIX doc.

        :param observables: List of STIX observables.
        :type observables: List of STIX observables.
        :param description: Parent-level (e.g. Indicator) description.
        :type description: str
        :param is_ind: Whether the observable is actually an Indicator
        :type is_ind: boolean
        :param ind_id: The ID of a parent STIX Indicator.
        :type ind_id: str
        :param ind_ci: The (confidence, impact) of a parent STIX Indicator.
        :type ind_ci: tuple
        """

        for ob in observables: # for each STIX observable
            p_id = ind_id or ob.id_ # use Indicator ID if given, otherwise Observable ID
            if not ob.object_:
                if ob.idref: # query saved TAXII content for referenced ID
                    txC = taxii.TaxiiContent
                    refQ = 'id="' + ob.idref
                    xmlblock = txC.objects(content__contains=refQ).first()
                    if xmlblock:
                        if isinstance(xmlblock.content, unicode): # BytesIO requires str
                            xmlblock.content = xmlblock.content.encode('utf-8')
                            encoding = 'utf-8'
                        else: # String has unknown encoding
                            encoding = None
                        with closing(BytesIO(xmlblock.content)) as f:
                            ref_pkg = STIXPackage.from_xml(f, encoding)
                        if 'Observable' in ob.idref:
                            self.parse_observables(ref_pkg.observables.observables,
                                                   description, is_ind, p_id, ind_ci)

                            if self.preview: # no need to store relationship if just a preview
                                continue

                            if ref_pkg.observables.observables[0].object_:
                                cbxid = ref_pkg.observables.observables[0].object_.id_
                                self.idMap.setdefault(ob.idref, []).append(cbxid)
                            elif ref_pkg.observables.observables[0].idref in self.idMap:
                                subref = ref_pkg.observables.observables[0].idref
                                self.idMap.setdefault(ob.idref, []).extend(self.idMap.pop(subref))
                    continue

                elif ob.observable_composition: # parse observable composition.
                    # CRITs doesn't support complex boolean relationships like
                    # ((A OR B) AND C). This code simply imports all observables
                    # and forms "Related_To" relationships between them
                    self.parse_observables(ob.observable_composition.observables,
                                           description, is_ind, p_id, ind_ci)
                    rel_ids = []

                    if self.preview: # no need to store relationship if just a preview
                        continue

                    for com_ob in ob.observable_composition.observables:
                        if com_ob.object_:
                            rel_ids.append(com_ob.object_.id_)
                        else:
                            xid = com_ob.id_ or com_ob.idref
                            if xid in self.idMap:
                                rel_ids.extend(self.idMap.pop(xid))
                            else:
                                rel_ids.append(xid)
                    if len(observables) > 1:
                        self.idMap.setdefault(ob.id_, []).extend(rel_ids)
                    else: # This is the top level, so form relationships
                        for oid in rel_ids:
                            for oid2 in rel_ids:
                                if oid != oid2:
                                    self.relationships.append((oid,
                                                               RelationshipTypes.RELATED_TO,
                                                               oid2, "High"))
                    continue

                self.failed.append(("No valid CybOX object_ or refid found!",
                                    "Observable (%s)" % ob.id_,
                                    ob.id_)) # note for display in UI
                continue

            description = [description]
            if ob.title:
                description.append('STIX Observable Title: %s' % ob.title)
            if ob.description:
                description.append('STIX Observable Description: %s' % ob.description)
            description = '\n'.join(x for x in description if x)
            self.parse_cybox_object(ob.object_, description, is_ind, p_id, ind_ci)


    def parse_cybox_object(self, cbx_obj, description='',
                           is_ind=False, p_id=None, ind_ci=None):
        """
        Parse a CybOX object form a STIX doc. An object can contain
        multiple related_objects, which in turn can have their own
        related_objects, so this handles those recursively.

        :param cbx_obj: The CybOX object to parse.
        :type cbx_obj: A CybOX object.
        :param description: Parent-level (e.g. Observable) description.
        :type description: str
        :param is_ind: Whether the observable is actually an Indicator
        :type is_ind: boolean
        :param p_id: The ID of a parent STIX Indicator or Observable.
        :type p_id: str
        :param ind_ci: The (confidence, impact) of a parent STIX Indicator.
        :type ind_ci: tuple
        """

        # Convert description to unicode if str
        if isinstance(description, str):
            description = description.decode('utf-8')

        # Setup indicator confidence/impact
        if not ind_ci: # if not provided, use defaults
            ind_ci = self.def_ci

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
            user = get_user_info(analyst)
            item = cbx_obj.properties
            val = cbx_obj.id_
            if isinstance(item, Address) and not is_ind:
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
                                                    description=description)
                            else:
                                res = {'success': False, 'reason': 'No IP Type'}
                        self.parse_res(imp_type, val, cbx_obj, res, p_id)
            if (not is_ind and (isinstance(item, DomainName) or
                (isinstance(item, URI) and item.type_ == 'Domain Name'))):
                imp_type = "Domain"
                for val in item.value.values:
                    if self.preview:
                        res = None
                    else:
                        res = upsert_domain(str(val),
                                            [self.source],
                                            username=analyst)
                    self.parse_res(imp_type, str(val), cbx_obj, res, p_id)

            elif isinstance(item, HTTPSession):
                imp_type = "RawData"
                dtype = "HTTP Header"
                val = cbx_obj.id_
                try:
                    c_req = item.http_request_response[0].http_client_request
                    hdr = c_req.http_request_header
                    if hdr.raw_header:
                        data = hdr.raw_header.value
                        title = "HTTP Header from STIX: %s" % self.package.id_
                        method = self.source_instance.method
                        ref = self.source_instance.reference
                        if self.preview or not user.has_access_to(RawDataACL.WRITE):
                            res = None
                            val = title
                            rdtype = RawDataType.objects(name=dtype).first()
                            if not rdtype:
                                msg = 'Add Raw Data Type "%s" and try again'
                                res = {'success': False, 'message': msg % dtype}
                        else:
                            res = handle_raw_data_file(data,
                                                    self.source.name,
                                                    user=analyst,
                                                    description=description,
                                                    title=title,
                                                    data_type=dtype,
                                                    tool_name="STIX",
                                                    tool_version=None,
                                                    method=method,
                                                    reference=ref)
                            if not res['success']:
                                if "Invalid data type" in res['message']:
                                    msg = 'Add Raw Data Type "%s" and try again'
                                    res['message'] = msg % dtype
                    else:
                        imp_type = "Indicator"
                        ind_type = IndicatorTypes.USER_AGENT
                        val = hdr.parsed_header.user_agent.value
                        val = ','.join(val) if isinstance(val, list) else val
                        if self.preview or not user.has_access_to(IndicatorACL.WRITE):
                            res = None
                            val = "%s - %s" % (ind_type, val)
                        else:
                            res = handle_indicator_ind(val,
                                                    self.source,
                                                    ind_type,
                                                    IndicatorThreatTypes.UNKNOWN,
                                                    IndicatorAttackTypes.UNKNOWN,
                                                    analyst,
                                                    add_relationship=True,
                                                    description=description,
                                                    confidence=ind_ci[0],
                                                    impact=ind_ci[1])
                except:
                    msg = "Unsupported use of 'HTTPSession' object."
                    res = {'success': False, 'reason': msg}

                self.parse_res(imp_type, val, cbx_obj, res, p_id)
            elif isinstance(item, WhoisEntry):
                # No sure where else to put this
                imp_type = "RawData"
                dtype = "Text"
                val = cbx_obj.id_
                if item.remarks:
                    data = item.remarks.value
                    title = "WHOIS Entry from STIX: %s" % self.package.id_
                    if self.preview or not user.has_access_to(RawDataACL.WRITE):
                        res = None
                        val = title
                        rdtype = RawDataType.objects(name=dtype).first()
                        if not rdtype:
                            msg = 'Add Raw Data Type "%s" and try again'
                            res = {'success': False, 'message': msg % dtype}
                    else:
                        res = handle_raw_data_file(data,
                                                self.source.name,
                                                user=analyst,
                                                description=description,
                                                title=title,
                                                data_type=dtype,
                                                tool_name="WHOIS",
                                                tool_version=None,
                                                method=self.source_instance.method,
                                                reference=self.source_instance.reference)
                        if not res['success']:
                            if "Invalid data type" in res['message']:
                                msg = 'Add Raw Data Type "%s" and try again'
                                res['message'] = msg % dtype
                else:
                    msg = "Unsupported use of 'WhoisEntry' object."
                    res = {'success': False, 'reason': msg}

                self.parse_res(imp_type, val, cbx_obj, res, p_id)
            elif isinstance(item, Artifact):
                # Not sure if this is right, and I believe these can be
                # encoded in a couple different ways.
                imp_type = "RawData"
                dtype = "Text"
                val = cbx_obj.id_
                rawdata = item.data.decode('utf-8')
                # TODO: find out proper ways to determine title, datatype,
                #       tool_name, tool_version
                title = "Artifact for Event: STIX Document %s" % self.package.id_
                if self.preview or not user.has_access_to(RawDataACL.WRITE):
                    res = None
                    val = title
                    rdtype = RawDataType.objects(name=dtype).first()
                    if not rdtype:
                        msg = 'Add Raw Data Type "%s" and try again'
                        res = {'success': False, 'message': msg % dtype}
                else:
                    res = handle_raw_data_file(rawdata,
                                            self.source.name,
                                            user=analyst,
                                            description=description,
                                            title=title,
                                            data_type=dtype,
                                            tool_name="STIX",
                                            tool_version=None,
                                            method=self.source_instance.method,
                                            reference=self.source_instance.reference)
                    if not res['success']:
                        if "Invalid data type" in res['message']:
                            msg = 'Add Raw Data Type "%s" and try again'
                            res['message'] = msg % dtype
                self.parse_res(imp_type, val, cbx_obj, res, p_id)
            elif (isinstance(item, File) and
                  item.custom_properties and
                  item.custom_properties[0].name == "crits_type" and
                  item.custom_properties[0]._value == "Certificate"):
                imp_type = "Certificate"
                val = str(item.file_name)
                data = None
                if self.preview or not user.has_access_to(CertificateACL.WRITE):
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
                self.parse_res(imp_type, val, cbx_obj, res, p_id)
            elif isinstance(item, File) and self.has_network_artifact(item):
                imp_type = "PCAP"
                val = str(item.file_name)
                data = None
                if self.preview or not user.has_access_to(PCAPACL.WRITE):
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
                self.parse_res(imp_type, val, cbx_obj, res, p_id)
            elif isinstance(item, File):
                imp_type = "Sample"
                md5 = item.md5
                if md5:
                    md5 = md5.lower()
                    validate_md5_result = validate_md5_checksum(md5)
                    if validate_md5_result.get('success', False) is False:
                        md5 = None
                sha1 = item.sha1
                if sha1:
                    sha1 = sha1.lower()
                    validate_sha1_result = validate_sha1_checksum(sha1)
                    if validate_sha1_result.get('success', False) is False:
                        sha1 = None
                sha256 = item.sha256
                if sha256:
                    sha256 = sha256.lower()
                    if len(sha256) == 63:
                        sha256 = "0" + sha256
                    validate_sha256_result = validate_sha256_checksum(sha256)
                    if validate_sha256_result.get('success', False) is False:
                        sha256 = None
                ssdeep = getattr(item, 'ssdeep', None) # Not supported yet
                if not ssdeep: # so see if we can find it
                    try:
                        for h in item.hashes.hashes:
                            if h.type_ == 'SSDEEP':
                                ssdeep = str(h.fuzzy_hash_value)
                    except:
                        pass

                fname = None
                if item.file_name is not None:
                    fname = str(item.file_name)
                size = item.size_in_bytes
                data = None
                if item.file_path: # save the path in the description field
                    path = "File Path: " + str(item.file_path)
                    description += "\n" + path
                for rel_obj in item.parent.related_objects or ():
                    if (isinstance(rel_obj.properties, Artifact) and
                        rel_obj.properties.type_ == Artifact.TYPE_FILE):
                        data = rel_obj.properties.data
                        self.parsed.append(rel_obj.id_)
                if not (md5 or data) and (fname or sha1 or sha256 or ssdeep): # Can't create a Sample
                    imp_type = "Indicator"
                    for indt, indv in ((IndicatorTypes.FILE_NAME, fname),
                                       (IndicatorTypes.SHA1, sha1),
                                       (IndicatorTypes.SHA256, sha256),
                                       (IndicatorTypes.SSDEEP, ssdeep)):
                        if indv:
                            if self.preview:
                                res = None
                                indv = "%s - %s" % (indt, indv)
                            else:
                                res = handle_indicator_ind(indv,
                                                  self.source,
                                                  indt,
                                                  IndicatorThreatTypes.UNKNOWN,
                                                  IndicatorAttackTypes.UNKNOWN,
                                                  analyst,
                                                  description=description,
                                                  confidence=ind_ci[0],
                                                  impact=ind_ci[1])
                            self.parse_res(imp_type, indv, cbx_obj, res, p_id)
                elif md5 or data: # Can create a Sample
                    val = fname or md5
                    if self.preview:
                        res = None
                        if fname:
                            val = "%s (%s)" % (md5, fname)
                    elif user.has_access_to(SampleACL.WRITE):
                        res = handle_file(val,
                                          data,
                                          self.source,
                                          user=analyst,
                                          md5_digest=md5,
                                          sha1_digest = sha1,
                                          sha256_digest = sha256,
                                          is_return_only_md5=False,
                                          size=size,
                                          description=description)
                    self.parse_res(imp_type, val, cbx_obj, res, p_id)
                else: # Can't do anything with this object
                    val = cbx_obj.id_
                    msg = "CybOX 'File' object has no hashes, data, or filename"
                    res = {'success': False, 'reason': msg}
                    self.parse_res(imp_type, None, cbx_obj, res, p_id)
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
                    if self.preview or user.has_access_to(EmailACL.WRITE):
                        res = None
                    else:
                        res = handle_email_fields(data,
                                                  analyst,
                                                  "STIX")
                    self.parse_res(imp_type, val, cbx_obj, res, p_id)
                    if not self.preview and res.get('status'):
                        id_list.append(cbx_obj.id_) # save ID for atchmnt rels
                        get_attach = True
                else: # Can't be an Email TLO, so save fields
                    for x, key in enumerate(data):
                        if data[key] and data[key] != "None":
                            if key in ('raw_header', 'raw_body'):
                                if key == 'raw_header':
                                    title = "Email Header from STIX Email: %s"
                                    dtype = "Email Header"
                                else:
                                    title = "Email Body from STIX Email: %s"
                                    dtype = "Email Body"
                                imp_type = 'RawData'
                                title = title % cbx_obj.id_
                                if self.preview or not user.has_access_to(RawDataACL.WRITE):
                                    res = None
                                    rdtype = RawDataType.objects(name=dtype)
                                    rdtype = rdtype.first()
                                    if not rdtype:
                                        msg = ('Add Raw Data Type "%s" and try'
                                               ' again')
                                        res = {'success': False,
                                               'message': msg % dtype}
                                else:
                                    res = handle_raw_data_file(data[key],
                                                               self.source,
                                                               analyst,
                                                               description,
                                                               title,
                                                               dtype,
                                                               "STIX",
                                                               self.stix_version)
                                    if not res['success']:
                                        if "Invalid data ty" in res['message']:
                                            msg = ('Add Raw Data Type "%s" and'
                                                   ' try again')
                                            res['message'] = msg % dtype
                                self.parse_res(imp_type, title, cbx_obj,
                                               res, p_id)
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
                                                   res, p_id)
                                    self.idMap.setdefault(cbx_obj.id_,
                                                            []).append(tmp_obj.id_)
                                    id_list.append(tmp_obj.id_)
                            else:
                                imp_type = 'Indicator'
                                if 'reply_to' in key:
                                    ind_type = IndicatorTypes.EMAIL_REPLY_TO
                                elif 'sender' in key:
                                    ind_type = IndicatorTypes.EMAIL_SENDER
                                elif 'from_address' in key:
                                    ind_type = IndicatorTypes.EMAIL_FROM
                                elif 'subject' in key:
                                    ind_type = IndicatorTypes.EMAIL_SUBJECT
                                elif 'x_mailer' in key:
                                    ind_type = IndicatorTypes.EMAIL_X_MAILER
                                elif 'message_id' in key:
                                    ind_type = IndicatorTypes.EMAIL_MESSAGE_ID
                                else:
                                    msg = 'No Indicator type for email field "%s"'
                                    self.failed.append((msg % key,
                                                        "%s (%s)" % (imp_type,
                                                                     data[key]),
                                                        None))
                                    continue
                                if self.preview or not user.has_access_to(IndicatorACL.WRITE):
                                    res = None
                                    data[key] = "%s - %s" % (ind_type,
                                                             data[key])
                                else:
                                    res = handle_indicator_ind(data[key],
                                                          self.source,
                                                          ind_type,
                                                          IndicatorThreatTypes.UNKNOWN,
                                                          IndicatorAttackTypes.UNKNOWN,
                                                          analyst,
                                                          add_domain=True,
                                                          add_relationship=True,
                                                          description=description,
                                                          confidence=ind_ci[0],
                                                          impact=ind_ci[1])
                                    if res['success']:
                                        get_attach = True
                                tmp_obj = copy(cbx_obj)
                                tmp_obj.id_ = '%s-%s' % (cbx_obj.id_, x)
                                self.parse_res(imp_type, data[key], tmp_obj,
                                               res, p_id)
                                self.idMap.setdefault(cbx_obj.id_,
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

                # Ignore what was already caught above and check for ind_type
                if ((is_ind or c_obj.object_type not in IPTypes.values())
                    and c_obj.object_type):
                    ind_type = c_obj.object_type
                    for val in c_obj.value:
                        if isinstance(val, int):
                            val = unicode(val)
                        elif not val: # skip empty strings
                            continue
                        else:
                            val = val.strip()

                        # handle URIs mislabeled as Domains
                        if (c_obj.object_type == 'Domain'
                            and ('/' in val or ':' in val)):
                            ind_type = "URI"

                        if self.preview or not user.has_access_to(IndicatorACL.WRITE):
                            res = None
                            val = "%s - %s" % (ind_type, val)
                        else:
                            res = handle_indicator_ind(val,
                                                    self.source,
                                                    ind_type,
                                                    IndicatorThreatTypes.UNKNOWN,
                                                    IndicatorAttackTypes.UNKNOWN,
                                                    analyst,
                                                    add_domain=True,
                                                    add_relationship=True,
                                                    description=description,
                                                    confidence=ind_ci[0],
                                                    impact=ind_ci[1])
                        self.parse_res(imp_type, val, cbx_obj, res, p_id)

        except Exception as e: # probably caused by cybox object we don't handle
            self.failed.append((e.message or str(e),
                                "%s (%s)" % (imp_type, val),
                                cbx_obj.id_)) # note for display in UI

        # parse any related CybOX object(s)
        for rel_obj in cbx_obj.related_objects or ():
            self.parse_cybox_object(rel_obj, description, is_ind, p_id, ind_ci)
            self.relationships.append((cbx_obj.id_, rel_obj.relationship.value,
                                       rel_obj.id_ or rel_obj.idref, "High"))


    def parse_res(self, imp_type, val, obj, res, p_id=None):
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
            self.idMap.setdefault(p_id, []).append(obj.id_)
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
        valid_rel_types = RelationshipTypes.values()

        # If package-level Events exists, relate TLOs to them
        if self.pkg_event:
            evt = self.pkg_event
            for pkg_id, imported in self.importedByPkg.iteritems():
                sub_pkg = self.updates[self.imported[pkg_id][1]]
                if pkg_id in self.pkg_rels: # Use provided relationship data if available
                    rel_type = self.pkg_rels[pkg_id][0]
                    if rel_type not in valid_rel_types:
                        rel_type = RelationshipTypes.RELATED_TO
                    confidence = self.pkg_rels[pkg_id][1]
                else:
                    rel_type = RelationshipTypes.RELATED_TO
                    confidence='Unknown'
                for tlo_meta in imported.itervalues():
                    evt.add_relationship(self.updates[tlo_meta[1]],
                                         rel_type=rel_type,
                                         rel_confidence=confidence,
                                         analyst=analyst)
                    sub_pkg.add_relationship(self.updates[tlo_meta[1]],
                                             rel_type=RelationshipTypes.RELATED_TO,
                                             rel_confidence='Unknown',
                                             analyst=analyst)
                sub_pkg.save(username=analyst)
            evt.save(username=analyst)

        # relate objects to each other
        for rel in self.relationships:
            for l_id in self.idMap.get(rel[0], [rel[0]]):
                for r_id in self.idMap.get(rel[2], [rel[2]]):
                    if (l_id in self.imported and r_id in self.imported and
                        l_id != r_id):
                        left = self.updates[self.imported[l_id][1]]
                        right = self.updates[self.imported[r_id][1]]
                        if left != right:
                            rel_type = rel[1]
                            if rel_type not in valid_rel_types:
                                rel_type = RelationshipTypes.RELATED_TO
                            left.add_relationship(right,
                                                  rel_type=rel_type,
                                                  rel_confidence=rel[3],
                                                  analyst=analyst)

        # save objects
        for id_ in self.imported:
            self.updates[self.imported[id_][1]].save(username=analyst)
