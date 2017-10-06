from crits.core.crits_mongoengine import EmbeddedObject
from crits.vocabulary.indicators import IndicatorTypes
from crits.vocabulary.ips import IPTypes
from crits.vocabulary.events import EventTypes
from crits.vocabulary.actors import (
    ThreatTypes,
    Sophistications,
    Motivations,
    IntendedEffects
)

from cybox.common import String, PositiveInteger

from cybox.objects.account_object import Account
from cybox.objects.address_object import Address
from cybox.objects.api_object import API
from cybox.objects.domain_name_object import DomainName
from cybox.objects.http_session_object import HTTPRequestHeaderFields
from cybox.objects.mutex_object import Mutex
from cybox.objects.port_object import Port
from cybox.objects.process_object import Process
from cybox.objects.uri_object import URI
from cybox.objects.win_registry_key_object import WinRegistryKey

from stix.common.vocabs import IncidentCategory, PackageIntent

class UnsupportedCybOXObjectTypeError(Exception):
    """
    Exception to return if we've detected an unknown CybOX object type.
    """

    def __init__(self, type_, **kwargs):
        self.message = ('"%s" is currently unsupported'
                        ' for output to CybOX.' % type_)

    def __str__(self):
        return repr(self.message)

class UnsupportedCRITsObjectTypeError(Exception):
    """
    Exception to return if we've detected an unknown CRITs object type.
    """

    def __init__(self, cybox_obj, **kwargs):
        self.message = ('"%s" is currently unsupported'
                   " for input into CRITs." % (type(cybox_obj).__name__))

    def __str__(self):
        return repr(self.message)

def get_object_values(obj):
    try:
        return obj.values
    except:
        return [obj.value]

def get_crits_ip_type(type_):
    if type_ == 'ipv4-addr':
        return IPTypes.IPV4_ADDRESS
    elif type_ == 'ipv6-addr':
        return IPTypes.IPV6_ADDRESS
    elif type_ == 'ipv4-net':
        return IPTypes.IPV4_SUBNET
    elif type_ == 'ipv6-net':
        return IPTypes.IPV6_SUBNET
    else:
        return None

def get_crits_event_type(category):
    """
    Converts a STIX Incident Category or Package Intent to a CRITs Event Type.

    :param category: A STIX Incident Category or Package Intent
    :type category: str
    :returns: CRITs Event Type (str)
    """
    if category == IncidentCategory.TERM_DENIAL_OF_SERVICE:
        return EventTypes.DENIAL_OF_SERVICE
    elif category == IncidentCategory.TERM_EXERCISEORNETWORK_DEFENSE_TESTING:
        return EventTypes.UNKNOWN
    elif category == IncidentCategory.TERM_IMPROPER_USAGE:
        return EventTypes.EXPLOITATION
    elif category == IncidentCategory.TERM_INVESTIGATION:
        return EventTypes.INTEL_SHARING
    elif category == IncidentCategory.TERM_MALICIOUS_CODE:
        return EventTypes.MALICIOUS_CODE
    elif category == IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS:
        return EventTypes.SCANNING
    elif category == IncidentCategory.TERM_UNAUTHORIZED_ACCESS:
        return EventTypes.UNAUTHORIZED_INFORMATION_ACCESS

    elif category == PackageIntent.TERM_EXPLOIT_CHARACTERIZATION:
        return EventTypes.EXPLOITATION
    elif category == PackageIntent.TERM_INDICATORS_MALWARE_ARTIFACTS:
        return EventTypes.MALICIOUS_CODE
    elif category == PackageIntent.TERM_INDICATORS_PHISHING:
        return EventTypes.PHISHING
    elif category == PackageIntent.TERM_MALWARE_CHARACTERIZATION:
        return EventTypes.MALICIOUS_CODE
    elif category == PackageIntent.TERM_MALWARE_SAMPLES:
        return EventTypes.MALICIOUS_CODE
    elif category in PackageIntent.values():
        return EventTypes.INTEL_SHARING

def get_crits_actor_tags(type_):
    if type_ == "Innovator":
        return Sophistications.INNOVATOR
    elif type_ == "Expert":
        return Sophistications.EXPERT
    elif type_ == "Practitioner":
        return Sophistications.PRACTITIONER
    elif type_ == "Novice":
        return Sophistications.NOVICE
    elif type_ == "Aspirant":
        return Sophistications.ASPIRANT
    elif type_ == "Ideological - Anti-Corruption":
        return Motivations.ANTI_CORRUPTION
    elif type_ == "Ideological - Anti-Establishment":
        return Motivations.ANTI_ESTABLISHMENT
    elif type_ == "Ideological - Environmental":
        return Motivations.ENVIRONMENTAL
    elif type_ == "Ideological - Ethnic / Nationalist":
        return Motivations.ETHNIC_NATIONALIST
    elif type_ == "Ideological - Information Freedom":
        return Motivations.INFORMATION_FREEDOM
    elif type_ == "Ideological - Religious":
        return Motivations.RELIGIOUS
    elif type_ == "Ideological - Security Awareness":
        return Motivations.SECURITY_AWARENESS
    elif type_ == "Ideological - Human Rights":
        return Motivations.HUMAN_RIGHTS
    elif type_ == "Ego":
        return Motivations.EGO
    elif type_ == "Financial or Economic":
        return Motivations.FINANCIAL_OR_ECONOMIC
    elif type_ == "Military":
        return Motivations.MILITARY
    elif type_ == "Opportunistic":
        return Motivations.OPPORTUNISTIC
    elif type_ == "Political":
        return Motivations.POLITICAL
    elif type_ == "Advantage - Economic":
        return IntendedEffects.ECONOMIC
    elif type_ == "Advantage - Military":
        return IntendedEffects.MILITARY
    elif type_ == "Advantage - Political":
        return IntendedEffects.POLITICAL
    elif type_ == "Theft - Intellectual Property":
        return IntendedEffects.INTELLECTUAL_PROPERTY
    elif type_ == "Theft - Credential Theft":
        return IntendedEffects.CREDENTIAL_THEFT
    elif type_ == "Theft - Identity Theft":
        return IntendedEffects.IDENTITY_THEFT
    elif type_ == "Theft - Theft of Proprietary Information":
        return IntendedEffects.PROPRIETARY_INFORMATION
    elif type_ == "Account Takeover":
        return IntendedEffects.ACCOUNT_TAKEOVER
    elif type_ == "Brand Damage":
        return IntendedEffects.BRAND_DAMAGE
    elif type_ == "Competitive Advantage":
        return IntendedEffects.COMPETITIVE_ADVANTAGE
    elif type_ == "Degredation of Service":
        return IntendedEffects.DEGREDATION_OF_SERVICE
    elif type_ == "Denial and Deception":
        return IntendedEffects.DENIAL_AND_DECEPTION
    elif type_ == "Destruction":
        return IntendedEffects.DESTRUCTION
    elif type_ == "Disruption":
        return IntendedEffects.DISRUPTION
    elif type_ == "Embarrassment":
        return IntendedEffects.EMBARRASSMENT
    elif type_ == "Exposure":
        return IntendedEffects.EXPOSURE
    elif type_ == "Extortion":
        return IntendedEffects.EXTORTION
    elif type_ == "Fraud":
        return IntendedEffects.FRAUD
    elif type_ == "Harassment":
        return IntendedEffects.HARASSMENT
    elif type_ == "ICS Control":
        return IntendedEffects.IC_CONTROL
    elif type_ == "Traffic Diversion":
        return IntendedEffects.TRAFFIC_DIVERSION
    elif type_ == "Unauthorized Access":
        return IntendedEffects.UNAUTHORIZED_ACCESS
    elif type_ == "Cyber Espionage Operations":
        return ThreatTypes.CYBER_ESPIONAGE_OPERATIONS
    elif type_ == "Hacker - White hat":
        return ThreatTypes.HACKER_WHITE_HAT
    elif type_ == "Hacker - Gray hat":
        return ThreatTypes.HACKER_GRAY_HAT
    elif type_ == "Hacker - Black hat":
        return ThreatTypes.HACKER_BLACK_HAT
    elif type_ == "Hacktivist":
        return ThreatTypes.HACKTIVIST
    elif type_ == "State Actor / Agency":
        return ThreatTypes.STATE_ACTOR_AGENCY
    elif type_ == "eCrime Actor - Credential Theft Botnet Operator":
        return ThreatTypes.CREDENTIAL_THEFT_BOTNET_OPERATOR
    elif type_ == "eCrime Actor - Credential Theft Botnet Service":
        return ThreatTypes.CREDENTIAL_THEFT_BOTNET_SERVICE
    elif type_ == "eCrime Actor - Malware Developer":
        return ThreatTypes.MALWARE_DEVELOPER
    elif type_ == "eCrime Actor - Money Laundering Network":
        return ThreatTypes.MONEY_LAUNDERING_NETWORK
    elif type_ == "eCrime Actor - Organized Crime Actor":
        return ThreatTypes.ORGANIZED_CRIME
    elif type_ == "eCrime Actor - Spam Service":
        return ThreatTypes.SPAM_SERVICE
    elif type_ == "eCrime Actor - Traffic Service":
        return ThreatTypes.TRAFFIC_SERVICE
    elif type_ == "eCrime Actor - Underground Call Service":
        return ThreatTypes.UNDERGROUND_CALL_SERVICE
    elif type_ == "Insider Threat":
        return ThreatTypes.INSIDER_THREAT
    elif type_ == "Disgrunted Customer / User":
        return ThreatTypes.DISGRUNTLED_CUSTOMER_USER
    else:
        return None

def get_incident_category(type_):
    """
    Converts a CRITs Event Type to a STIX Incident Category.

    :param type_: The type of a CRITs event
    :type type_: str
    :returns: STIX Incident Category (str)
    """
    #if type_ == EventTypes.APPLICATION_COMPROMISE:
    if type_ == EventTypes.DENIAL_OF_SERVICE:
        return IncidentCategory.TERM_DENIAL_OF_SERVICE
    elif type_ == EventTypes.DISTRIBUTED_DENIAL_OF_SERVICE:
        return IncidentCategory.TERM_DENIAL_OF_SERVICE
    #elif type_ == EventTypes.EXPLOITATION:
    #elif type_ == EventTypes.INTEL_SHARING:
    elif type_ == EventTypes.MALICIOUS_CODE:
        return IncidentCategory.TERM_MALICIOUS_CODE
    elif type_ == EventTypes.PHISHING:
        return IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS
    elif type_ == EventTypes.PRIVILEGED_ACCOUNT_COMPROMISE:
        return IncidentCategory.TERM_UNAUTHORIZED_ACCESS
    elif type_ == EventTypes.SCANNING:
        return IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS
    elif type_ == EventTypes.SENSOR_ALERT:
        return IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS
    elif type_ == EventTypes.SOCIAL_ENGINEERING:
        return IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS
    elif type_ == EventTypes.SNIFFING:
        return IncidentCategory.TERM_SCANSORPROBESORATTEMPTED_ACCESS
    #elif type_ == EventTypes.SPAM:
    #elif type_ == EventTypes.STRATEGIC_WEB_COMPROMISE:
    elif type_ == EventTypes.UNAUTHORIZED_INFORMATION_ACCESS:
        return IncidentCategory.TERM_UNAUTHORIZED_ACCESS
    #elif type_ == EventTypes.UNKNOWN:
    #elif type_ == EventTypes.WEBSITE_DEFACEMENT:
    else:
        return None

def make_cybox_object(type_, value=None):
    """
    Converts type_, name, and value to a CybOX object instance.

    :param type_: The object type.
    :type type_: str
    :param value: The object value.
    :type value: str
    :returns: CybOX object
    """

    if type_ == IndicatorTypes.USER_ID:
        acct = Account()
        acct.description = value
        return acct
    elif type_ in IPTypes.values():
        if type_ == IPTypes.IPV4_ADDRESS:
            name = 'ipv4-addr'
        elif type_ == IPTypes.IPV6_ADDRESS:
            name = 'ipv6-addr'
        elif type_ == IPTypes.IPV4_SUBNET:
            name = 'ipv4-net'
        elif type_ == IPTypes.IPV6_SUBNET:
            name = 'ipv6-net'
        return Address(category=name, address_value=value)
    elif type_ == IndicatorTypes.API_KEY:
        api = API()
        api.description = value
        return api
    elif type_ == IndicatorTypes.DOMAIN:
        obj = DomainName()
        obj.value = value
        return obj
    elif type_ == IndicatorTypes.USER_AGENT:
        obj = HTTPRequestHeaderFields()
        obj.user_agent = value
        return obj
    elif type_ == IndicatorTypes.MUTEX:
        m = Mutex()
        m.named = True
        m.name = String(value)
        return m
    elif type_ in (IndicatorTypes.SOURCE_PORT,
                   IndicatorTypes.DEST_PORT):
        p = Port()
        try:
            p.port_value = PositiveInteger(value)
        except ValueError: # XXX: Raise a better exception...
            raise UnsupportedCybOXObjectTypeError(type_, name)
        return p
    elif type_ == IndicatorTypes.PROCESS_NAME:
        p = Process()
        p.name = String(value)
        return p
    elif type_ == IndicatorTypes.URI:
        r = URI()
        r.type_ = 'URL'
        r.value = value
        return r
    elif type_ in (IndicatorTypes.REGISTRY_KEY,
                   IndicatorTypes.REG_KEY_CREATED,
                   IndicatorTypes.REG_KEY_DELETED,
                   IndicatorTypes.REG_KEY_ENUMERATED,
                   IndicatorTypes.REG_KEY_MONITORED,
                   IndicatorTypes.REG_KEY_OPENED):
        obj = WinRegistryKey()
        obj.key = value
        return obj
    """
    The following are types that are listed in the 'Indicator Type' box of
    the 'New Indicator' dialog in CRITs. These types, unlike those handled
    above, cannot be written to or read from CybOX at this point.

    The reason for the type being omitted is written as a comment inline.
    This can (and should) be revisited as new versions of CybOX are released.
    NOTE: You will have to update the corresponding make_crits_object function
    with handling for the reverse direction.

    In the mean time, these types will raise unsupported errors.
    """
    #elif type_ == "Device": # No CybOX API
    #elif type_ == "DNS Cache": # No CybOX API
    #elif type_ == "GUI": # revisit when CRITs supports width & height specification
    #elif type_ == "HTTP Session": # No good mapping between CybOX/CRITs
    #elif type_ == "Linux Package": # No CybOX API
    #elif type_ == "Network Packet": # No good mapping between CybOX/CRITs
    #elif type_ == "Network Route Entry": # No CybOX API
    #elif type_ == "Network Route": # No CybOX API
    #elif type_ == "Network Subnet": # No CybOX API
    #elif type_ == "Semaphore": # No CybOX API
    #elif type_ == "Socket": # No good mapping between CybOX/CRITs
    #elif type_ == "UNIX File": # No CybOX API
    #elif type_ == "UNIX Network Route Entry": # No CybOX API
    #elif type_ == "UNIX Pipe": # No CybOX API
    #elif type_ == "UNIX Process": # No CybOX API
    #elif type_ == "UNIX User Account": # No CybOX API
    #elif type_ == "UNIX Volume": # No CybOX API
    #elif type_ == "User Session": # No CybOX API
    #elif type_ == "Whois": # No good mapping between CybOX/CRITs
    #elif type_ == "Win Computer Account": # No CybOX API
    #elif type_ == "Win Critical Section": # No CybOX API
    #elif type_ == "Win Executable File": # No good mapping between CybOX/CRITs
    #elif type_ == "Win File": # No good mapping between CybOX/CRITs
    #elif type_ == "Win Kernel": # No CybOX API
    #elif type_ == "Win Mutex": # No good mapping between CybOX/CRITs
    #elif type_ == "Win Network Route Entry": # No CybOX API
    #elif type_ == "Win Pipe": # No good mapping between CybOX/CRITs
    #elif type_ == "Win Prefetch": # No CybOX API
    #elif type_ == "Win Semaphore": # No CybOX API
    #elif type_ == "Win System Restore": # No CybOX API
    #elif type_ == "Win Thread": # No good mapping between CybOX/CRITs
    #elif type_ == "Win Waitable Timer": # No CybOX API
    raise UnsupportedCybOXObjectTypeError(type_)

def make_crits_object(cybox_obj):
    """
    Converts a CybOX object instance to a CRITs EmbeddedObject instance.

    :param cybox_obj: The CybOX object.
    :type cybox_obj: CybOX object.
    :returns: :class:`crits.core.crits_mongoengine.EmbeddedObject`
    """

    try:
        o = EmbeddedObject()
        o.datatype = "string"
        if isinstance(cybox_obj, Account):
            o.object_type = IndicatorTypes.USER_ID
            o.value = get_object_values(cybox_obj.description)
            return o
        elif isinstance(cybox_obj, Address):
            name = str(cybox_obj.category)
            if name == 'ipv4-addr':
                o.object_type = IPTypes.IPV4_ADDRESS
            elif name == 'ipv6-addr':
                o.object_type = IPTypes.IPV6_ADDRESS
            elif name == 'ipv4-net':
                o.object_type = IPTypes.IPV4_SUBNET
            elif name == 'ipv6-net':
                o.object_type = IPTypes.IPV6_SUBNET
            elif name == 'asn':
                o.object_type = IndicatorTypes.AS_NUMBER
            elif name == 'cidr':
                o.object_type = IndicatorTypes.IPV4_SUBNET
            elif name == 'e-mail':
                o.object_type = IndicatorTypes.EMAIL_ADDRESS
            elif name == 'mac':
                o.object_type = IndicatorTypes.MAC_ADDRESS
            else:
                raise UnsupportedCRITsObjectTypeError(cybox_obj)
            o.value = get_object_values(cybox_obj.address_value)
            return o
        elif isinstance(cybox_obj, API):
            o.object_type = IndicatorTypes.API_KEY
            o.value = get_object_values(cybox_obj.description)
            return o
        elif isinstance(cybox_obj, DomainName):
            o.object_type = IndicatorTypes.DOMAIN
            o.value = get_object_values(cybox_obj.value)
            return o
        elif isinstance(cybox_obj, Mutex):
            o.object_type = IndicatorTypes.MUTEX
            o.value = get_object_values(cybox_obj.name)
            return o
        # Assume this is a destination port because it almost always is
        elif isinstance(cybox_obj, Port):
            o.object_type = IndicatorTypes.DEST_PORT
            o.value = get_object_values(cybox_obj.port_value)
            return o
        elif isinstance(cybox_obj, Process):
            o.object_type = IndicatorTypes.PROCESS_NAME
            o.value = get_object_values(cybox_obj.name)
            return o
        elif isinstance(cybox_obj, URI):
            if cybox_obj.type_ == 'Domain Name':
                o.object_type = IndicatorTypes.DOMAIN
            else:
                o.object_type = IndicatorTypes.URI
            o.value = get_object_values(cybox_obj.value)
            return o
        elif isinstance(cybox_obj, WinRegistryKey):
            o.object_type = IndicatorTypes.REGISTRY_KEY
            o.value = get_object_values(cybox_obj.key)
            return o
    except:
        z = UnsupportedCRITsObjectTypeError(cybox_obj)
        z.message = "Unsupported use of '%s' object." % type(cybox_obj).__name__
        raise z

    raise UnsupportedCRITsObjectTypeError(cybox_obj)
