import cgi
import logging
import os
import pytz
import re
import socket
import uuid
import zipfile

from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzutc
from io import BytesIO
from M2Crypto import BIO, SMIME, X509, Rand

import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages as tm
import libtaxii.messages_11 as tm11
from mixbox.idgen import set_id_namespace

from django.conf import settings
from django import forms as dforms
#from django.template.loader import render_to_string
from django.utils.safestring import SafeText

# ValidationError moved to errors starting with mongoengine 0.12. or 0.13
try:
    from mongoengine.base import ValidationError
except ImportError:
    from mongoengine.errors import ValidationError

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
from . import forms
from .parsers import STIXParser, STIXParserException
from .object_mapper import make_cybox_object, UnsupportedCybOXObjectTypeError
from .object_mapper import get_incident_category

from crits.events.event import Event
from crits.core.class_mapper import class_from_id, class_from_type
from crits.core.crits_mongoengine import Releasability
from crits.services.analysis_result import AnalysisConfig
from crits.services.core import ServiceConfigError
from crits.services.handlers import get_config, update_config
from crits.services.service import CRITsService

from crits.vocabulary.ips import IPTypes
from crits.vocabulary.relationships import RelationshipTypes

logger = logging.getLogger("crits." + __name__)

def poll_taxii_feeds(feeds, analyst, begin=None, end=None, import_now=False):
    """
    Given a list of feeds, individually poll each, save the data to
    the DB, and return a preview for each and status.

    :param feeds: Feeds to poll represented as [server_name, feed#]
    :type feeds: list
    :param analyst: Userid of the analyst initiating the poll
    :type analyst: string
    :param begin: Exclusive begin component of the timerange to be polled
    :type begin: :class:`datetime.datetime`
    :param end: Inclusive end component of the timerange to be polled
    :type end: :class:`datetime.datetime`
    :param import_now: If True, import all STIX data into CRITs
    :type import_now: boolean
    :returns: dict with keys:
              "polls" (list) - The metadata for each poll
              "status" (bool) - False if any poll failed
              "poll_msg" (str) - Status message
    """
    results = {'polls': [], 'status': True}
    success_polls = failed_polls = 0
    poll_details = []
    sc = get_config('taxii_service').taxii_servers

    if import_now:
        ret = {
                'successes': 0,
                'failures': [],
                'Certificate': [],
                'Domain': [],
                'Email': [],
                'Event': [],
                'Indicator': [],
                'IP': [],
                'PCAP': [],
                'RawData': [],
                'Sample': [],
               }

    for feed in feeds:
        svrc = sc[feed[0]]
        hostname = svrc['hostname']
        https = svrc['https']
        port = svrc['port']
        path = svrc['ppath']
        version = svrc['version']
        akey = str(svrc['keyfile'])
        user = str(svrc.get('user'))
        pword = str(svrc.get('pword'))
        acert = str(svrc['lcert'])
        feedc = svrc['feeds'][feed[1]]
        feed_name = feedc['feedname']
        subID = feedc.get('subID')
        ecert = feedc.get('fcert')
        ekey = feedc.get('fkey')

        result = execute_taxii_agent(hostname, https, port, path, version,
                                     feed_name, akey, acert, subID, analyst,
                                     user, pword, ecert, ekey, begin, end,
                                     import_now)

        fails = result['failures']
        fails = "<br>".join(cgi.escape(x) for x in fails)

        if fails:
            results['status'] = False
            failed_polls += 1
            success = False
        else:
            success = True
            success_polls += 1

        if 'import' in result:
            for k in ret:
                if k == 'successes':
                    ret[k] += result['import'][k]
                else:
                    ret[k].extend(result['import'][k])

        poll_details = {'hostname': hostname,
                        'feed': feed_name,
                        'mid': result['taxii_msg_id'],
                        'poll_id': result['poll_id'],
                        'blk_count': result['blk_count'],
                        'start': result['start'],
                        'end': result['end'],
                        'success': success,
                        'msg': fails}
        results['polls'].append(poll_details)

    total_polls = success_polls + failed_polls
    msg = "%s of %s polls were processed successfully" % (success_polls,
                                                          total_polls)
    if import_now:
        results['imported'] = ret
    results['poll_msg'] = msg
    return results


def execute_taxii_agent(hostname=None, https=None, port=None, path=None,
                        version="0", feed=None, akey=None, acert=None,
                        subID=None, analyst=None, user=None, pword=None,
                       ecert=None, ekey=None, start=None, end=None,
                       import_now=False):
    """
    Poll a single feed using the provided parameters, if import_now is False,
    write the data to the database, if import_now is True, return the
    results of the import.

    :param hostname: Hostname of the TAXII server
    :type hostname: string
    :param https: If True, instruct client to use HTTPS
    :type https: bool
    :param port: TAXII server port to which to connect
    :type port: string
    :param path: Path component of the TAXII server URL
    :type path: string
    :param version: TAXII version to be used
    :type version: string
    :param feed: Name of the TAXII feed/collection
    :type feed: string
    :param akey: Path to the authentication key file
    :type akey: string
    :param acert: Path to the authentication certificate file
    :type acert: string
    :param subID: Subscription ID for the selected TAXII feed
    :type subID: string
    :param analyst: Userid of the anaylst making this request
    :type analyst: string
    :param user: Username used to authenticate to the TAXII server
    :type user: string
    :param pword: Password used to authenticate to the TAXII server
    :type pword: string
    :param ecert: Path to a certificate file used for encryption of TAXII content
    :type ecert: string
    :param ekey: Path to a key file used for encryption of TAXII content
    :type ekey: string
    :param start: Exclusive begin component of the timerange to be polled
    :type start: :class:`datetime.datetime`
    :param end: Inclusive end component of the timerange to be polled
    :type end: :class:`datetime.datetime`
    :param import_now: If True, import the data directly into CRITs
    :type import_now: boolean
    :returns: dict with keys:
              "failures" (list) - Failure messages
              "blk_count" (int) - The count of content blocks retrieved
              "start" (string) - Exclusive begin component of the timerange that was polled
              "end" (string) - Inclusive end component of the timerange that was polled
              "taxii_msg_id" (string) - TAXII Message ID of the poll
              "import" (dict) - The results of the import, if any
    """

    ret = {
            'failures': [],
            'blk_count': 0,
            'poll_id': None,
            'start': start,
            'end': end,
            'taxii_msg_id': None,
          }

    save_datetimes = False

    # Last document's end time is our start time.
    if not start:
        save_datetimes = True
        last = taxii.Taxii.get_last(hostname + ':' + feed)
        if last:
            start = pytz.utc.localize(last.end)

    # If start is a string, convert it to a datetime
    # YYYY-MM-DD HH:MM:SS
    if isinstance(start, str):
        start = pytz.utc.localize(parse(start, fuzzy=True))
    elif isinstance(start, datetime) and not start.tzinfo:
        start = start.replace(tzinfo=pytz.utc)

    # store the current time as the time of this request
    runtime = datetime.now(tzutc())

    # End time is always now, unless specified.
    if not end:
        end = runtime

    # If end is a string, convert it to a datetime
    # YYYY-MM-DD HH:MM:SS
    if isinstance(end, str):
        end = pytz.utc.localize(parse(end, fuzzy=True))
    elif isinstance(end, datetime) and not end.tzinfo:
        end = end.replace(tzinfo=pytz.utc)

    if start:
        ret['start'] = start.strftime('%Y-%m-%d %H:%M:%S')
    else:
        ret['start'] = 'None'
    ret['end'] = end.strftime('%Y-%m-%d %H:%M:%S')

    # compare start and end to make sure:
    # 1) start time is before end time
    # 2) end time is not in the future
    if (start != None and start >= end):
        ret['failures'].append("Start time must be before end time")
        return ret
    if end > runtime:
        ret['failures'].append("End time cannot be in the future")
        return ret

    # subID & port must be none if not provided
    if not subID:
        subID = None
    if not port:
        port = None

    # Instantiate TAXII client class
    client = tc.HttpClient()

    # Setup proxy communication, if needed
    if settings.HTTP_PROXY:
        proxy = settings.HTTP_PROXY
        if not proxy.startswith('http://'):
            proxy = 'http://' + proxy
        client.setProxy(proxy)

    # Setup client authentication
    if https:
        client.setUseHttps(True)
    if akey and acert and user:
        client.setAuthType(tc.HttpClient.AUTH_CERT_BASIC)
        client.setAuthCredentials({'key_file': akey, 'cert_file': acert,
                                   'username': user, 'password': pword})
    elif akey and acert:
        client.setAuthType(tc.HttpClient.AUTH_CERT)
        client.setAuthCredentials({'key_file': akey, 'cert_file': acert})
    elif user:
        client.setAuthType(tc.HttpClient.AUTH_BASIC)
        client.setAuthCredentials({'username': user, 'password': pword})

    crits_taxii = taxii.Taxii()
    crits_taxii.runtime = runtime
    crits_taxii.end = end
    crits_taxii.feed = hostname + ':' + feed

    # if version=0, Poll using 1.1 then 1.0 if that fails.
    while True:
        status = ""
        if version in ('0', '1.1'):
            if subID:
                pprams = None
            else:
                pprams = tm11.PollRequest.PollParameters()
            poll_msg = tm11.PollRequest(message_id=tm11.generate_message_id(),
                                        collection_name=feed,
                                        poll_parameters=pprams,
                                        exclusive_begin_timestamp_label=start,
                                        inclusive_end_timestamp_label=end,
                                        subscription_id=subID)
            xml_msg_binding = t.VID_TAXII_XML_11
            tm_ = tm11

        else: # '1.0' should be the only other option
            poll_msg = tm.PollRequest(message_id=tm.generate_message_id(),
                                      feed_name=feed,
                                      exclusive_begin_timestamp_label=start,
                                      inclusive_end_timestamp_label=end,
                                      subscription_id=subID)
            xml_msg_binding = t.VID_TAXII_XML_10
            tm_ = tm

        try:
            response = client.callTaxiiService2(hostname, path,
                                                xml_msg_binding,
                                                poll_msg.to_xml(), port)
        except Exception as e:
            if "alert unknown ca" in str(e):
                ret['failures'].append("Certficate Error - TAXII Server does not "
                                       "recognize your certificate: %s" % e)
            else:
                ret['failures'].append("TAXII Server Communication Error: %s" % e)
            return ret

        # If server says it's a different TAXII version than selected, notify
        if (version == '1.1' and
            response.info().getheader('X-TAXII-Content-Type') == t.VID_TAXII_XML_10):
            ret['failures'].append('Error - TAXII 1.1 selected, but server is TAXII 1.0')
            return ret
        if (version == '1.0' and
            response.info().getheader('X-TAXII-Content-Type') == t.VID_TAXII_XML_11):
            if status:
                status += 'Server response content type is TAXII 1.1'
            else:
                ret['failures'].append('Error - TAXII 1.0 selected, but server is TAXII 1.1')
            return ret

        try:
            taxii_msg = t.get_message_from_http_response(response,
                                                         poll_msg.message_id)

            if (response.getcode() != 200
                or taxii_msg.message_type == tm_.MSG_STATUS_MESSAGE):
                status += "Server Response: %s"
                msg = (taxii_msg.status_type, taxii_msg.message)
                status = status % ' - '.join(x for x in msg if x)
            else:
                break

        except Exception as e:
            status += str(e)
            if version == '1.0' and "taxii_xml_binding-1.1" in str(e):
                status += ". Try selecting TAXII Version 1.1 in settings."

        if version == '0':
            ret['failures'].append('TAXII 1.1 ' + status)
            version = '1.0' # try '1.0'
        else:
            ret['failures'].append('TAXII %s ' % version + status)
            return ret

    valid = tm_.validate_xml(taxii_msg.to_xml())
    if valid != True:
        ret['failures'].append("Invalid XML: %s" % valid)
        return ret

    if taxii_msg.message_type != tm_.MSG_POLL_RESPONSE:
        msg = "No poll response. Unexpected message type: %s"
        ret['failures'].append(msg % taxii_msg.message_type)
        return ret

    mid = taxii_msg.message_id
    ret['taxii_msg_id'] = mid
    if not taxii_msg.content_blocks:
        if save_datetimes:
            crits_taxii.save()
        return ret

    if import_now:
        import_result = {
                'successes': 0,
                'failures': [],
                'Certificate': [],
                'Domain': [],
                'Email': [],
                'Event': [],
                'Indicator': [],
                'IP': [],
                'PCAP': [],
                'RawData': [],
                'Sample': [],
               }

    for content_block in taxii_msg.content_blocks:
        label = content_block.timestamp_label.strftime("%Y-%m-%d %H:%M:%S")
        data = parse_content_block(content_block, tm_, ekey, ecert)
        errors = ["%s: %s" % ("Content Block", data[1])] if data[1] else []

        content = taxii.TaxiiContent()
        content.populate(data[0], analyst, mid, hostname, feed, label, start,
                         end, poll_time=runtime, errors=errors)
        if import_now:
            ic_ret = import_content([content], analyst)
            if ic_ret and ic_ret['status']:
                for k in import_result:
                    if k == 'successes':
                        import_result[k] += ic_ret[k]
                    else:
                        import_result[k].extend(ic_ret[k])
        else:
            content.save()
        ret['blk_count'] += 1
        t_offset = runtime.replace(tzinfo=None)-datetime(1970,1,1)
        ret['poll_id'] = '%.3f' % (int(t_offset.total_seconds() * 1000)/1000.0)
    if save_datetimes:
        crits_taxii.save()
    if import_now:
        ret['import'] = import_result

    return ret

def parse_content_block(content_block, tm_, privkey=None, pubkey=None):
    """
    Given a content_block, parse its data based on its content_binding.
    Decrypt the content_block if it is encrypted as x-pkcs7-mime.

    :param content_block: The TAXII content_block of data to be processed
    :type content_block: :class:`libtaxii.messages_10.ContentBlock`
    :param tm_: One of two possible libtaxii messages modules
    :type tm_:  :module:`libtaxii.messages` or :module:`libtaxii.messages_11`
    :param privkey: Path to a key file used for decryption of TAXII content
    :type privkey: string
    :param pubkey: Path to a certificate file used for decryption of TAXII content
    :type pubkey: string
    :returns: tuple: (parsed_data or None, error_message or None)
    """
    stix_bindings = (t.CB_STIX_XML_10,
                     t.CB_STIX_XML_101,
                     t.CB_STIX_XML_11,
                     t.CB_STIX_XML_111,
                     t.CB_STIX_XML_12)

    binding = str(content_block.content_binding)
    if binding == 'application/x-pkcs7-mime':
        if not privkey or not pubkey:
            msg = "Encrypted data found, but certificate or key not provided"
            return (None, msg)

        inbuf = BIO.MemoryBuffer(BytesIO(content_block.content).read())
        s = SMIME.SMIME()
        try:
            s.load_key(str(privkey), str(pubkey))
            p7, data = SMIME.smime_load_pkcs7_bio(inbuf)
            buf = s.decrypt(p7)
        except SMIME.PKCS7_Error:
            return (None, "Decryption Failed")
        f = BytesIO(buf)
        new_block = f.read()
        f.close()
        return parse_content_block(tm_.ContentBlock.from_xml(new_block),
                                   tm_, privkey, pubkey)
    elif binding in stix_bindings:
        f = BytesIO(content_block.content)
        data = f.read()
        f.close()
        return (data, None)
    else:
        msg = 'Unknown content binding "%s"' % binding
        return (None, msg)


def process_stix_upload(filedata, analyst, source, reference, use_hdr_src,
                        import_now=False):
    """
    Take the given file data and save each contained STIX document in the DB.
    If the file is a ZIP, extract and save each STIX document.

    :param filedata: The uploaded filedata
    :type filedata: :class:`django.core.files.uploadedfile.InMemoryUploadedFile`
    :param analyst: Userid of the analyst who uploaded the data
    :type analyst: string
    :param source: The analyst provided source name of the data
    :type source: string
    :param reference: A reference to the source of the data
    :type reference: string
    :param use_hdr_src: If True, try to use the STIX Header Information Source
                         instead of the value in "source" parameter
    :type use_hdr_src: boolean
    :param import_now: If True, import all STIX data into CRITs
    :type import_now: boolean
    :returns: dictionary
    """

    t_stamp = datetime.now(tzutc())
    t_stamp = t_stamp.replace(microsecond=t_stamp.microsecond / 1000 * 1000)
    top_name = filedata.name

    if import_now:
        ret = {
                'successes': 0,
                'failures': [],
                'Certificate': [],
                'Domain': [],
                'Email': [],
                'Event': [],
                'Indicator': [],
                'IP': [],
                'PCAP': [],
                'RawData': [],
                'Sample': [],
               }

    if zipfile.is_zipfile(filedata):
        with zipfile.ZipFile(filedata, 'r') as z:
            for zinfo in z.infolist():
                result = process_stix_doc(z.open(zinfo), zinfo.filename,
                                       t_stamp, source, reference, use_hdr_src,
                                       analyst, import_now, top_name)
                if result and result['status']:
                    for k in ret:
                        if k == 'successes':
                            ret[k] += result[k]
                        else:
                            ret[k].extend(result[k])
    else:
        filedata.seek(0)
        ret = process_stix_doc(filedata, top_name, t_stamp, source,
                               reference, use_hdr_src, analyst, import_now)

    if import_now:
        return ret
    else:
        poll_id = t_stamp.replace(tzinfo=None)-datetime(1970,1,1)
        poll_id = '%.3f' % poll_id.total_seconds()
        return generate_import_preview(poll_id, analyst)


def process_stix_doc(data, doc_name, t_stamp, source, reference, use_hdr_src,
                     analyst, import_now=False, top_name=None):
    """
    Take the data for a STIX document, decode if necessary, and save in the DB.

    :param data: The STIX document data
    :type data: :class:`django.core.files.uploadedfile.InMemoryUploadedFile`
                OR :class:`zipfile.ZipExtFile`
    :param doc_name: The filename of the STIX document
    :type doc_name: string
    :param t_stamp: Timestamp representing when this data was uploaded
    :type t_stamp: :class:`datetime.datetime`
    :param source: The analyst provided source name of the data
    :type source: string
    :param reference: A reference to the source of the data
    :type reference: string
    :param use_hdr_src: If True, try to use the STIX Header Information Source
                         instead of the value in "source" parameter
    :type use_hdr_src: boolean
    :param analyst: Userid of the analyst who uploaded the data
    :type analyst: string
    :param import_now: If True, import all STIX data into CRITs
    :type import_now: boolean
    :param top_name: The filename of the STIX document or parent ZIP file
    :type top_name: string
    :returns: if import_now is True, returns result of import_content function
    """

    if not top_name:
        top_name = doc_name

    decoded = u''
    checked = False
    encoding = 'utf-8'
    ## search and extract encoding string
    ptrn = r"""^<\?xml.+?encoding=["'](?P<encstr>[^"']+)["'].*?\?>"""

    for line in data:
        if not checked:
            match = re.search(ptrn, line)
            checked = True
            if match:
                encoding = match.group("encstr")
        decoded += line.decode(encoding, 'replace')

    content = taxii.TaxiiContent()
    content.populate(decoded, analyst, reference, source, top_name, doc_name,
                     poll_time=t_stamp, use_hdr_src=use_hdr_src)

    if import_now: # Do not save if we're importing right now
        result = import_content([content], analyst)
        return result
    else: # save for later
        content.save()


def save_standards_doc(data, analyst, message_id, hostname, feed, block_label,
                       begin=None, end=None, poll_time=None, use_hdr_src=False,
                       errors=[]):
    """
    Take the given standards data and save it in the DB

    :param data: Content being saved
    :type data: string
    :param analyst: Userid of the analyst who polled the data
    :type analyst: string
    :param message_id: ID of the TAXII message from which this content came
    :type message_id: string
    :param hostname: Hostname of the TAXII server from which this content came
    :type hostname: string
    :param feed: Feed/collection from which this data was polled
    :type feed: string
    :param block_label: STIX filename, or when block submitted to TAXII server
    :type block_label: string
    :param begin: Exclusive begin component of the timerange that was polled
    :type begin: :class:`datetime.datetime`
    :param end: Inclusive end component of the timerange that was polled
    :type end: :class:`datetime.datetime`
    :param poll_time: Timestamp representing when this data was polled
    :type poll_time: :class:`datetime.datetime`
    :param use_hdr_src: If True, try to use the STIX Header Information Source
                         instead of the value in "source" parameter
    :type use_hdr_src: boolean
    :param errors: List of errors
    :type errors: list
    :returns: Nothing
    """

    if data or errors:
        taxii_content = taxii.TaxiiContent()
        taxii_content.taxii_msg_id = message_id
        taxii_content.hostname = hostname
        taxii_content.use_hdr_src = use_hdr_src
        taxii_content.feed = feed
        taxii_content.block_label = block_label
        taxii_content.poll_time = poll_time or datetime.now()
        if end: # TAXII poll will always have end timestamp
            end = end.strftime('%Y-%m-%d %H:%M:%S')
            begin = begin.strftime('%Y-%m-%d %H:%M:%S') if begin else 'None'
            taxii_content.timerange = '%s to %s' % (begin, end)
        else: # Must be a STIX file upload
            taxii_content.timerange = 'STIX File Upload'
        taxii_content.analyst = analyst
        taxii_content.content = data or ""
        taxii_content.errors = errors
        taxii_content.import_failed = False
        taxii_content.save()

def select_blocks(select=None, deselect=None):
    """
    Change the "selected" field of blocks in the DB based on poll_ids,
    or lists of block ObjectIDs.

    :param select: A Poll ID or list of block IDs for which "selected"
                   should be set to True.
    :type select: list or str
    :param deselect: A Poll ID or list of block IDs for which "selected"
                     should be set to False.
    :type deselect: list or str
    :returns: dict with keys:
              "success" (bool) - DB Update Pass/Fail
              "msg" (str) - Failure message
    """
    ret = {'success': True, 'msg': ''}
    tc = taxii.TaxiiContent
    try:
        if isinstance(select, list) and select:
            tc.objects(id__in=select).update(set__selected=True)
        elif isinstance(select, basestring) and select:
            p_time = datetime.utcfromtimestamp(float(select))
            tc.objects(poll_time=p_time).update(set__selected=True)
        if isinstance(deselect, list) and deselect:
            tc.objects(id__in=deselect).update(set__selected=False)
        elif isinstance(deselect, basestring) and deselect:
            p_time = datetime.utcfromtimestamp(float(deselect))
            tc.objects(poll_time=p_time).update(set__selected=False)
    except Exception as e:
        ret['success'] = False
        ret['msg'] = str(e)
    return ret


def generate_import_preview(poll_id, analyst, page=1, mult=10):
    """
    Given a Poll ID (unix timestamp), parse all associated content blocks and
    generate preview data for the CRITs TLOs that can be imported into CRITs

    :param poll_id: ID of the desired TAXII poll (unix timestamp)
    :type poll_id: string
    :param analyst: Userid of the analyst requesting the preview
    :type analyst: string
    :param page: The desired page number
    :type page: int
    :param mult: The desired number of blocks/page
    :type mult: int
    :returns: dict with keys:
              "successes" (int) - Count of successful preview objects
              "failures" (list) - Failure messages
              "blocks" (list) - Content blocks, their metadata, and preview objects
              "start" (string) - Exclusive begin component of the timerange that was polled
              "end" (string) - Inclusive end component of the timerange that was polled
              "poll_time" (:class:`datetime.datetime`) - Datetime the feed was polled
              "taxii_msg_id" (string) - TAXII Message ID of the poll
              "source" (string) - Source from which the content came
              "feed" (string) - Name of the TAXII feed/collection that was polled
                                or name of the file that was uploaded
              "analyst" (string) - Userid of the anaylst that initiated the poll
    """
    tsvc = get_config('taxii_service')
    hdr_events = tsvc['header_events']
    obs_as_ind = tsvc['obs_as_ind']
    mult = int(mult)
    page = int(page)
    skip = mult * (page - 1)
    p_time = datetime.utcfromtimestamp(float(poll_id))
    block_count = taxii.TaxiiContent.objects(poll_time=p_time).count()
    pages = (block_count / mult) + (1 if block_count % mult else 0)
    while skip > block_count: # prevent invalid skip value
        page -= 1
        skip = mult * (page - 1)
    blocks = taxii.TaxiiContent.objects(poll_time=p_time).limit(mult).skip(skip)
    if not blocks:
        ret = {
          'failures': ['No data exists for Timestamp %s' % p_time],
          'msg': '',
        }
        return ret

    ret = {
            'successes': 0,
            'failures': [],
            'blocks': [],
            'block_count': block_count,
            'timerange': blocks[0].timerange,
            'poll_id': poll_id,
            'poll_time': blocks[0].poll_time,
            'taxii_msg_id': blocks[0].taxii_msg_id,
            'source': blocks[0].hostname,
            'feed': blocks[0].feed,
            'analyst': blocks[0].analyst,
            'page': page,
            'pages': pages,
            'page_range': range(1, pages + 1),
            'mult': mult,
          }

    for num, block in enumerate(blocks):
        tlos = {}
        failures = []

        for e in block.errors:
            err = e.split(': ')
            failures.append((err[1], err[0]))

        if block.content:
            objs = import_standards_doc(block.content, analyst, None, None,
                                        hdr_events, obs_as_ind,
                                        preview_only=True)

            if not objs['success']:
                failures.append((objs['reason'], 'STIX Package'))

            for k in objs['failed']:
                failures.append(k)

            for sid in objs['imported']:
                ret['successes'] += 1
                tlo_meta = objs['imported'][sid]
                tlos.setdefault(tlo_meta[0], []).append((tlo_meta[1],
                                                         tlo_meta[2]))

        ret['blocks'].append({'id': block.id,
                              'num': num + skip + 1,
                              'block_label': block.block_label,
                              'tlos': tlos,
                              'failures': failures,
                              'selected': block.selected})
    return ret

def get_saved_polls(action, poll_id=None):
    """
    If action is 'list', get metadata for all saved TAXII polls. If action
    is 'delete' and a Poll ID is provided, delete all content
    related to that poll before returning the remaining poll metadata.

    :param action: If 'list', return metadata.
                   If 'download', return XML-formatted data
                   If 'delete', delete a set of data, then return metadata
    :type action: string
    :param poll_id: ID of the poll for which content should be deleted
    :type poll_id: string
    :returns: dict with keys:
              "unimported" (dict) - Polls that have not yet been imported
              "errored" (dict) - Polls that errored during import
              "success" (bool) - True if poll data was successfully retrieved
              "msg" (string) - If success is False, provide an error msg
    """
    if action in ('delete', 'download'):
        p_time = datetime.utcfromtimestamp(float(poll_id))
        data = taxii.TaxiiContent.objects(poll_time=p_time) # get data from dB
        if action == 'delete':
            data.delete() # delete the given poll
            return {'success': True}
        else: # download
            if  data[0].timerange == 'STIX File Upload':
                filename = data[0].feed
                res = ''.join(block.content for block in data)
                return {'response': res, 'filename': filename}

            # rebuild XML
            filename = "taxii_poll-%s.xml" % p_time.strftime('%Y%m%dT%H%M%S')
            content_blocks = []
            for block in data:
                stamp = datetime.strptime(block.block_label, '%Y-%m-%d %H:%M:%S')
                stamp = stamp.replace(tzinfo=pytz.utc)
                c_block = tm11.ContentBlock(content_binding = t.CB_STIX_XML_111,
                                            timestamp_label = stamp,
                                            content = block.content)
                content_blocks.append(c_block)
            res = tm11.PollResponse(message_id=block.taxii_msg_id,
                                    in_response_to="Unknown",
                                    collection_name=block.feed,
                                    message=block.timerange,
                                    content_blocks=content_blocks)
            return {'response': res.to_xml(), 'filename': filename}
    elif action != 'list':
        return {'success': False, 'msg': 'Invalid action type'}

    content = taxii.TaxiiContent.objects()
    polls = {}
    ret = {'unimported': [], 'errored': []}
    for block in content:
        time = str(block.poll_time)
        poll_id = '%.3f' % (block.poll_time-datetime(1970,1,1)).total_seconds()
        if time not in polls:
            polls[time] = {'time': time,
                           'poll_id': poll_id,
                           'msg_id': block.taxii_msg_id,
                           'source': block.hostname,
                           'feed': block.feed,
                           'timerange': block.timerange,
                           'analyst': block.analyst,
                           'count': 1,
                           'errors': block.errors,
                           'import_failed': block.import_failed}
        else:
            polls[time]['count'] += 1
            polls[time]['errors'].extend(block.errors)
            if block.import_failed:
                polls[time]['import_failed'] = True

    for poll in polls:
        if polls[poll]['import_failed']:
            ret['errored'].append(polls[poll])
        else:
            ret['unimported'].append(polls[poll])

    # sort the lists chronologically
    ret['unimported'].sort(key=lambda k: k['time'])
    ret['errored'].sort(key=lambda k: k['time'])

    ret['success'] = True
    return ret

def get_saved_block(block_id=None):
    """
    Return the XML data for the given block ID.

    :param block_id: ObjectId of the requested block
    :type poll_id: string
    :returns: dict with keys:
              "response" (str) - The XML
              "filename" (str) - The name of the XML file
    """

    data = taxii.TaxiiContent.objects(id=block_id).first() # get data from dB

    if data.timerange == 'STIX File Upload':
        filename = data.block_label
        res = data.content
        return {'response': res, 'filename': filename}

    # rebuild XML
    stamp = datetime.strptime(data.block_label, '%Y-%m-%d %H:%M:%S')
    stamp = stamp.replace(tzinfo=pytz.utc)
    filename = "taxii_block-%s-%s.xml"
    filename = filename % (data.feed, stamp.strftime('%Y%m%dT%H%M%S'))
    c_block = tm11.ContentBlock(content_binding = t.CB_STIX_XML_111,
                                timestamp_label = stamp,
                                content = data.content)

    return {'response': c_block.to_xml(), 'filename': filename}

def import_poll(poll_id, analyst, action=None):
    """
    Given a poll_id (timestamp), parse and import those content blocks where
    "selected" is True. User can select whether to delete or keep
    unimported blocks from the same poll via the 'action' key. An action
    of "import_delete" directs the parser to delete unimported content
    from the same poll, while any other value for 'action' keeps the
    unimported content.

    :param poll_id: Timestamp as the ID of the poll to import
    :type poll_id: str
    :param analyst: Userid of the analyst requesting the import
    :type analyst: string
    :param action: If 'import_delete', delete unimported content
    :type action: string
    :returns: dict with keys:
              "successes" (int) - Count of successfully imported objects
              "failures" (list) - Individual failure messages
              "status" (bool) - True if import was generally successful
              "msg" (string) - General error messages
              "Certificate" (list) - IDs and values of imported Certificates
              "Domain" (list) - IDs and values of imported Domains
                ...and so on for each TLO type
    """

    ret = {
            'successes': 0,
            'failures': [],
            'status': False,
            'msg': ''
          }
    tlos = {
            'Certificate': [],
            'Domain': [],
            'Email': [],
            'Event': [],
            'Indicator': [],
            'IP': [],
            'PCAP': [],
            'RawData': [],
            'Sample': [],
           }

    method = "STIX Import"

    p_time = datetime.utcfromtimestamp(float(poll_id))
    blocks = taxii.TaxiiContent.objects(poll_time=p_time, selected=True)

    tsvc = get_config('taxii_service')
    hdr_events = tsvc['header_events']
    obs_as_ind = tsvc['obs_as_ind']
    tsrvs = tsvc.taxii_servers
    pids = {}

    for block in blocks:
        source = ""
        reference = block.taxii_msg_id
        data = block.content
        use_hdr_src = block.use_hdr_src

        for svr in tsrvs:
            if tsrvs[svr].get('hostname') == block.hostname:
                for feed in tsrvs[svr]['feeds']:
                    if tsrvs[svr]['feeds'][feed]['feedname'] == block.feed:
                        feed_cfg = tsrvs[svr]['feeds'][feed]
                        source = feed_cfg['source']
                        default_ci = (feed_cfg.get('def_conf', 'unknown'),
                                      feed_cfg.get('def_impact', 'unknown'))
                        break
                if source:
                    break
        else:
            source = block.hostname
            default_ci = ('unknown', 'unknown')

        objs = import_standards_doc(data, analyst, method, reference,
                                    hdr_events, default_ci, source,
                                    use_hdr_src, obs_as_ind)

        if not objs['success']:
            ret['failures'].append((objs['reason'],
                                   'STIX Package'))
            block.import_failed = True
            block.errors.append('STIX Package: %s' % objs['reason'])

        for sid in objs['imported']:
            ret['successes'] += 1
            tlo_meta = objs['imported'][sid]
            tlos.setdefault(tlo_meta[0], []).append((tlo_meta[1],
                                                     tlo_meta[2]))

        for k in objs['failed']:
            ret['failures'].append(k)
            block.import_failed = True
            block.errors.append('%s: %s' % (k[1], k[0]))

        if block.import_failed:
            block.save()
        else:
            try:
                block.delete() # delete it if it exists in the DB
            except:
                pass

        pids[block.poll_time] = 1 # save unique poll timestamps

    if action == "import_delete":
        taxii.TaxiiContent.objects(poll_time__in=pids.keys(), errors=[]).delete()

    ret.update(tlos) # add the TLO lists to the return dict

    ret['status'] = True

    return ret


def import_content(content_objs, analyst, action=None):
    """
    Given a list of TaxiiContent objects, or Mongo ObjectIDs, parse and import
    the content. User can select whether to delete or keep
    unimported blocks from the same poll via the 'action' key. An action
    of "import_delete" directs the parser to delete unimported content
    from the same poll, while any other value for 'action' keeps the
    unimported content.

    :param block_ids: Mongo ObjectIDs of the blocks to import
    :type block_ids: list of strs or list of :class:`taxii.TaxiiContent`
    :param analyst: Userid of the analyst requesting the import
    :type analyst: string
    :param action: If 'import_delete', delete unimported content
    :type action: string
    :returns: dict with keys:
              "successes" (int) - Count of successfully imported objects
              "failures" (list) - Individual failure messages
              "status" (bool) - True if import was generally successful
              "msg" (string) - General error messages
              "Certificate" (list) - IDs and values of imported Certificates
              "Domain" (list) - IDs and values of imported Domains
                ...and so on for each TLO type
    """

    ret = {
            'successes': 0,
            'failures': [],
            'status': False,
            'msg': ''
          }
    tlos = {
            'Certificate': [],
            'Domain': [],
            'Email': [],
            'Event': [],
            'Indicator': [],
            'IP': [],
            'PCAP': [],
            'RawData': [],
            'Sample': [],
           }

    if not content_objs:
        return {'status': False, 'msg': 'No content was selected for import'}

    method = "STIX Import"
    if isinstance(content_objs[0], basestring):
        blocks = taxii.TaxiiContent.objects(id__in=content_objs)
    else:
        blocks = content_objs

    tsvc = get_config('taxii_service')
    hdr_events = tsvc['header_events']
    obs_as_ind = tsvc['obs_as_ind']
    tsrvs = tsvc.taxii_servers
    pids = {}

    for block in blocks:
        source = ""
        reference = block.taxii_msg_id
        data = block.content
        use_hdr_src = block.use_hdr_src

        for svr in tsrvs:
            if tsrvs[svr].get('hostname') == block.hostname:
                for feed in tsrvs[svr]['feeds']:
                    if tsrvs[svr]['feeds'][feed]['feedname'] == block.feed:
                        feed_cfg = tsrvs[svr]['feeds'][feed]
                        source = feed_cfg['source']
                        default_ci = (feed_cfg.get('def_conf', 'unknown'),
                                      feed_cfg.get('def_impact', 'unknown'))
                        break
                if source:
                    break
        else:
            source = block.hostname
            default_ci = ('unknown', 'unknown')

        objs = import_standards_doc(data, analyst, method, reference,
                                    hdr_events, default_ci, source,
                                    use_hdr_src, obs_as_ind)

        if not objs['success']:
            ret['failures'].append((objs['reason'],
                                   'STIX Package'))
            block.import_failed = True
            block.errors.append('STIX Package: %s' % objs['reason'])

        for sid in objs['imported']:
            ret['successes'] += 1
            tlo_meta = objs['imported'][sid]
            tlos.setdefault(tlo_meta[0], []).append((tlo_meta[1],
                                                     tlo_meta[2]))

        for k in objs['failed']:
            ret['failures'].append(k)
            block.import_failed = True
            block.errors.append('%s: %s' % (k[1], k[0]))

        if block.import_failed:
            block.save()
        else:
            try:
                block.delete() # delete it if it exists in the DB
            except:
                pass

        pids[block.poll_time] = 1 # save unique poll timestamps

    if action == "import_delete":
        taxii.TaxiiContent.objects(poll_time__in=pids.keys(), errors=[]).delete_one()

    ret.update(tlos) # add the TLO lists to the return dict

    ret['status'] = True

    return ret

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
        if obj.ip_type == IPTypes.IPV4_ADDRESS:
            obje.category = "ipv4-addr"
        elif obj.ip_type == IPTypes.IPV6_ADDRESS:
            obje.category = "ipv6-addr"
        elif obj.ip_type == IPTypes.IPV4_SUBNET:
            obje.category = "ipv4-net"
        elif obj.ip_type == IPTypes.IPV6_SUBNET:
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
        try:
            ind.confidence = obj.confidence.rating.title()
        except:
            pass
        try:
            ind.likely_impact = obj.impact.rating.title()
        except:
            pass
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
    inc = Incident(title=obj.title,
                   short_description=obj.event_type,
                   description=obj.description)
    category = get_incident_category(obj.event_type)
    if category:
        inc.add_category(category)

    return (inc, obj.releasability)

def has_cybox_repr(obj):
    """
    Determine if this indicator is of a type that can
    successfully be converted to a CybOX object.

    :return The CybOX representation if possible, else False.
    """
    try:
        rep = make_cybox_object(obj.ind_type, obj.value)
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
                if rel.relationship == RelationshipTypes.CONTAINS and rel.rel_type == 'Sample':
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

            # wrap in stix Indicator because some STIX objects can't have
            # related_observables and we want to be able to relate observables
            # to anything else
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
    for stix_obj in stix: # for each new STIX object
        for rel in relationships.get(stix_obj.id_, {}): # each CRITs oid related to the new STIX object
            if isinstance(refObjs.get(rel), S_Ind): # if a STIX Indicator was made for that CRITs oid
                stix_obj.related_indicators.append(refObjs[rel]) # relate the STIX ind to that new STIX obj
                rel_meta = relationships.get(stix_obj.id_)[rel]
                stix_obj.related_indicators[-1].relationship = rel_meta[0]
                stix_obj.related_indicators[-1].confidence = rel_meta[1]

                # Add any Email Attachments to CybOX EmailMessage Objects
                if isinstance(stix_obj, S_Ind):
                    if 'EmailMessage' in stix_obj.observable.object_.id_:
                        if rel_meta[0] == 'Contains' and rel_meta[2] == 'Sample':
                            email = stix_obj.observable.object_.properties
                            if not email.attachments:
                                email.attachments = Attachments()
                            email.attachments.append(refObjs[rel].idref)

    tool_list = ToolInformationList()
    tool = ToolInformation("CRITs", "MITRE")
    tool.version = settings.CRITS_VERSION
    tool_list.append(tool)
    i_s = InformationSource(
        time=Time(produced_time= datetime.now()),
        identity=Identity(name=settings.COMPANY_NAME),
        tools=tool_list)

    stix_desc = ("This STIX package was generated by the TAXII service "
                 "of CRITs, the open source threat repository. You can "
                 "learn more about CRITs at https://crits.github.io")
    stix_title = "CRITs Generated STIX Package"
    header = STIXHeader(information_source=i_s,
                        description=StructuredText(value=stix_desc),
                        package_intents=["Collective Threat Intelligence"],
                        title=stix_title)

    stix_msg['stix_obj'] = STIXPackage(incidents=stix_msg['stix_incidents'],
                    indicators=stix_msg['stix_indicators'],
                    threat_actors=stix_msg['stix_actors'],
                    stix_header=header)

    return stix_msg

def run_taxii_service(analyst, obj, rcpts, preview,
                      relation_choices=[], confirmed=False):
    """
    :param analyst The analyst triggering this TAXII service call
    :param obj The context object being shared
    :param rcpts The list of sources to which the TAXII message is being sent
    :param preview If true, generate and return the STIX doc, rather
                   than sending via TAXII
    :param relation_choices The list of items related to OBJ that have
                            been chosen for sharing
    :param confirmed True if user has accepted & approved releasability updates
    """
    ret = {
            'success': False, # tells client if any message was sent successfully
            'rcpts': [], # list of sources the message was sent
            'failed_rcpts': [], # list of sources to which message failed to send
          }

    if not obj: # no item (shouldn't occur unless someone is really trying to break things.)
        ret['reason'] = "No object found."
        return ret

    if not rcpts and not preview: # no recipients selected in TAXII form (ok for preview)
        ret['reason'] = "No recipients selected."
        return ret

    # If dealing with an event context, make sure at least one related item is
    # selected. Events have no real sharing value without related information.
    if obj._meta['crits_type'] == Event._meta['crits_type'] and len(relation_choices) == 0:
        ret['reason'] = "Need at least one related item to send."
        return ret

    # Set the XML namespace for STIX documents
    sc = get_config('taxii_service')
    set_id_namespace({sc['namespace']: sc['ns_prefix']})

    # Get list of recipient sources
    rcpt_srcs = []
    for rcpt in rcpts:
        (svr, fid) = rcpt.split(' - ')
        rcpt_srcs.append(sc['taxii_servers'][svr]['feeds'][fid]['source'])

    # Convert object and chosen related items to STIX/CybOX
    try:
        stix_msg = to_stix(obj, relation_choices, bin_fmt="base64")
        stix_doc = stix_msg['stix_obj']
    except UnsupportedCybOXObjectTypeError as e:
        ret['reason'] = e.message
        return ret

    # if doing a preview of content, return content now
    if preview:
        ret['preview'] = stix_doc.to_xml()
        return ret
    elif not confirmed: # if user has not accepted responsibility for releasability
        release = verify_releasability(rcpt_srcs, stix_msg['final_objects'],
                                       analyst, False)
        if release: # if releasability needs to change
            ret['release_changes'] = release
            return ret # make user confirm changes, instead of sending messages

    # Instantiate TAXII client class
    client = tc.HttpClient()

    # Setup proxy communication, if needed
    if settings.HTTP_PROXY:
        proxy = settings.HTTP_PROXY
        if not proxy.startswith('http://'):
            proxy = 'http://' + proxy
        client.setProxy(proxy)

    # The minimum required info has been provided by user via the TAXII form.
    # Form configuration and validation ensures the form is valid.
    #
    # NOTE: this does not guarantee that the message will send to
    # each/any recipient feed successfully.

    # Loop through each recipient
    for feed in rcpts:
        try: # try to get config
            (svr, fid) = feed.split(' - ')
            scfg = sc['taxii_servers'][svr]
            fcfg = sc['taxii_servers'][svr]['feeds'][fid]
            hostname = scfg['hostname']
            version = scfg['version']
            https = scfg['https']
            lcert = scfg['lcert']
            path = scfg['ipath']
            port = scfg['port']
            akey = scfg['keyfile']
            user = scfg.get('user')
            pword = scfg.get('pword')
            feedname = fcfg['feedname']
            source = fcfg['source']
            fcert = fcfg['fcert']
            rcpt = "%s - %s" % (svr, feedname)
            if not port:
                port = None

        except KeyError as e: # if can't find necessary config info, do next
            ret['failed_rcpts'].append((feed, 'None/Bad Configuration'))
            continue

        #TODO: this doesn't confirm that 'hostname' is a TAXII server...
        # This doesn't work if a proxy is needed for internet access
        if not settings.HTTP_PROXY and not resolve_taxii_server(hostname):
            msg = "Cannot contact TAXII Server at: %s" % hostname
            ret['failed_rcpts'].append((rcpt, msg))
            continue

        # Setup client authentication and proxy communication
        if https:
            client.setUseHttps(True)
        if akey and lcert and user:
            client.setAuthType(tc.HttpClient.AUTH_CERT_BASIC)
            client.setAuthCredentials({'key_file': akey, 'cert_file': lcert,
                                       'username': user, 'password': pword})
        elif akey and lcert:
            client.setAuthType(tc.HttpClient.AUTH_CERT)
            client.setAuthCredentials({'key_file': akey, 'cert_file': lcert})
        elif user:
            client.setAuthType(tc.HttpClient.AUTH_BASIC)
            client.setAuthCredentials({'username': user, 'password': pword})

        # generate and send inbox messages
        # one message per feed, with appropriate TargetFeed header specified

        failed = True
        status = ""

        # if version=0, Poll using 1.1 then 1.0 if that fails.
        try:
            while True:
                if version in ('0', '1.1'):
                    content_block = build_content_block(tm11, stix_doc, fcert)
                    result = gen_send(tm11, client, content_block, hostname,
                                      t.VID_TAXII_XML_11,
                                      dcn = [feedname],
                                      url = path,
                                      port = port)
                else: # '1.0' should be the only other option
                    content_block = build_content_block(tm, stix_doc, fcert)
                    result = gen_send(tm, client, content_block, hostname,
                                    t.VID_TAXII_XML_10,
                                    eh = {'TargetFeed': feedname},
                                    url = path,
                                    port = port)
                if len(result) == 2:
                    res = result[1]
                    if res.status_type == tm11.ST_SUCCESS:
                        failed = False
                        ret['rcpts'].append(rcpt)
                        break
                    else:
                        status += "Server Response: " + res.message
                else:
                    status += "Error: " + cgi.escape(result[0])

                if version == '0': # if version is unknown & '1.1' failed
                    status = 'TAXII 1.1 ' + status + '<br><br>TAXII 1.0 '
                    version = '1.0' # try '1.0'
                else: # specific version provided, so done
                    break
        except IOError as e:
            msg = "Error reading encryption certificate - %s" % e
            ret['failed_rcpts'].append((rcpt, msg))
            continue

        if failed:
            ret['failed_rcpts'].append((rcpt, status))
        else: # update releasability for successful TAXII messages
            verify_releasability([source], stix_msg['final_objects'],
                                 analyst, True)

    ret['success'] = True
    return ret

def build_content_block(tm_, stix_doc, cert):
    """
    Build a content block from the STIX document. Encrypt it if a
    certificate is provided.

    :param tm_: The TAXII version that we should use.
    :type tm_: TAXII message class.
    :param stix_doc: The STIX document.
    :type stix_doc: class 'stix.core.stix_package.STIXPackage'
    :param cert: Path to the certificate used to encrypt the content block.
    :type cert: str
    :returns: A content block class
    """
    content_block = tm_.ContentBlock(content_binding = t.CB_STIX_XML_111,
                                     content = stix_doc.to_xml())

    if cert: # if encryption cert provided, encrypt the content_block
        encrypted_block = encrypt_block(content_block.to_xml(), cert)

        # Wrap encrypted block in content block
        content_block = tm_.ContentBlock(
                             content_binding = "application/x-pkcs7-mime",
                             content = encrypted_block)
    return content_block

def gen_send(tm_, client, content_block, hostname, t_xml, dcn=None, eh=None,
             url="/inbox/", port=None):
    """
    Generate and send a TAXII message.

    :param tm_: The TAXII version imported that we should use.
    :type tm_: TAXII message class.
    :param client: The TAXII client to use.
    :type client: TAXII Client.
    :param content_block: The content block to use.
    :type content_block: TAXII Content Block
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
    :param port: The TAXII server port to connect to.
    :type port: str
    :returns: tuple (response, taxii_message) or (exception message)
    """

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
            inbox_message.to_xml(),
            port
        )
        taxii_message = t.get_message_from_http_response(response,
                                                         inbox_message.message_id)
        return (response, taxii_message)
    # can happen if 'hostname' is reachable, but is not a TAXII server, etc
    except Exception as e:
        return (str(e),)

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

def add_feed_config_buttons(html):
    """
    Modify the form html to include buttons enabling the addition, editing,
    and removal of feeds.

    :return str
    """

    # Add TAXII Feed config buttons to form
    html = str(html)
    idx = html.rfind('</select>')
    buttons = '<br /><input class="form_submit_button" type="button" id="add" value="Add" /> <input class="form_submit_button" type="button" id="edit" value="Edit Selected" /> <input class="form_submit_button" type="button" id="remove" value="Remove Selected" />'
    return SafeText(html[0:idx+9] + buttons + html[idx:])

def get_taxii_server_config(server):
    """
    Get the TAXII Server config in the DB.

    :return dictionary
    """

    cfg = ''
    feeds = []
    status = {'success': False}

    if server:
        service = CRITsService.objects(name='taxii_service',
                                       status__ne="unavailable").first()
        if not service:
            msg = 'Service "%s" unavailable. Please review error logs.' % name
            status['config_error'] = msg
            status['form'] = ''
            status['service'] = ''
            return status

        cfg = service.config.taxii_servers[server]
        try:
            feeds = [(x, cfg['feeds'][x]['feedname']) for x in cfg['feeds']]
        except (AttributeError, KeyError):
            feeds = []

        cfg['servername'] = server
        cfg['cur_sname'] = server
    status['form'] = forms.TAXIIServerConfigForm(feeds, initial=cfg)

    # Add TAXII Feed config buttons to form
    status['html'] = add_feed_config_buttons(status['form'])

    status['success'] = True
    return status

def update_taxii_server_config(updates, analyst):
    """
    Update the TAXII Server config in the DB.

    :return dictionary
    """
    result = {'success': False}
    service = CRITsService.objects(name='taxii_service').first()
    servers = service.config.taxii_servers
    if 'remove_server' in updates:
        try:
            del servers[updates['remove_server']]
        except:
            pass
    elif 'remove_feed' in updates:
        try:
            srv_name = updates.get('srv_name')
            sdict = service.to_dict()
            servers = sdict['config']['taxii_servers']
            del servers[srv_name]['feeds'][updates['remove_feed']]
            service.config.taxii_servers = servers
        except:
            pass
    elif 'edit_feed' in updates:
        if not updates['edit_feed']:
            result['success'] = False
            return result
        data = servers[updates['srv_name']]['feeds'][updates['edit_feed']]
        hostname = servers[updates['srv_name']].get('hostname', '')
        last = taxii.Taxii.get_last(hostname + ':' + data['feedname'])
        if last:
            data['last_poll'] = str(pytz.utc.localize(last.end)).split('+')[0]
        else:
            data['last_poll'] = "No Record of Previous Poll"
        result.update(data)
        result['fid'] = updates['edit_feed']
        result['success'] = True
        return result
    elif updates:
        # Get the class that implements this service.
        from . import TAXIIClient
        taxii_class = TAXIIClient()
        try:
            if 'servername' in updates:
                taxii_class.parse_server_config(updates)
                name = updates.pop('servername', None)
                cur_sname = updates.pop('cur_sname', None)
                if not cur_sname:
                    cur_sname = name

                try:
                    if 'feeds' in servers.get(cur_sname, {}):
                        updates['feeds'] = servers[cur_sname]['feeds']
                    else:
                        updates['feeds'] = {}

                    # Remove existing if changing servername
                    if cur_sname and cur_sname != name:
                        del servers[cur_sname]

                    servers[name] = updates
                except AttributeError:
                    servers = {}
                    servers[name] = updates
            elif 'feedname' in updates:
                taxii_class.parse_feed_config(updates)
                srv_name = updates.pop('srv_name', None)
                fid = updates.pop('fid', None)

                sdict = service.to_dict()
                servers = sdict['config']['taxii_servers']

                try:
                    feeds = servers[srv_name]['feeds']
                    if not fid:
                        fid = len(feeds)
                        while str(fid) in feeds:
                            fid += 1
                    feeds[str(fid)] = updates
                    servers[srv_name]['feeds'] = feeds
                except (KeyError, TypeError):
                    if not isinstance(servers, dict):
                        servers = {}
                    servers[srv_name] = {'feeds': {'0': updates}}

                service.config.taxii_servers = servers
        except ServiceConfigError as e:
            result['error'] = str(e)
            return result

    try:
        service.save(username=analyst)
    except ValidationError, e:
        result['message'] = e
        return result

    if 'remove_server' in updates:
        service.reload()
        choices = ''
        for choice in service.config.taxii_servers:
            choices += '<option value="%s">%s</option>' % (choice, choice)
        result['html'] = choices
    elif 'remove_feed' in updates or 'subID' in updates:
        service.reload()
        choices = ''
        feeds = service.config.taxii_servers[srv_name]['feeds']
        html = '<option value="%s">%s</option>'
        for choice in feeds:
            choices += html % (choice,
                               feeds[choice]['feedname'])
        result['html'] = choices

    result['success'] = True
    return result

def update_taxii_service_config(post_data, analyst):
    """
    Update the TAXII Service config in the DB.

    :return dictionary
    """
    status = {'success': False}
    service = CRITsService.objects(name='taxii_service',
                                   status__ne="unavailable").first()
    if not service:
        msg = 'Service "%s" is unavailable. Please review error logs.' % name
        status['config_error'] = msg
        status['form'] = ''
        status['service'] = ''
        return status

    # Get the class that implements this service.
    from . import TAXIIClient
    taxii_class = TAXIIClient()

    config = service.config.to_dict()
    cfg_form, html = taxii_class.generate_config_form(config)
    # This isn't a form object. It's the HTML.
    status['form'] = html
    status['service'] = service

    if post_data:
        #Populate the form with values from the POST request
        form = cfg_form([], post_data)
        if form.is_valid():
            try:
                taxii_class.parse_service_config(form.cleaned_data)
            except ServiceConfigError as e:
                service.status = 'misconfigured'
                service.save()
                status['config_error'] = str(e)
                return status

            form.cleaned_data['taxii_servers'] = config['taxii_servers']
            result = update_config('taxii_service',
                                   form.cleaned_data, analyst)

            if not result['success']:
                return status

            service.status = 'available'
            service.save()
        else:
            status['config_error'] = form.errors
            return status

    status['success'] = True
    return status

def import_standards_doc(data, analyst, method, ref=None, hdr_events=False,
                         def_ci=None, source=None, use_hdr_src=False,
                         obs_as_ind=False, preview_only=False):
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
    :param hdr_events: Whether or not we should make an Event for this document.
    :type hdr_events: bool
    :param def_ci: The default Indicator (confidence, impact).
    :type def_ci: tuple
    :param source: The name of the source who provided this document.
    :type source: str
    :param use_hdr_src: If True, try to use the STIX Header Information
                         Source instead of the value in "source" parameter
    :type use_hdr_src: boolean
    :param obs_as_ind: If True, create indicators for all qualifying
	                   observables instead of Domain and IP TLOs
    :type obs_as_ind: boolean
    :param preview_only: If True, nothing is imported and a preview is returned
    :type preview_only: boolean
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
        parser = STIXParser(data, analyst, method, def_ci, preview_only)
        parser.parse_stix(ref, hdr_events, source, use_hdr_src, obs_as_ind)
        parser.relate_objects()
    except STIXParserException as e:
        logger.exception(str(e))
        ret['reason'] = str(e.message)
        return ret
    except Exception as e:
        logger.exception(str(e))
        ret['reason'] = str(e)
        return ret

    ret['imported'] = parser.imported
    ret['failed'] = parser.failed
    ret['success'] = True
    return ret
