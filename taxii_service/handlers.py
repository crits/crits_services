import pytz
import socket
import os
from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzutc
from StringIO import StringIO
from M2Crypto import BIO, SMIME, X509, Rand

import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages as tm
import libtaxii.messages_11 as tm11

from django.conf import settings

from . import taxii
from . import formats
from crits.events.event import Event
from crits.core.crits_mongoengine import Releasability
from crits.standards.handlers import import_standards_doc
import crits.services

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

    sc = crits.services.manager.get_config('taxii_service')
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
        client.setProxy(proxy, proxy_type=tc.HttpClient.PROXY_HTTPS)

    crits_taxii = taxii.Taxii()
    crits_taxii.runtime = runtime
    crits_taxii.end = end

    poll_msg = tm.PollRequest(message_id=tm.generate_message_id(),
                              feed_name=feed,
                              exclusive_begin_timestamp_label=start,
                              inclusive_end_timestamp_label=end)
    response = client.callTaxiiService2(hostname, '/poll/', t.VID_TAXII_XML_10,
                                        poll_msg.to_xml())

    if response.getcode() != 200:
        ret['reason'] = "Response is not 200 OK"
        return ret

    taxii_msg = t.get_message_from_http_response(response, poll_msg.message_id)

    valid = tm.validate_xml(taxii_msg.to_xml())
    if valid != True:
        ret['reason'] = valid
        return ret

    if taxii_msg.message_type != tm.MSG_POLL_RESPONSE:
        ret['reason'] = "No poll response"
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
            ret[k[0]].append(k[1])
        for k in objs['failed']:
            ret['failures'].append(k)


    crits_taxii.save()
    return ret

def parse_content_block(content_block, privkey=None, pubkey=None):
    if content_block.content_binding == 'application/x-pks7-mime':
        if not privkey and not pubkey:
            return None

        inbuf = BIO.MemoryBuffer(StringIO(content_block.content).read())
        s = SMIME.SMIME()
        try:
            s.load_key(privkey, pubkey)
            p7, data = SMIME.smime_load_pkcs7_bio(inbuf)
            buf = s.decrypt(p7)
        except SMIME.PKCS7_Error:
            return None
        f = StringIO(buf)
        new_block = f.read()
        f.close()
        return parse_content_block(tm.ContentBlock.from_xml(new_block), privkey, pubkey)
    elif content_block.content_binding == t.CB_STIX_XML_10:
        f = StringIO(content_block.content)
        data = f.read()
        f.close()
        return data
    else:
        return None

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
    sc = manager.get_config('taxii_service')
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
    stix_msg = obj.to_stix(relation_choices, bin_fmt="base64")
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
        client.setProxy(proxy, proxy_type=tc.HttpClient.PROXY_HTTPS)

    # generate and send inbox messages
    # one message per feed, with appropriate TargetFeed header specified
    # Store each TAXII message in a list.
    for feed in destination_feeds:
        rcpt = feed[0]
        # Create encrypted block
        encrypted_block = encrypt_block(
            tm.ContentBlock(
                content_binding = t.CB_STIX_XML_10,
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
