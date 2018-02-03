from distutils.version import StrictVersion

import tempfile
import sys
import os
import time
import hashlib
import json
from base64 import b64decode

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse

from crits.pcaps.pcap import PCAP
from crits.samples.handlers import handle_file
from crits.emails.handlers import handle_eml
from crits.services.handlers import get_config
from crits.vocabulary.relationships import RelationshipTypes
import crits.services

def chopshop_carver(pcap_md5, options, analyst):
    # Make sure we can find ChopShop
    sc = get_config('ChopShop')
    user = get_user_info(analyst)

    if not sc:
        return {'success': False, 'message': 'Could not find ChopShop service.'}

    shop_path = "%s/shop" % str(sc['basedir'])
    if not os.path.exists(shop_path):
        return {'success': False, 'message': "ChopShop shop path does not exist."}

    sys.path.append(shop_path)
    import ChopLib as CL
    if StrictVersion(str(CL.VERSION)) < StrictVersion('4.0'):
        return {'success': False, 'message': 'Need ChopShop 4.0 or newer'}

    # Until we have an smtp_extractor in ChopShop we have to resort to
    # to (ab)using payloads to dump the entire TCP stream and letting
    # handle_eml() process everything. We also use the payloads module
    # for handling raw carves. If a user wants to do SMTP and raw
    # simultaneously it won't work because we can't distinguish one
    # payloads module from another.
    if options.get('raw', False) and options.get('smtp', False):
        return {'success': False, 'message': "Can not process SMTP and raw simultaneously."}

    # Make sure we have a PCAP to work with
    pcap = PCAP.objects(md5=pcap_md5).first()
    if not pcap:
        return {'success': False, 'message': "No PCAP found."}
    pcap_data = pcap.filedata.read()
    if not pcap_data:
        return {'success': False, 'message': "Could not get PCAP from GridFS: %s" %  pcap_md5}

    source = pcap['source'][0]['name'] # XXX: This kind of sucks...

    # Create module string to pass to ChopShop
    modules = []
    if options.get('http_resp', False) or options.get('http_req', False):
        modules.append("http | http_extractor")

    if options.get('smtp', False) or options.get('raw', False):
        # ChopShop really needs an smtp_extractor, but there's no good
        # capability to do that yet. Maybe one day I'll build one. :)
        # For now, just use payloads and let handle_eml() sort it out.
        #
        # Raw carving works exactly the same way, just post-processed
        # differently.
        modules.append("payloads -b")

    if not modules:
        return {'success': False, 'message': "No modules specified."}

    mod_string = ';'.join(mod for mod in modules)

    from ChopLib import ChopLib
    from ChopUi import ChopUi

    choplib = ChopLib()
    chopui = ChopUi()

    choplib.base_dir = str(sc['basedir'])

    choplib.modules = mod_string

    chopui.jsonout = jsonhandler
    choplib.jsonout = True

    # ChopShop (because of pynids) needs to read a file off disk.
    # Write the pcap data to a temporary file.
    temp_pcap = tempfile.NamedTemporaryFile(delete=False)
    temp_pcap.write(pcap_data)
    temp_pcap.close()

    choplib.filename = temp_pcap.name
    chopui.bind(choplib)
    chopui.start()

    if chopui.jsonclass == None:
        os.unlink(temp_pcap.name)
        chopui.join()
        choplib.finish()
        choplib.join()
        return {'success': False,
                'message': 'Lost race condition in chopui. Try again.'}

    # ChopUI must be started before the jsonhandler class is insantiated.
    # Tell the class what we are looking for now that it exists.
    chopui.jsonclass.parse_options(options)

    choplib.start()

    while chopui.is_alive():
        time.sleep(.1)

    chopui.join()
    choplib.finish()
    choplib.join()

    os.unlink(temp_pcap.name)

    message = ''

    # Grab any carved HTTP bodies.
    for (md5_digest, (name, blob)) in chopui.jsonclass.http_files.items():
        if user.has_access_to(SampleACL.WRITE) and handle_file(name, blob, source, related_md5=pcap_md5, user=user, source_method='ChopShop Filecarver', md5_digest=md5_digest, related_type='PCAP'):
            # Specifically not using name here as I don't want to deal
            # with sanitizing it
            message += "Saved HTTP body: <a href=\"%s\">%s</a><br />" % (reverse('crits-samples-views-detail', args=[md5_digest]), md5_digest)
        else:
            message += "Failed to save file %s." % md5_digest

    # Grab any carved SMTP returns.
    for blob in chopui.jsonclass.smtp_returns.values():
        ret = handle_eml(blob, source, None, analyst, 'ChopShop FileCarver',
                         related_id=pcap.id, related_type='PCAP',
                         relationship_type=RelationshipTypes.RELATED_TO)
        if not ret['status']:
            message += ret['reason']
            continue

        message += "Saved email: <a href=\"%s\">%s</a><br />%i attachment(s)<br />" % (reverse('crits-emails-views-email_detail', args=[ret['object'].id]), ret['object'].id, len(ret['attachments'].keys()))

        for md5_digest in ret['attachments'].keys():
            message += "<a href=\"%s\">%s</a><br />" % (reverse('crits-samples-views-detail', args=[md5_digest]), md5_digest)

    # Handle raw returns.
    for id_, blob in chopui.jsonclass.raw_returns.items():
        if user.has_access_to(SampleACL.WRITE):
            md5_digest = handle_file(id_, blob, source, related_md5=pcap_md5, user=user, source_method='ChopShop Filecarver', related_type='PCAP')
        else:
            md5_digest = None
        if md5_digest:
            message += "Saved raw %s: <a href=\"%s\">%s</a><br />" % (id_, reverse('crits-samples-views-detail', args=[md5_digest]), md5_digest)
        else:
            message += "Failed to save raw %s." % md5_digest

    # It's possible to have no files here if nothing matched.
    # Still return True as there were no problems.
    if not message:
        message = 'No files found.'
    return {'success': True, 'message': message}

class jsonhandler:
    def __init__(self, ui_stop_fn=None, lib_stop_fn=None, format_string=None):
        self.service = None
        self.http_files = {} # Key is the MD5, value is a tuple (name, data)
        self.smtp_returns = {} # Key is quadtuple, value is data
        self.raw_returns = {} # Key is quadtuple, value is data
        self.types = []
        self.http_req = False
        self.http_resp = False
        self.smtp = False
        self.raw = False

    def parse_options(self, options):
        if options['types']:
            self.types = [str(t) for t in options['types'].split(',')]
        self.http_req = options['http_req']
        self.http_resp = options['http_resp']
        self.smtp = options['smtp']
        self.raw = options['raw']

    # Given a chunk of JSON data (request or response)
    # grab the body if we want it, save it to self.http_files.
    # Path is used as the filename to save as.
    def __grab_body(self, chunk, path):
        if self.types and chunk.get('headers', {}).get('Content-Type', '') not in self.types:
            return

        # If http_extractor ever supports other encoding for bodies
        # this will have to be updated.
        body = b64decode(chunk.get('body', ""))
        if not body:
            return

        # XXX: Steal sanitize_filename() from ChopShop?
        name = os.path.basename(path)
        md5_digest = hashlib.md5(body).hexdigest()
        if not name:
            name = md5_digest
        self.http_files[md5_digest] = (name, body)

    def handle_message(self, message):
        # The first 'data' is ChopShop stuffing the module
        # output into a key.
        # The second 'data' is from the module stuffing it's
        # output into a key.
        # It's ugly but that's what we get for not being
        # clever in our names.
        data = message['data']['data']
        # ChopShop stuffs the output of the module into a string... :(
        data = json.loads(data)

        # Expand this to other modules when they are added
        if message['module'] == "http_extractor":
            path = data.get('request', {}).get('uri', {}).get('path', '')
            if self.http_resp:
                self.__grab_body(data.get('response', {}), path)

            if self.http_req:
                self.__grab_body(data.get('request', {}), path)
        elif message['module'] == "payloads":
            # Payloads is used for both SMTP and raw carving.
            addr = message['addr']
            id_ = addr['src'] + ":" + str(addr['sport']) + "-" + addr['dst'] + ":" + str(addr['dport'])

            if self.smtp:
                returns = self.smtp_returns
            elif self.raw:
                id_ += "_" + data['direction']
                returns = self.raw_returns

            if id_ in returns:
                returns[id_] += b64decode(data['payload'])
            else:
                returns[id_] = b64decode(data['payload'])

    def handle_ctrl(self, message):
        pass

    def stop(self):
        pass
