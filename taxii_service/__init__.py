import logging
import os
import socket
import datetime
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages as tm


from M2Crypto import BIO, Rand, SMIME, X509
from crits import settings
from crits.core.handlers import does_source_exist
from crits.core.crits_mongoengine import Releasability
from crits.events.event import Event
from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)

class TAXIIClient(Service):
    """
    Send TAXII message to TAXII server.
    """

    name = "taxii_service"
    version = "1.0.1"
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Event']
    required_fields = ['_id']
    rerunnable = True
    description = "Send TAXII messages to a TAXII server."
    template = "taxii_service_results.html"
    default_config = [
        ServiceConfigOption('hostname',
                            ServiceConfigOption.STRING,
                            description="TAXII Server hostname.",
                            default=None,
                            required=True,
                            private=True
                            ),
        ServiceConfigOption('keyfile',
                            ServiceConfigOption.STRING,
                            description="Location of your keyfile on the server.",
                            default=None,
                            required=True,
                            private=True
                            ),
        ServiceConfigOption('certfile',
                            ServiceConfigOption.STRING,
                            description="Location of your certfile on the server.",
                            default=None,
                            required=True,
                            private=True
                            ),
        ServiceConfigOption('data_feed',
                            ServiceConfigOption.STRING,
                            description="Your TAXII Data Feed Name.",
                            default=None,
                            required=True,
                            private=True
                            ),
        ServiceConfigOption('certfiles',
                            ServiceConfigOption.LIST,
                            description=("Comma-delimited list of CRITs Source"
                                         " name, TAXII feed name, and"
                                         " corresponding certificate"
                                         " file on disk for that source."),
                            default=None,
                            required=True,
                            private=True
                            ),
    ]

    @classmethod
    def _validate(cls, config):
        hostname = config.get("hostname", "").strip()
        keyfile = config.get("keyfile", "").strip()
        certfile = config.get("certfile", "").strip()
        data_feed = config.get("data_feed", "").strip()
        certfiles = config.get("certfiles", "")
        if not hostname:
            raise ServiceConfigError("You must specify a TAXII Server.")
        if not keyfile:
            raise ServiceConfigError("You must specify a keyfile location.")
        if  not os.path.isfile(keyfile):
            raise ServiceConfigError("keyfile does not exist.")
        if not certfile:
            raise ServiceConfigError("You must specify a certfile location.")
        if  not os.path.isfile(certfile):
            raise ServiceConfigError("certfile does not exist.")
        if not data_feed:
            raise ServiceConfigError("You must specify a TAXII Data Feed.")
        if not certfiles:
            raise ServiceConfigError("You must specify at least one certfile.")
        for crtfile in certfiles:
            try:
                (source, feed, filepath) = crtfile.split(',')
            except ValueError:
                raise ServiceConfigError(("You must specify a source, feed name"
                                              ", and certificate path for each source."
                                             ))
            source.strip()
            feed.strip()
            filepath.strip()
            if not does_source_exist(source):
                raise ServiceConfigError("Invalid source: %s" % source)
            if  not os.path.isfile(filepath):
                raise ServiceConfigError("certfile does not exist: %s" % filepath)

    def __init__(self, *args, **kwargs):
        super(TAXIIClient, self).__init__(*args, **kwargs)
        return
        logger.debug("Initializing TAXII Client.")
        self.hostname = self.config['hostname'].strip()
        self.keyfile = self.config['keyfile'].strip()
        self.certfile = self.config['certfile'].strip()
        self.certfiles = self.config['certfiles']

    def _scan(self, context):
        #TODO: not sure if this should come after we make the TAXII message
        #      so the check is closer to actual submission time?
        if not resolve_taxii_server(self.hostname):
            self._error("Cannot contact TAXII Server: %s" % self.hostname)
            return
        else:
            self._info("TAXII Server Online: %s" % self.hostname)
            self._notify()
            client = tc.HttpClient()
            client.setUseHttps(True)
            client.setAuthType(tc.HttpClient.AUTH_CERT)
            client.setAuthCredentials({'key_file': self.keyfile,
                                'cert_file': self.certfile})

            if settings.HTTP_PROXY:
                proxy = settings.HTTP_PROXY
                if not proxy.startswith('http://'):
                    proxy = 'http://' + proxy
                client.setProxy(proxy, proxy_type=tc.HttpClient.PROXY_HTTPS)

            event_list = Event.objects(id=context._id)
            if len(event_list) < 1:
                self._info("Could not locate event in the database")
                self._notify()
            else:
                event_data = event_list[0]
                (stix_doc, final_sources, final_objects) = event_data.to_stix(context.username)
                if len(final_sources) < 1:
                    self._error("No sources to send to! Ensure all related content is marked as releasable!")
                    return
                final_objects.append(event_data)

                # collect the list of data feeds to send this message to
                destination_feeds = []
                for crtfile in self.certfiles:
                    (source, feed, filepath) = crtfile.split(',')
                    if source.strip() in final_sources:
                        destination_feeds.append((source.strip(), feed.strip(), filepath.strip()))

                self._info("Generating STIX document(s).")
                self._notify()
                inbox_messages = []

                # generate inbox messages
                # for now we will send one message per feed to isolate failures to one
                # feed submission and not prevent other messages from being sent.
                for feed in destination_feeds:
                    # Create encrypted block
                    encrypted_block = encrypt_block(
                        tm.ContentBlock(
                            content_binding = t.CB_STIX_XML_10,
                            content = stix_doc.to_xml()).to_xml(),
                        feed[2]
                    )
                    # Wrap encrypted block in content block
                    content_block = tm.ContentBlock(
                        content_binding = "SMIME",
                        content = encrypted_block
                    )
                    # Create inbox message
                    inbox_message = tm.InboxMessage(
                        message_id = tm.generate_message_id(),
                        content_blocks = [content_block],
                        extended_headers = {'TargetFeed': feed[1]}
                    )

                    inbox_messages.append((feed[0], inbox_message))

                self._info("Sending TAXII message(s)")
                self._notify()

                # send messages
                for (src, inbox_msg) in inbox_messages:
                    response = client.callTaxiiService2(self.hostname,
                                                        "/inbox/",
                                                        t.VID_TAXII_XML_10,
                                                        inbox_message.to_xml())
                    taxii_message = t.get_message_from_http_response(response, inbox_message.message_id)
                    if taxii_message.status_type == tm.ST_SUCCESS:
                        # update releasability for objects
                        date = datetime.datetime.now()
                        instance = Releasability.ReleaseInstance(analyst=context.username, date=date)
                        for idx in enumerate(final_objects):
                            final_objects[idx[0]].add_releasability_instance(name=src, instance=instance)
                        self._add_result(self.name, "Success", {'recipient': src})
                    else:
                        self._add_result(self.name, "Failure", {'recipient': src})
                # save releasability to database
                self._info("Updated releasability status for all related content.")
                self._notify()
                for obj in final_objects:
                    obj.save()
                return


def resolve_taxii_server(hostname):
    try:
        socket.gethostbyname(hostname)
        return 1
    except socket.error:
        return 0

# Take in a blob of data and a public key. Encrypts and
# returns the encrypted blob.
def encrypt_block(blob, pubkey):
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
