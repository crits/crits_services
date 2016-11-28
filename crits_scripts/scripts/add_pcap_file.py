import os
import hashlib
from optparse import OptionParser

from crits.pcaps.handlers import handle_pcap_file
from crits.core.basescript import CRITsBaseScript
from crits.vocabulary.acls import PCAPACL

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-d", "--description", action="store", dest="description",
                type="string", default="", help="PCAP Description")
        parser.add_option("-f", "--file", action="store", dest="filename",
                type="string", help="scanned FILENAME")
        parser.add_option("-s", "--source", action="store",
                dest="source", type="string", help="source")
        parser.add_option("-m", "--method", action="store",
                dest="method", type="string", help="source method")
        parser.add_option("-r", "--reference", action="store",
                dest="reference", type="string", help="source reference")
        parser.add_option("-p", "--parent", action="store", dest="parent",
                type="string", default="", help="parent md5")
        parser.add_option("-P", "--parent-type", action="store", dest="parent_type",
                type="string", default="PCAP", help="parent type (Sample, PCAP...)")
        parser.add_option("-t", "--tlp", action="store", dest="tlp",
                type="string", default="red", help="TLP of data")

        (opts, args) = parser.parse_args(argv)

        if not opts.filename:
            parser.error("File name not provided")
        filename = opts.filename

        if not opts.source:
            parser.error("Source not provided")
        source = opts.source

        if not self.user.has_access_to(PCAPACL.WRITE):
            print "[-] User does not have permission to add PCAP"
            return

        description = opts.description
        parent = opts.parent
        parent_type = opts.parent_type
        user = self.user
        method = opts.method or "Command line add_pcap_file.py"
        reference = opts.reference
        tlp = opts.tlp

        f = open(filename, 'rb')
        data = f.read()
        f.close()
        (dirname, fname) = os.path.split(filename)
        print parent
        print parent_type

        status = handle_pcap_file(fname, data, source, user, description,
                                  related_md5=parent, related_type=parent_type,
                                  method=method, reference=reference,
                                  tlp=tlp)

        if status['success']:
            md5 = hashlib.md5(data).hexdigest()
            print "[+] Added %s (MD5: %s)" % (filename, md5)
        else:
            print "[-] %s returned error: %s" % (filename, status['message'])
