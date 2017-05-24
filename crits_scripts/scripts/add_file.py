from optparse import OptionParser
import hashlib
import os

from crits.samples.handlers import handle_file
from crits.core.basescript import CRITsBaseScript
from crits.vocabulary.acls import SampleACL

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--file", action="store", dest="filename",
                type="string", help="scanned FILENAME")
        parser.add_option("-s", "--source", action="store",
                dest="source", type="string", help="source")
        parser.add_option("-p", "--parent", action="store", dest="parent_md5",
                type="string", help="parent MD5")
        parser.add_option("-i", "--parent-id", action="store", dest="parent_id",
                type="string", help="parent ID")
        parser.add_option("-P", "--parent-type", action="store", dest="parent_type",
                type="string", default="Sample", help="parent type (Sample, PCAP, ...)")
        parser.add_option("-t", "--trojan", action="store", dest="trojan",
                type="string", help="trojan")
        parser.add_option("-r", "--reference", action="store", dest="reference",
                type="string", help="reference field")
        parser.add_option("-b", "--bucket", action="store", dest="bucket_list",
                type="string", help="bucket list")
        parser.add_option("-T", "--tlp", action="store", dest="tlp",
                type="string", default="red", help="TLP of data")

        (opts, args) = parser.parse_args(argv)

        md5hash = hashlib.md5()
        if opts.source:
            source = opts.source
        else:
            print "[-] Source required, none provided"
            return
        if opts.parent_md5 and opts.parent_id:
            print "[-] Specify one of -p or -i!"
            return
        if not user.has_access_to(SampleACL.WRITE):
            print "[-] User does not have permission to add Samples."
            return
        if not opts.tlp or opts.tlp not in ['red', 'amber', 'green', 'white']:
            opts.tlp = 'red'

        try:
            fin = open(opts.filename, 'rb')
            data = fin.read()
            fin.close()
            md5hash.update(data)
            sourcemd5 = md5hash.hexdigest()
            print "[+] Read %d from %s" % (len(data), opts.filename)
        except:
            print "[-] Cannot open %s for reading!" % opts.filename
            return
        if opts.parent_md5:
            parent_md5 = opts.parent_md5
        else:
            parent_md5 = None
        if opts.parent_id:
            parent_id = opts.parent_id
        else:
            parent_id = None
        parent_type = opts.parent_type
        if opts.trojan:
            trojan = opts.trojan
        else:
            trojan = None
        fname = opts.filename
        (dirname, filename) = os.path.split(fname)
        sample = handle_file(
            filename,
            data,
            source,
            source_reference=opts.reference,
            source_tlp=opts.tlp,
            backdoor=trojan,
            user=self.user,
            related_md5=parent_md5,
            related_id=parent_id,
            related_type=parent_type,
            source_method="Command line add_file.py",
            bucket_list=opts.bucket_list)
        if sourcemd5 != sample:
            print "[-] Source MD5: %s is not the same as the returned MD5: %s" % (sourcemd5, sample)
        else:
            print "[+] Added %s (MD5: %s)" % (filename, sample)
