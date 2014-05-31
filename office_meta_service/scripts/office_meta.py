from optparse import OptionParser

from django.core.mail import send_mail
from crits.core.mongo_tools import get_file
from crits.core.basescript import CRITsBaseScript
from office_meta_service.office_meta import OfficeParser

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-m", "--md5", action="store", dest="md5",
                type="string", help="MD5 of file to retrieve")
        parser.add_option("-f", "--file", action="store", dest="file",
                type="string", help="File to analyze")
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                default=False, help="Be verbose")
        (opts, args) = parser.parse_args(argv)

        if opts.md5:
            if opts.verbose:
                print "[+] attempting to call get_file on %s" % opts.md5
            data = get_file(opts.md5)
        elif opts.file:
            fin = open(opts.file, 'rb')
            data = fin.read()
            fin.close()
        if opts.verbose:
            print "[+] parsing %d bytes" % len(data)
        if len(data) > 512:
            oparser = OfficeParser(data, opts.verbose)
            oparser.parse_office_doc()
