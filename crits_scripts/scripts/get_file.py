from optparse import OptionParser

from crits.core.mongo_tools import get_file
from crits.samples.sample import Sample
from crits.samples.handlers import get_filename
from crits.core.basescript import CRITsBaseScript


class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-c", "--collection", action="store", dest="collection",
                type="string", help="collection (if not samples)")
        parser.add_option("-m", "--md5", action="store", dest="md5",
                type="string", help="md5 of file")
        parser.add_option("-o", "--output", action="store", dest="filename",
                type="string", help="output filename")
        (opts, args) = parser.parse_args(argv)
        data = None
        collection = opts.collection or Sample._meta['collection']
        if opts.md5:
            try:
                data = get_file(opts.md5, collection=collection)
            except:
                print "[+] could not read data for %s" % opts.md5
                return

        if data:
            if opts.filename:
                filename = opts.filename
            else:
                filename = get_filename(opts.md5, collection=collection)
            if filename == None:
                filename = opts.md5
            print "[+] writing %d bytes to %s" % (len(data), filename)
            try:
                fin = open(filename, 'wb')
                fin.write(data)
                fin.close()
            except:
                print "[+] error writing %s to disk" % filename
