import sys
import time
import tarfile
from StringIO import StringIO
from optparse import OptionParser

from crits.core.mongo_tools import *
from crits.core.basescript import CRITsBaseScript
import settings

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-y", "--yara-hit", action="store", dest="yarahit",
                type="string", help="string of yarahit")
        parser.add_option("-o", "--output-file", action="store", dest="outfile",
                type="string", help="output archive file (no extension)")
        (opts, args) = parser.parse_args(argv)
        data = None
        if opts.yarahit and opts.outfile:
            filename = "%s.tar.bz2" % opts.outfile
            try:
                tar = tarfile.open(filename, "w:bz2")
            except Exception, e:
                print "Error when attempting to open %s for writing: %s" % (filename, e)
                sys.exit(1)
            samples = mongo_connector(settings.COL_SAMPLES)
            results = samples.find({'analysis.results.result': '%s' % opts.yarahit}, {'filename': 1,'md5': 1})
            count = results.count()
            if count <= 0:
                print "No matching samples found!"
                sys.exit(1)
            for result in results:
                m = result['md5']
                f = result['filename']
                s = get_file(m)
                info = tarfile.TarInfo(name="%s" % f)
                info.mtime = time.time()
                if s is not None:
                    info.size = len(s)
                else:
                    info.size = 0
                try:
                    tar.addfile(info, StringIO(s))
                except Exception, e:
                    "Error attempting to add %s to the tarfile: %s" % (f, e)
                    pass
            tar.close()
            print "Generated %s containing %s files." % (filename, count)
