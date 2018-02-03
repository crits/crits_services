import sys
import time
import tarfile
from io import BytesIO
from optparse import OptionParser

import bson
from crits.core.mongo_tools import *
from crits.core.basescript import CRITsBaseScript
import settings

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-y", "--yara-hit", action="store", dest="yarahit",
                type="string", help="string of yarahit")
        parser.add_option("-o", "--output-file", action="store", dest="outfile",
                type="string", help="output archive file (no extension)")
        (opts, args) = parser.parse_args(argv)
        if opts.yarahit and opts.outfile:
            filename = "%s.tar.bz2" % opts.outfile
            try:
                tar = tarfile.open(filename, "w:bz2")
            except Exception as e:
                print ("Error when attempting to open %s for writing: %s" % (filename, e))
                sys.exit(1)
            samples = mongo_connector(settings.COL_ANALYSIS_RESULTS)
            results = samples.find({'results.result': '%s' % opts.yarahit}, {'object_id': 1})
            count = results.count()
            if count <= 0:
                print ("No matching samples found!")
                sys.exit(1)
            for result in results:
                print ("oid next in %s " % settings.COL_SAMPLES )
                boid = result['object_id']
                print ("oid: %s" % str(boid))
                try:
                    fm = mongo_connector(settings.COL_SAMPLES)
                    f = fm.find_one({'_id': bson.ObjectId(oid=str(boid))}, {'filename':1 })['filename']
                    m = fm.find_one({ '_id' : bson.ObjectId(oid=str(boid))}, {'md5':1})['md5']
                    print ("m: %s" % str(m))
                except Exception as e:
                    print ("Error : %s" % (e))
                    return None
                s = get_file(m)
                info = tarfile.TarInfo(name="%s" % f)
                info.mtime = time.time()
                if s is not None:
                    info.size = len(s)
                else:
                    info.size = 0
                try:
                    tar.addfile(info, BytesIO(s))
                except Exception as e:
                    print ("Error attempting to add %s to the tarfile: %s" % (f, e))
                    pass
            tar.close()
            print ("Generated %s containing %s files." % (filename, count))
