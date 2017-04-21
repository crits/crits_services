import sys
import tarfile
import time
from io import BytesIO
from optparse import OptionParser

from crits.core.basescript import CRITsBaseScript
from crits.samples.sample import Sample

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option('-b', '--bucket', action='store', dest='bucket', 
                          type='string', help='bucket list name')
        parser.add_option("-o", "--output-file", action="store", dest="outfile", 
                          type="string", help="output archive file (no extension)")
        (opts, args) = parser.parse_args(argv)

        samples = Sample.objects(bucket_list=opts.bucket)
        if opts.bucket and opts.outfile:
            filename = "%s.tar.bz2" % opts.outfile
            try:
                tar = tarfile.open(filename, "w:bz2")
            except Exception as e:
                print ("Error when attempting to open %s for writing: %s" % (filename, e))
                sys.exit(1)
        count = len(samples)
        if count <= 0:
            print ("No matching bucket name found!")
            sys.exit(1)
        for sample in samples:
            m = sample.md5
            f = sample.filename
            s = sample.filedata.read()
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
            
            
