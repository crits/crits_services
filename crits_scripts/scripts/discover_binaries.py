import ast
import sys

from optparse import OptionParser

from crits.core.basescript import CRITsBaseScript
from crits.samples.sample import Sample

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--filter", action="store", dest="filter",
                type="string", help="filter for samples to discover binaries")
        (opts, args) = parser.parse_args(argv)

        if opts.filter:
            query = ast.literal_eval(opts.filter)
        else:
            query = {}

        errorpath = "/tmp/gridfs_migrate_errors.txt"
        try:
            err = open(errorpath, "w")
        except:
            print "Could not open file handle to write to: %s" % errorpath
            sys.exit(1)

        error_count = 0
        samples = Sample.objects(__raw__=query)
        count = len(samples)
        print "Migrating %s samples found with query %s...\n" % (count, query)
        i = 1
        for s in samples:
            md5 = s.md5
            try:
                print >> sys.stdout, "\r\tWorking on sample %d of %d" % (i, count),
                sys.stdout.flush()
                s.discover_binary()
                s.save()
            except Exception, e:
                error_count += 1
                err.write("Error saving sample for discover binary: %s - %s" % (md5, e))
            i += 1
        if error_count:
            print "Check %s for samples that didn't get their binaries updated!" % errorpath
        print "Discover binaries process has completed."
