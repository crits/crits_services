import optparse

from crits.services.core import ServiceManager
from crits.services.db import DatabaseAnalysisDestination
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        usage = "usage: %prog [options] MD5 ..."
        parser = optparse.OptionParser(usage=usage)
        parser.add_option("-s", "--service", action="store",
                help="The service whose results to delete")
        #parser.add_option("-m", "--md5", action="store_true",
        #        help="TARGETS is one or more MD5 hashes of file to "
        #        "analyze (from database)")
        #parser.add_option("-f", "--files", action="store_true",
        #        help="TARGETS is one or more filenames to analyze")
        parser.add_option("-d", "--debug", action="store_true",
                help="Debug (Verbose output)", default=False)
        (opts, args) = parser.parse_args(argv)

        if not opts.service:
            parser.error("Service not specified")
        if len(args) == 0:
            parser.error("No targets specified")

        m = ServiceManager()

        service = opts.service
        if service not in m.services:
            print "Warning: unknown service %s" % service

        dest = DatabaseAnalysisDestination()

        for md5 in args:
            print "Deleting %s (%s)" % (md5, service)
            dest._delete_all_analysis_results(md5, service)
        print "Done"
