from crits.core.basescript import CRITsBaseScript
from crits.standards.handlers import import_standards_doc

from optparse import OptionParser

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--file", dest="infile", action="store",
                          type="string", default='', help="File to import.")
        parser.add_option("-s", "--source", dest="source", action="store",
                          default=None, help="Source to use if not in file.")
        parser.add_option("-e", "--event", dest="event", action="store_true",
                          default=False, help="Make event.")
        parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                          default=False, help="Print saved objects.")

        (opts, args) = parser.parse_args(argv)

        if not opts.infile:
            print "Need a file to parse."
            return

        f = open(opts.infile, 'r')
        data = f.read()
        f.close()

        ret = import_standards_doc(data, "Command Line", "Standards Import Script", hdr_events=opts.event, source=opts.source)
        if ret['success']:
            for k in ["events", "samples", "emails", "indicators"]:
                print "%s (%i)" % (k, len(ret[k]))
                if opts.verbose:
                    for i in ret[k]:
                        print "\t" + i
        else:
            print "Failure: %s" % ret['reason']
