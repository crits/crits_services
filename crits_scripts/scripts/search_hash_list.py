from optparse import OptionParser

import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-i", "--input", action="store", dest="input",
                type="string", help="input filename containing list of hashes")
        parser.add_option("-o", "--output", action="store", dest="output",
                type="string", help="output filename")
        parser.add_option("-t", "--hash-type", action="store", dest="hash",
                type="string", help="hash type")
        (opts, args) = parser.parse_args(argv)

        if opts.input:
            hash_list = open(opts.input, 'rb').read()
            hash_list = hash_list.split()
        if opts.hash:
            query_string = "%s" % opts.hash
        else:
            query_string = "md5"

        if hash_list:
            results = []
            samples = mongo_connector(settings.COL_SAMPLES)
            for h in hash_list:
                h = h.strip()
                result = samples.find_one({query_string: h}, {'md5': 1})
                if result:
                    results.append(result["md5"])
            if opts.output:
                fout = open(opts.output, 'wb')
                for result in results:
                    fout.write(result + '\n')
                fout.close()
            else:
                for result in results:
                    print result
