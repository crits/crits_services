"""
Example Usage:
    python ssdeep_compare.py -m d386a81ec23170159febfe8ab69193cf -t 10"
"""

import sys
from optparse import OptionParser

from crits.samples.handlers import ssdeep_compare
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-m", "--md5", action="store", dest="md5",
                type="string", help="md5 of file")
        parser.add_option("-t", "--threshold", action="store", dest="threshold",
                type="int", help="threshold")
        parser.add_option("-s", "--ssdeep", action="store", dest="ssdeep",
                type="string", help="ssdeep comparison value")
        (opts, args) = parser.parse_args(argv)
        if opts.md5:
            hash_type = 'md5'
            hash_value = opts.md5
        elif opts.ssdeep:
            hash_type = 'ssdeep'
            hash_value = opts.ssdeep
        else:
            print "Must provide an MD5 of ssdeep hash"
            sys.exit(1)
        if opts.threshold:
            threshold = opts.threshold
        else:
            threshold = 50
        results = ssdeep_compare(hash_type, hash_value, threshold=threshold, use_mime=False)
        print results
        for result in results["match_list"]:
            print "Match %s - %d%%" % (result["md5"], result["score"])
