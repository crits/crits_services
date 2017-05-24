"""
Example Usage:
    python get_md5s.py -f "{'source.name': 'foo'}"
"""

import ast
from optparse import OptionParser

from crits import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.basescript import CRITsBaseScript

settings.MONGO_READ_PREFERENCE = 'secondary'

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--filter", action="store", dest="filter",
                type="string", help="filetype filter")
        (opts, args) = parser.parse_args(argv)

        try:
            samples = mongo_connector(settings.COL_SAMPLES)
            if opts.filter:
                query = ast.literal_eval(opts.filter)
            else:
                query = {}

            md5_list = samples.find(query, {"md5": 1})

            for item in md5_list:
                try:
                    if item['md5'] != None:
                        print item['md5']
                except:
                    pass
        except:
            pass
