from optparse import OptionParser

from crits.core.mongo_tools import mongo_connector
import settings
import pymongo
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-i", "--indicators", action="store_true", dest="indicators",
                help="copy over indicators")
        (opts, args) = parser.parse_args(argv)

        indicators = mongo_connector(settings.COL_INDICATORS)
        if opts.indicators:
            conn = pymongo.Connection()
            db = conn.crits
            coll = db.indicators
            prod_indicators = coll.find()
            for i in prod_indicators:
                indicators.insert(i)
