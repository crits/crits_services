import datetime
import settings

from crits.core.mongo_tools import mongo_connector
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        indicators = mongo_connector(settings.COL_INDICATORS)
        today = datetime.datetime.today()
        yesterday = today - datetime.timedelta(days=1)
        i = indicators.find({'created': {'$gte': yesterday, '$lt': today}}, {'type': 1, 'value': 1})
        for a in i:
            print "%s, %s" % (a['type'], a['value'])
