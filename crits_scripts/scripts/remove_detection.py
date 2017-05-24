from crits import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        print "Removing old detection results..."
        samples = mongo_connector(settings.COL_SAMPLES)

        samples.update({},
                       {"$unset": {'detection': 1,
                                   'unsupported_attrs.detection': 1}},
                       multi=True)
