import datetime
import tarfile
import time
from io import BytesIO

from crits.core.mongo_tools import mongo_connector, get_file
from crits.core.basescript import CRITsBaseScript
import settings

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        samples = mongo_connector(settings.COL_SAMPLES)
        today = datetime.datetime.fromordinal(datetime.datetime.now().toordinal())
        md5s = samples.find({"source.instances.date": {"$gte": today}})
        filename = "%s/%s.tar.bz2" % ("/tmp/samples", today.strftime("%Y-%m-%d"))
        tar = tarfile.open(filename, "w:bz2")
        for md5 in md5s:
            m = md5['md5']
            f = md5['filename']
            s = get_file(m)
            info = tarfile.TarInfo(name="%s" % f)
            info.mtime = time.time()
            info.size = len(s)
            tar.addfile(info, BytesIO(s))
        tar.close()
    
