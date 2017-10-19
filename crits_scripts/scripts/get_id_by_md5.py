"""
Example Usage:
    python get_id_by_md5.py -m md5"
"""

from optparse import OptionParser
from django.conf import settings
from crits.samples.sample import Sample
from crits.core.basescript import CRITsBaseScript

settings.MONGO_READ_PREFERENCE = 'secondary'

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-m", "--md5", action="store", dest="md5",
                type="string", help="filetype filter")
        (opts, args) = parser.parse_args(argv)

        try:
            if opts.md5:
                sample = Sample.objects(md5=opts.md5).first()
        except Exception as e:
            print "Bad things - '%s'" % e
        if sample:
            print sample.id
