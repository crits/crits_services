from django.conf import settings

from crits.services.analysis_result import AnalysisResult
from crits.core.mongo_tools import mongo_connector, put_file
from crits.samples.handlers import handle_file
from crits.samples.sample import Sample
from crits.core.basescript import CRITsBaseScript

class TestFile(object):
    """
    def handle_file(filename, data, source, method='Generic', reference=None, related_md5=None,
                    related_id=None, related_type='Sample', backdoor=None, user='',
                    campaign=None, confidence='low', md5_digest=None, bucket_list=None,
                    ticket=None, relationship=None, inherited_source=None, is_validate_only=False,
                    is_return_only_md5=True, cache={}):

    """
    test_filename = "test_file.txt"
    test_data = "the quick brown fox jumps the lazy dog"
    test_mime = "text/plain"
    test_md5 = '4070871fdaa84f213c801b37d127e856'
    actions = ['_del_grid', '_add_grid', '_del_meta', '_add_meta',
               '_del_triage', '_add_triage']
    sources = ['source1', 'source2', 'source3', 'source4', 'source5']
    bucket_lists = ['one', 'two', 'three', 'four', 'five', 'six']
    metadata_fields = ['sha1', 'sha256', 'ssdeep', 'filetype',
                       'mimetype', 'size']

    def __init__(self):
        self.samples = mongo_connector(settings.COL_SAMPLES)
        self.grid = mongo_connector("%s.files" % settings.COL_SAMPLES)
        self._clean()
        print "[+] Initializing with fn='%s', source='%s'" % (self.test_filename,
                                                              self.sources)

    def _clean(self):
        self._del_sample()

    def _upload_file(self):
        print "[+] calling handle_file with file data"
        handle_file(self.test_filename, self.test_data, self.sources[0])

    def _upload_md5(self):
        print "[+] calling handle_file with md5_digest"
        handle_file(self.test_filename, data='', source=self.sources[0],
                    md5_digest = self.test_md5)

    def _randomize(self):
        return

    def _del_sample(self):
        sample = Sample.objects(md5=self.test_md5).first()
        if sample:
            print "[-] deleting from grid"
            if sample.filedata:
                sample.filedata.delete()
            print "[-] deleting sample"
            sample.delete()
        else:
            print "[-] could not find sample to delete"

    def _del_grid(self):
        print "[-] deleting from grid"
        self.grid.remove({'md5': self.test_md5})

    def _add_grid(self):
        print "[+] adding to gridfs"
        put_file(self.test_md5, self.test_data)

    def _check(self):
        self._check_grid()
        self._check_triage()

    def _check_triage(self):
        sample = Sample.objects(md5=self.test_md5).first()
        results = False
        if sample and sample.filedata:
            if len(AnalysisResult.objects(object_id=str(sample.id))) > 0:
                results = True
        print "[?] sample analysis executed == %s" % results
        return results

    def _check_grid(self):
        sample = Sample.objects(md5=self.test_md5).first()
        result = False
        if sample:
            if sample.filedata:
                data = sample.filedata.read()
                result = data == self.test_data
            print "[?] check grid == %s" % result
        return result

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        print "\r\n*** init, basic check ***"
        new = TestFile()
        new._check()
        print "*" * 40

        print "\r\n+++ del grid, upload md5, upload file +++"
        new._del_grid()
        new._upload_md5()
        new._check()
        new._upload_file()
        new._check()
        print "*" * 40

        print "\r\n+++ clean, add to grid, upload md5 +++"
        new._clean()
        new._check()
        new._add_grid()
        new._check()
        new._upload_md5()
        new._check()
        print "*" * 40
