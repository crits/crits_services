import ast
from optparse import OptionParser
from datetime import datetime

from crits.core.basescript import CRITsBaseScript
from snugglefish_service.snugglefish import SnuggleIndex
from crits.samples.sample import Sample

#from . import snugglefish

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def __create_index(self, name, query, directory):
        # Note: I am intentionally not checking to make sure
        # the directory exists. It is up to the indexer to put
        # the result in the appropriate place.
        sngindex = SnuggleIndex()
        sngindex.name = name
        sngindex.query = query
        sngindex.directory = directory
        sngindex.save()
        return sngindex

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-a", "--action", action="store", dest="action",
                type="string", help="action")
        parser.add_option("-n", "--name", action="store", dest="name",
                type="string", help="index name")
        parser.add_option("-c", "--count", action="store", dest="count",
                type="string", help="count")
        parser.add_option("-q", "--query", action="store", dest="query",
                type="string", help="query filter")
        parser.add_option("-d", "--directory", action="store", dest="directory",
                type="string", help="index directory")
        (opts, args) = parser.parse_args(argv)

        if opts.action.lower() not in ['create', 'getnew', 'status', 'delete', 'update']:
            print "Action must be one of create, getnew, status, delete or update."
            return

        if not opts.name:
            print "Need an index name."
            return

        if opts.action == 'create':
            if not opts.query or not opts.directory:
                print "Need a query filter and directory."
                return

            # We don't store the parsed query as it needs to be a string but
            # we can make sure it is parsable before storing it.
            try:
                query = ast.literal_eval(opts.query)
            except Exception, e:
                print "Error with query: %s" % e
                return

            sngindex = SnuggleIndex.objects(name=opts.name).first()
            if sngindex:
                print "Index already exists."
                return

            self.__create_index(opts.name, opts.query, opts.directory)
        elif opts.action == 'getnew':
            query = None
            if not opts.count:
                print "Need a count."
                return

            try:
                count = int(opts.count)
            except Exception, e:
                print "Error with count: %s" % e
                return

            sngindex = SnuggleIndex.objects(name=opts.name).first()
            if not sngindex:
                if not opts.query or not opts.directory:
                    print "Index does not exist, provide a query and directory."
                    return
                else:
                    try:
                        query = ast.literal_eval(opts.query)
                    except Exception, e:
                        print "Error with query: %s" % e
                        return

                    sngindex = self.__create_index(opts.name, opts.query,
                                                   opts.directory)

            if not query:
                try:
                    query = ast.literal_eval(sngindex.query)
                except Exception, e:
                    print "Error with query: %s" % e
                    return

            # XXX: Get count worth of samples using query...
            samples = Sample.objects(__raw__=query).order_by('+id').only('md5')[sngindex.count:sngindex.count + count]
            if not samples:
                print "No objects found."
                return

            for sample in samples:
                print sample.md5

            sngindex.last_id = samples[len(samples) - 1].id
            sngindex.save()
        elif opts.action == 'update':
            sngindex = SnuggleIndex.objects(name=opts.name).first()
            if not sngindex:
                print "Index does not exist."
                return

            try:
                count = int(opts.count)
            except Exception, e:
                print "Error with count: %s" % e
                return

            # Ensure that last_id is not None. This may happen if
            # an index is created but no samples are fetched yet.
            # Someone may want to update the count without fetching
            # anything, which is impossible.
            if not sngindex.last_id:
                print "Last ID is None, did you really fetch these?"
                return

            sngindex.last_update = datetime.now()
            sngindex.count += count
            sngindex.save()
        elif opts.action == 'status':
            sngindex = SnuggleIndex.objects(name=opts.name).first()
            if not sngindex:
                print "Index does not exist."
                return

            try:
                query = ast.literal_eval(sngindex.query)
            except Exception, e:
                print "Error with query: %s" % e
                return

            total = Sample.objects(__raw__=query).count()

            print "Name: %s" % sngindex.name
            print "Directory: %s" % sngindex.directory
            print "Created: %s" % sngindex.created
            print "Last update: %s" % sngindex.last_update
            print "Query: %s" % sngindex.query
            print "Last ID: %s" % sngindex.last_id
            print "Total objects: %i" % total
            print "Count indexed: %i" % sngindex.count
            try:
                print "Percent indexed: %f" % ((float(sngindex.count)/total) * 100)
            except:
                print "Percent indexed: 0"

            sngindex.total = total
            sngindex.save()
        elif opts.action == 'delete':
            sngindex = SnuggleIndex.objects(name=opts.name).first()
            if not sngindex:
                print "Index does not exist."
                return
            sngindex.delete()
