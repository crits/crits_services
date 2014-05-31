import ast
import sys

from optparse import OptionParser

from crits import settings
from crits.core.mongo_tools import mongo_connector, get_file, put_file, delete_file
from crits.core.basescript import CRITsBaseScript
from crits.samples.sample import Sample

settings.MONGO_READ_PREFERENCE = 'secondary'

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-c", "--collection", action="store", dest="collection",
                type="string", default="samples",
                help="name of old samples collection if not 'samples'")
        parser.add_option("-d", "--delete-samples", action="store", dest="sampledelete",
                type="string", help="path to results file with sample md5s to delete")
        parser.add_option("-D", "--delete-files", action="store", dest="griddelete",
                type="string", help="path to results file with gridfs md5s to delete")
        parser.add_option("", "--delete-samples-query",
                          action="store", dest="sampledeletequery",
                type="string", help="query for samples to delete")
        parser.add_option("-f", "--filter", action="store", dest="filter",
                type="string", help="filter for samples to migrate and output results file")
        parser.add_option("-g", "--gridfs", action="store", dest="gridfs",
                type="string", help="path to gridfs file with md5s to migrate")
        (opts, args) = parser.parse_args(argv)

        if opts.sampledelete or opts.sampledeletequery:
            print "Deleting matching md5s from %s..." % opts.collection
            count = 0
            failed = 0
            try:
                samples = mongo_connector(opts.collection)
            except Exception, e:
                print "Error: %s" % str(e)
                sys.exit(1)
            try:
                if opts.sampledeletequery:
                    query = ast.literal_eval(opts.sampledeletequery)
                    samples.remove(query)
                    print "Deleted samples matching query %s..." % query
                else:
                    with open(opts.sampledelete) as o:
                        for line in o:
                            md5 = line.strip()
                            samples.remove({'hashes.md5': md5})
                            count += 1
                    print "Deleted %s md5s from old collection." % count
            except Exception, e:
                print "Mongo Error: %s" % str(e)
                sys.exit(1)
            sys.exit(0)

        if opts.gridfs or opts.griddelete:
            errorpath = "/tmp/gridfs_migrate_errors.txt"
            try:
                err = open(errorpath, "w")
            except:
                print "Could not open file handle to write to: %s" % errorpath
                sys.exit(1)
            filename = None
            error_count = 0
            if opts.gridfs:
                print "Copying GridFS data matching md5s to new collection..."
                filename = opts.gridfs
            elif opts.griddelete:
                print "Deleting matching md5s from GridFS..."
                filename = opts.griddelete
            count = 0
            no_data = 0
            try:
                with open(filename) as o:
                    for line in o:
                        md5 = line.strip()
                        data = get_file(md5, opts.collection)
                        if data:
                            if opts.gridfs:
                                put_file(md5, data)
                                s = Sample.objects(md5=md5).first()
                                if s:
                                    s.discover_binary()
                                    try:
                                        s.save()
                                    except:
                                        error_count += 1
                                        err.write("Error saving sample for discover binary: %s" % md5)
                            elif opts.griddelete:
                                delete_file(md5, opts.collection)
                            count += 1
                        else:
                            no_data += 1
                if opts.gridfs:
                    print "Copied %s md5s to new collection." % count
                    if error_count:
                        print "Check %s for samples that didn't get their binaries updated!" % errorpath
                elif opts.griddelete:
                    print "Deleted %s md5s from GridFS." % count
                print "There were %s md5s which we did not find data for." % no_data
            except Exception, e:
                print "Error: %s" % str(e)
                sys.exit(1)
            sys.exit(0)

        try:
            samples = mongo_connector(opts.collection)
            sample = mongo_connector(settings.COL_SAMPLES)
            if opts.filter:
                query = ast.literal_eval(opts.filter)
            else:
                query = {}

            sample_list = samples.find(query)
        except Exception, e:
            print "Error setting up/executing query: %s" % str(e)
            sys.exit(1)

        filepath = "/tmp/sample_migrate_results.txt"
        errorpath = "/tmp/sample_migrate_errors.txt"
        try:
            f = open(filepath, "w")
            e = open(errorpath, "w")
        except:
            print "Could not open file handle to write to: %s" % filepath
            sys.exit(1)

        count = sample_list.count()
        print "Migrating %s samples found with query %s...\n" % (count, query)
        i = 1
        failed = 0
        for s in sample_list:
            try:
                print >> sys.stdout, "\r\tWorking on sample %d of %d" % (i, count),
                sys.stdout.flush()
                hashes = s['hashes']
                if 'md5' in hashes:
                    s['md5'] = hashes['md5']
                else:
                    s['md5'] = ""
                if 'sha1' in hashes:
                    s['sha1'] = hashes['sha1']
                else:
                    s['sha1'] = ""
                if 'sha256' in hashes:
                    s['sha256'] = hashes['sha256']
                else:
                    s['sha256'] = ""
                if 'ssdeep' in hashes:
                    s['ssdeep'] = hashes['ssdeep']
                else:
                    s['ssdeep'] = ""
                del s['hashes']
                sample.save(s)
                f.write("%s\n" % s['md5'])
                i += 1
            except Exception, e:
                failed += 1
                e.write("Issue with Sample ID: %s -- %s" % (s['_id'], str(e)))
        f.close()
        print "\n\nWe did not remove any samples from the old collection!"
        print "Please clean up your old samples collection as needed."
        print "Review %s for a list of md5s which need GridFS migration." % filepath
        if failed:
            print "There were %s failed migrations!" % failed
            print "View %s for information on failed migrations!" % errorpath
