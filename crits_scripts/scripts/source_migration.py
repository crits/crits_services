import sys
import datetime
from copy import deepcopy

import settings
from django.utils.dateparse import parse_datetime
from crits.core.mongo_tools import *
import pymongo
from bson import ObjectId
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def get_new_style_source(self, obj, oid, obj_created_date=None):
        if 'source' not in obj:
            return []

        try:
            if obj_created_date and not isinstance(obj_created_date, datetime.datetime):
                obj_created_date = None
            source_list = obj['source']
            source_dict = {}

            #handle string source "list"
            if isinstance(source_list, basestring):
                obj_created_date = self.handle_string_source(source_list, source_dict, obj_created_date)
                return [{'name':key, 'instances':val} for key,val in source_dict.items()]

            #handle dict source "list"
            if isinstance(source_list, dict):
                source_list = [source_list]

            for source in source_list:
                #make a copy of the source in case something goes wrong.
                #   That way, we don't lose data when we delete keys from the
                #   original source.
                source = deepcopy(source)
                #handle string source
                if isinstance(source, basestring):
                    obj_created_date = self.handle_string_source(source, source_dict, obj_created_date)
                    continue

                #handle dict source
                name = source['name']

                #Check to see if source is already in the new format.
                #       Don't change it if it is, but continue with processing in case there is
                #       somehow other data in the source list that is in the wrong format. (For
                #       example, perhaps some object-adding code didn't get converted and we need
                #       to run this script again to fix improperly added sources.)
                if 'instances' in source:
                    if name in source_dict:
                        source_dict[name] += source['instances']
                    else:
                        source_dict[name] = source['instances']
                    continue
                else:
                    #delete no-longer-relevant fields
                    for item in ['name', 'authority', 'classification', 'rel']:
                        if item in source: del source[item]
                    #make sure necessary fields are there
                    for item in ['method', 'reference']:
                        if item not in source: source[item] = ""
                    if 'date' not in source:
                        if obj_created_date:
                            source['date'] = obj_created_date
                            obj_created_date = obj_created_date + datetime.timedelta(seconds=1)
                        else:
                            source['date'] = datetime.datetime.now()
                    else:
                        if isinstance(source['date'], basestring):
                            source['date'] = parse_datetime(source['date'])
                if name in source_dict:
                    source_dict[name].append(source)
                else:
                    source_dict[name] = [source]
            return [{'name':key, 'instances':val} for key,val in source_dict.items()]
        except Exception, e:
            raise
            print "issue: %s -> oid: %s" % (e, oid)
            return []

    def handle_string_source(self, name, source_dict, obj_created_date=None):
        if isinstance(obj_created_date, basestring):
            obj_created_date = parse_datetime(obj_created_date)
        d = {'method':'', 'reference':'', 'date':obj_created_date or datetime.datetime.now()}
        if name in source_dict:
            source_dict[name].append(d)
        else:
            source_dict[name] = [d]
        if obj_created_date:
            return obj_created_date + datetime.timedelta(seconds=1)

    def fix_sources(self, collection):
        col = mongo_connector(collection)
        doc_list = col.find({'source.instances': {'$exists': 0}}, {'_id': 1, 'source': 1, 'date':1, 'uploadDate':1, 'created':1, 'md5': 1}, timeout=False)

        count = doc_list.count()
        print "\tFound %s documents that need updating." % count

        i = 0
        # for each document
        for doc in doc_list:
            i += 1
            print >> sys.stdout, "\r\tWorking on document %d of %d" % (i,count),
            sys.stdout.flush()
            query = {}
            # get the ID and the list of sources
            oid = doc['_id']
            if 'md5' in doc:
                query = {'_id': ObjectId(oid), 'md5': doc['md5']}
            if 'uploadDate' in doc:
                date = doc['uploadDate']
            elif 'date' in doc:
                date = doc['date']
            elif 'created' in doc:
                date = doc['created']
            else:
                date = None
            update_query = {'$set': {'source': self.get_new_style_source(doc, oid, date)}}
            col.update(query, update_query, safe=True)
        doc_list.close()
        if i > 0:
            print "\n"

    def fix_fqdn_and_ip(self, collection):
        col = mongo_connector(collection)
        doc_list = col.find({}, {'_id': 1, 'fqdn': 1}, timeout=False)

        count = doc_list.count()
        print "\tFound %s documents that need updating." % count

        i = 0
        # for each document
        for doc in doc_list:
            i += 1
            print >> sys.stdout, "\r\tWorking on document %d of %d" % (i,count),
            sys.stdout.flush()
            # get the ID and the list of sources
            oid = doc['_id']
            #update FQDNs
            for fqdn in doc['fqdn']:
                if 'date' in fqdn:
                    date = fqdn['date']
                else:
                    date = None
                col.update({'_id': ObjectId(oid), 'fqdn.name':fqdn['name']}, {'$set': {'fqdn.$.source': self.get_new_style_source(fqdn, oid, date)}})

                #update IPs
                ip_list = fqdn['ip_addresses']
                for ip in ip_list:
                    #if 'source' in ip and ip['source']:
                    #       print ip['ip'], ip['source']
                    if 'date' in ip:
                        date = ip['date']
                    else:
                        date = None
                    #first need to pull old IP
                    col.update({'_id':ObjectId(oid), 'fqdn.name':fqdn['name']}, {'$pull':{'fqdn.$.ip_addresses':{'$elemMatch':ip}}})
                    ip['source'] = self.get_new_style_source(ip, oid, date)
                    #now re-add with new source
                    col.update({'_id':ObjectId(oid), 'fqdn.name':fqdn['name']}, {'$push':{'fqdn.$.ip_addresses':ip}})
        doc_list.close()
        if i > 0:
            print "\n"

    def run(self, argv):
        print "Migrating Emails..."
        self.fix_sources(settings.COL_EMAIL)
        print "Migrating Indicators..."
        self.fix_sources(settings.COL_INDICATORS)
        print "Migrating Events..."
        self.fix_sources(settings.COL_EVENTS)
        print "Migrating PCAPs..."
        self.fix_sources(settings.COL_PCAPS)
        print "Migrating Domains..."
        self.fix_sources(settings.COL_DOMAINS)

        # custom function for fqdn/ip
        print "Migrating FQDNs and IPs..."
        self.fix_fqdn_and_ip(settings.COL_DOMAINS)

        print "Migrating Samples..."
        self.fix_sources(settings.COL_SAMPLES)
