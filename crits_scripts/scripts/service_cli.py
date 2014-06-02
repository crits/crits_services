import ast
from optparse import OptionParser

import settings

from crits.core.mongo_tools import mongo_find
import crits.service_env
from crits.services.core import ServiceAnalysisError
from crits.core.basescript import CRITsBaseScript
from crits.core.class_mapper import class_from_value

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run_services(self, service_list, sample_list, verbose=False, force=False):
        env = crits.service_env.environment
        if verbose:
            print "Beginning scanning of files\n-------------------\n"
        for (sample_md5, sample_id) in sample_list:
            try:
                context = env.create_context("Sample", sample_id, self.username)
            except Exception as e:
                print "    [-] error fetching md5 {0}, {1}".format(sample_md5, e)
                continue
            for service in service_list:
                if verbose:
                    print "    [+] {0} scan md5: {1}".format(service, sample_md5)
                try:
                    env.run_service(service, context, execute='process', force=force)
                except ServiceAnalysisError as e:
                    if verbose:
                        print "    [+] %s" % e

    def list_available_services(self):
        print "\nAvailable Services\n---------------------"
        for service_name in crits.service_env.manager.enabled_services:
            print "    [+] %s" % service_name
        print "\n"

    def get_service_list(self, triage = False, enabled = False):
        if triage:
            return crits.service_env.manager.triage_services
        elif enabled:
            return crits.service_env.manager.enabled_services

    def print_running_services(self, service_list):
        print "\nServices:\n---------------"
        for service_name in service_list:
            print "    [+] {0}".format(service_name)
        print "\n"

    def print_sample_stats(self, sample_list, sample_filter=None):
        if sample_filter:
            print "Samples from {0}\n----------------".format(sample_filter)
        else:
            print "\nSamples\n------------"
        print "    [+] %d samples" % (len(sample_list))
        print "\n"

    def run(self, argv):
        parser = OptionParser()
        parser.add_option('-l', '--list', dest='list_services', action='store_true',
                            default=False,
                            help='List available services')
        parser.add_option('-t', '--triage', dest='triage', action='store_true',
                            default=False,
                            help='Run all triage services')
        parser.add_option('-e', '--enabled', dest='enabled', action='store_true',
                            default=False,
                            help='Run all enabled services')
        parser.add_option('-s', '--services', dest='services', help='Service list')
        parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose mode')
        parser.add_option('-f', '--filter', dest='sample_filter',
                            help='Sample query filter')
        parser.add_option('-m', '--md5', dest='md5',
                            help='md5 of sample')
        parser.add_option('-F', '--force', dest='force', action='store_true',
                            default=False,
                            help='Force run')
        (opts, args) = parser.parse_args(argv)

        service_list = []
        sample_list = []
        if opts.list_services:
            self.list_available_services()
        if (opts.triage or opts.enabled):
            service_list = self.get_service_list(opts.triage, opts.enabled)
            if opts.verbose:
                self.print_running_services(service_list)
        elif (opts.services):
            if len(opts.services) > 0:
                service_list = opts.services.split(',')
                if opts.verbose:
                    self.print_running_services(service_list)
        if (opts.sample_filter):
            query = ast.literal_eval(opts.sample_filter)
            query_results = mongo_find(settings.COL_SAMPLES, query, {'md5': 1})
            sample_list = [(sample["md5"], str(sample["_id"])) for sample in query_results]
            if opts.verbose:
                self.print_sample_stats(sample_list, opts.sample_filter)
        if (opts.md5):
            # Given an MD5 we have to get the sample ID.
            #
            # XXX: This should be extended so we can pass an MD5 of a PCAP.
            # The entire script also needs to have an option for ID, so we
            # can work with other object types that support services.
            obj = class_from_value('Sample', opts.md5)
            if not obj:
                print "[-] Unable to find object."
                return

            sample_list = [(opts.md5, obj.id)]
            if opts.verbose:
                self.print_sample_stats(sample_list)
        if sample_list and service_list:
            self.run_services(service_list, sample_list, opts.verbose, opts.force)
