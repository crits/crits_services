import ast
from optparse import OptionParser

from crits.services.handlers import run_service
from crits.services.core import ServiceAnalysisError
from crits.core.basescript import CRITsBaseScript
from crits.core.class_mapper import class_from_value, class_from_type

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run_services(self, service_list, obj_list, verbose=False, config={}):
        if verbose:
            print "Running services\n-------------------\n"
        for obj in obj_list:
            for service in service_list:
                if verbose:
                    print "    [+] {0} scan obj: {1}".format(service, obj.id)
                try:
                    result = run_service(service,
                                         obj._meta['crits_type'],
                                         obj.id,
                                         self.user,
                                         obj=obj,
                                         custom_config=config,
                                         execute='process')
                    if result['success'] != True:
                        if verbose:
                            print "    [+] %s" % result['html']
                except ServiceAnalysisError as e:
                    if verbose:
                        print "    [+] %s" % e

    def print_running_services(self, service_list):
        print "\nServices:\n---------------"
        for service_name in service_list:
            print "    [+] {0}".format(service_name)
        print "\n"

    def print_object_stats(self, obj_list, query_filter=None):
        if query_filter:
            print "Objects from {0}\n----------------".format(query_filter)
        else:
            print "\nObjects\n------------"
        print "    [+] %d objects" % (len(obj_list))
        print "\n"

    def run(self, argv):
        parser = OptionParser()
        parser.add_option('-s', '--services', dest='services', help='Service list')
        parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose mode')
        parser.add_option('-f', '--filter', dest='query_filter',
                            help='Query filter')
        parser.add_option('-T', '--type', dest='type_', default='Sample',
                            help='CRITs type query for (default: Sample)')
        parser.add_option('-i', '--identifier', dest='identifier',
                            help='Identifier for type (NOT OBJECT ID)')
        parser.add_option('-c', '--config', dest='config', default={},
                            help='Service configuration')
        (opts, args) = parser.parse_args(argv)

        service_list = []
        if opts.services:
            service_list = opts.services.split(',')
            if opts.verbose:
                self.print_running_services(service_list)

        if opts.query_filter:
            query = ast.literal_eval(opts.query_filter)
            klass = class_from_type(opts.type_)
            if not klass:
                print "[-] Invalid type."
            obj_list = klass.objects(__raw__=query)
            if opts.verbose:
                self.print_object_stats(obj_list, opts.query_filter)

        if opts.identifier:
            obj = class_from_value(opts.type_, opts.identifier)
            if not obj:
                print "[-] Unable to find object."
                return

            obj_list = [obj]
            if opts.verbose:
                self.print_object_stats(obj_list)

        config = {}
        if opts.config:
            config = ast.literal_eval(opts.config)

        if obj_list and service_list:
            self.run_services(service_list, obj_list, opts.verbose, config)
