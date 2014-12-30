import ast
from optparse import OptionParser

from mongoengine.base import ValidationError

from crits.core.basescript import CRITsBaseScript
from crits.domains.domain import Domain
from crits.services.core import ServiceAnalysisError
from crits.services.handlers import run_service

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-d", "--domain", action="store", dest="domain",
                          type="string",
                          help="Domain to use (if not provided, do all)")
        parser.add_option("-c", "--config", dest="config", default={},
                          help="Service configuration")
        parser.add_option("-v", "--verbose", action="store_true",
                          dest="verbose", default=False, help="Be verbose")
        parser.add_option("-n", "--dry_run", action="store_true",
                          dest="dry_run", default=False, help="Dry run, just show what would happen.")
        (opts, args) = parser.parse_args(argv)

        if opts.domain:
            if opts.verbose:
                print "[+] Using domain: %s" % opts.domain
            domain = opts.domain
        else:
            if opts.verbose:
                print "[+] Using ALL domains"
            domain = None

        config = {}
        if opts.config:
            config = ast.literal_eval(opts.config)

        if not config:
            print "No config provided, defaulting to live only."
            config['live_query'] = True
        else:
            print "Using config: %s" % config

        query = {
                  '$or': [
                    {
                      'whois':
                          {
                            '$exists': True,
                            '$not': {'$size': 0}
                          }
                    },
                    {
                      'unsupported_attrs.whois':
                          {
                            '$exists': True,
                            '$not': {'$size': 0}
                          }
                    }
                  ]
                }
        if domain:
            query['domain'] = domain

        doms = Domain.objects(__raw__=query)
        for dom in doms:
            print "Executing whois for %s" % dom.domain
            if opts.dry_run:
                continue
            try:
                result = run_service('whois',
                                     'Domain',
                                     dom.id,
                                     self.username,
                                     obj=dom,
                                     custom_config=config)
                dom.save()
            except ServiceAnalysisError as e:
                print "Service error: %s" % e
            except ValidationError as e:
                print "Validation error: %s" % e
