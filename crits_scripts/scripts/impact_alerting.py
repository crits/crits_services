"""
Example Usage:
    python impact_alerting.py -t "Address - ipv4-addr" -i low,medium,high -a "Firewall Block"
"""

import sys
from optparse import OptionParser

from crits.indicators.handlers import ci_search
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-t", "--type", dest="itype", default=None,
            help="Type of indicator you want to query for (ex: \"Address - ipv4-addr\", \"URI - Domain Name\", etc.")
        parser.add_option("-c", "--confidence", dest="confidence", default=None,
            help="Confidence level (unknown, benign, low, medium, high) minimum value. Specify multiple values separated with a comma.")
        parser.add_option("-i", "--impact", dest="impact", default=None,
            help="Impact level (unknown, benign, low, medium, high) minimum value. Specify multiple values separated with a comma.")
        parser.add_option("-a", "--action", dest="action", default=None,
            help="Action type, ex 'Flow Monitoring'. Specify multiple values separated with a comma.")

        (options, args) = parser.parse_args(argv)
        if options.itype is None or (options.confidence is None and options.impact is None):
            print "You must provide a type and at least a confidence or impact level to search for."
            sys.exit(1)
        else:
            results = ci_search(options.itype, options.confidence, options.impact, options.action)
            for result in results:
                print_action = True
                if options.action and "actions" in result:
                    for action in result["actions"]:
                        if action["action_type"] in options.action and action["active"] == "off":
                            print_action = False
                if print_action:
                    print "%s" % result['value']
