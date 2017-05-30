"""
Example Usage:
    python get_emails.py -f "{'from': 'example@foo.com'}"
"""

import ast
from optparse import OptionParser

from crits import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.data_tools import format_object
from crits.core.basescript import CRITsBaseScript
import os

settings.MONGO_READ_PREFERENCE = 'secondary'

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--filter", action="store", dest="filter",
                type="string", help="filetype filter")
        parser.add_option("-o", "--output-dir", action="store", dest="out",
                type="string", help="output directory")
        parser.add_option("-y", "--yaml", action="store_true", dest="yaml",
                default=False, help="export in YAML")
        parser.add_option("-j", "--json", action="store_true", dest="json",
                default=False, help="export in JSON")
        (opts, args) = parser.parse_args(argv)

        emails = mongo_connector(settings.COL_EMAIL)
        if opts.filter:
            query = ast.literal_eval(opts.filter)
        else:
            query = {}
        if opts.yaml:
            meta_format = "yaml"
        elif opts.json:
            meta_format = "json"
        else:
            print(parser.format_help().strip())
            return
        emails = emails.find(query, {})

        if opts.out:
            path = opts.out
        else:
            path = os.getcwd()

        for email in emails:
            email_id = str(email['_id'])
            data = format_object("Email", email_id, "json",
                                 remove_source=True,
                                 remove_rels=False,  # should this be False?
                                 remove_schema_version=True,
                                 remove_campaign=True
                                )
            if data:
                pathname = os.path.join(path, email_id + "." + meta_format)
                print "[+] Writing %s" % pathname
                with open(pathname, "wb") as f:
                    f.write(data)
