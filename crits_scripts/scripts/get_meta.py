import ast
import re
import datetime

import settings

from optparse import OptionParser
from crits.core.mongo_tools import mongo_connector
from crits.core.basescript import CRITsBaseScript

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def convert_ascii(self, data):
        if len(data) > 0:
            if ord(data[0]) in range(32,127):
                return data[0] + self.convert_ascii(data[1:])
            else:
                return self.convert_ascii(data[1:])
        return ""

    def get_sample_list(self, filter, meta):
        try:
            samples = mongo_connector(settings.COL_SAMPLES, preference="secondary")
            md5_list = samples.find(filter, meta)
        except:
            pass
        return md5_list

    def make_meta(self, opts):
        meta = {}
        for opt in opts:
            meta[opt] = 1
        return meta

    def parse_office_meta(self, meta):
        results = {}
        item = re.compile("(.+): (.+)", re.DOTALL)
        meta_items = meta.split(',')
        for meta_item in meta_items:
            match = item.match(meta_item)
            if match:
                results[match.group(1).lstrip().rstrip()] = match.group(2).lstrip().rstrip()
        return results

    def get_val_dot(self, value, element):
    #    print value, element
        end = element.find('.')
        if isinstance(value, dict):
            if end >= 0:
                if value.has_key(element[:end]):
                    return self.get_val_dot(value[element[:end]], element[end+1:])
            else:
                if value.has_key(element):
                    if isinstance(value[element], datetime.datetime):
                        return value[element].strftime("%D")
                    return value[element]
        elif len(value) > 0:
            return self.get_val_dot(value[0], element)
        return ""

    def print_csv(self, item_list, element_list):
        temp = ""
        for element in element_list:
            temp += self.convert_ascii(self.get_val_dot(item_list, element)) + ","
        return temp[:-1]

    def get_office_meta(self, filter):
        meta_filter = ["md5", "filename", "campaign.name", "backdoor.name", "filetype", "source.instances.date"]
        output_filter = ["source.instances.date", "md5", "filename", "campaign.name", "backdoor.name",
            "meta.Last Saved By", "meta.Company", "meta.Pages", "meta.Author", "meta.Create Time/Date"]
        meta = self.make_meta(meta_filter)
        sample_list = self.get_sample_list(filter, meta)
        for sample in sample_list:
            sample["meta"] = self.parse_office_meta(sample["filetype"])
            print self.print_csv(sample, output_filter)

    def get_yara_meta(self, filter):
        meta_filter = ["md5", "analysis.results.result", "analysis.service_name"]
        meta = self.make_meta(meta_filter)
        sample_list = self.get_sample_list(filter, meta)
        for item in sample_list:
            if item.has_key("md5"):
                if item.has_key("analysis"):
                    for results in item["analysis"]:
                        #print results
                        try:
                            if results.has_key("service_name"):
                                if results["service_name"] == "yara":
                                    if results.has_key("results"):
                                        for result in results["results"]:
                                            if result.has_key("result"):
                                                print "'%s', '%s'" % (item["md5"], result["result"])
                        except:
                            pass
                            #print "error with %s" % item["md5"]

    def get_pdf_meta(self, filter):
        meta = {}
        meta["md5"] = 1
        meta["analysis.results.md5"] = 1
        meta["analysis.service_name"] = 1
        sample_list = self.get_sample_list(filter, meta)
        for item in sample_list:
            if item.has_key("md5"):
                if item.has_key("analysis"):
                    for results in item["analysis"]:
                        #print results
                        try:
                            if results.has_key("service_name"):
                                if results["service_name"] == "pdfinfo":
                                    if results.has_key("results"):
                                        for result in results["results"]:
                                            if result.has_key("md5"):
                                                print "'%s', '%s'" % (item["md5"], result["md5"])
                        except:
                            pass
                            #print "error with %s" % item["md5"]

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-f", "--filter", action="store", dest="filter",
                type="string", help="filetype filter")
        parser.add_option("-y", "--yara", action="store_true", dest="yara",
                default=False, help="perform yara scans")
        parser.add_option("-p", "--pdfinfo", action="store_true", dest="pdf_info",
                default=False, help="perform pdf info scans")
        parser.add_option("-z", "--peinfo", action="store_true", dest="pe_info",
                default=False, help="perform pe info scans")
        parser.add_option("-o", "--office", action="store_true", dest="office",
                default=False, help="perform office query")
        (opts, args) = parser.parse_args(argv)
        if opts.filter:
            filter = ast.literal_eval(opts.filter)
        else:
            filter = {}

        if opts.pdf_info:
            self.get_pdf_meta(filter)
        elif opts.yara:
            self.get_yara_meta(filter)
        elif opts.office:
            self.get_office_meta(filter)
