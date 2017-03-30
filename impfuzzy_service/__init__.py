import io
import logging
import pyimpfuzzy

from django.template.loader import render_to_string

from crits.samples.sample import Sample
from crits.services.core import Service, ServiceConfigError

from . import forms

logger = logging.getLogger(__name__)

#This is based on ssdeep_compare

class impfuzzyService(Service):
    """
    Compare sample to others with impfuzzy.
    """

    name = "impfuzzy_compare"
    version = '1.0.1'
    description = "Compare samples using impfuzzy."
    supported_types = ['Sample']

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")
        # Only run on PE files
        if not obj.is_pe():
            raise ServiceConfigError("Not a PE.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        if config:
            # The values are submitted as a list for some reason.
            data = {'threshold': config['threshold'][0]}
        else:
            data = {}
            fields = forms.impfuzzyRunForm().fields
            for name, field in fields.iteritems():
                data[name] = field.initial
        return forms.impfuzzyRunForm(data)

    @staticmethod
    def get_config(existing_config):
        # There are no longer config options for this service.
        return {}

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.impfuzzyRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def run(self, obj, config):
        threshold = config.get("threshold", 50)
        target_impfuzzy = None
        try:
            target_impfuzzy = pyimpfuzzy.get_impfuzzy_data(obj.filedata.read())
        except Exception:
            pass
        target_md5 = obj.md5
        if not target_impfuzzy:
            logger.error = "impfuzzy: Could not generate impfuzzy value for sample: %s" % str(obj.id)
            self._error("Could not generate impfuzzy value for sample")
            return
        # setup the sample space to compare against
        # first use the mimetype as a comparator if available
        if obj.impfuzzy:
            obj.impfuzzy = target_impfuzzy
            obj.save()
            self._info("impfuzzy: Filled-in in the impfuzzy")
        else:
            self._info("impfuzzy attribute already present, not overwriting")
        self._add_result('impfuzzy_hash', target_impfuzzy,{'impfuzzy': target_impfuzzy})
        target_mimetype = obj.mimetype
        query_filter = {}
        if target_mimetype:
            query_filter['mimetype'] = target_mimetype
        # then use only samples with a multiple of chunksize
        chunk_size = int(target_impfuzzy.split(":")[0])
        query_filter["$or"] = []
        query_filter["$or"].append({"impfuzzy": {"$regex": "^%d:" % chunk_size * 2}})
        query_filter["$or"].append({"impfuzzy": {"$regex": "^%d:" % chunk_size}})
        query_filter["$or"].append({"impfuzzy": {"$regex": "^%d:" % (chunk_size // 2)}})
        result_filter = {'md5': 1, 'impfuzzy': 1, 'description':1}
        candidate_space = Sample.objects(__raw__=query_filter).only(*result_filter)
        #    self.info("candidate: %s" % repr(candidate_space))
        match_list = []
        for candidate in candidate_space:
            if "impfuzzy" in candidate:
                score = pyimpfuzzy.hash_compare(target_impfuzzy, candidate["impfuzzy"])
                if score >= threshold and candidate["md5"] != target_md5:
                    # Grab the md5 and the description for later
                    match_list.append({'md5': candidate["md5"], 'description': candidate["description"], 'score': score})
        # finally sort the results
        match_list.sort(key=lambda sample: sample["score"], reverse=True)
        for match in match_list:
            #Show the MD5 and the Description
            self._add_result("impfuzzy_match (MD5)", match["md5"], {'description': match["description"], 'score': match["score"]})
