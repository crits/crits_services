import logging
import pydeep

from django.template.loader import render_to_string

from crits.samples.sample import Sample
from crits.services.core import Service

from . import forms

logger = logging.getLogger(__name__)

class SSDeepService(Service):
    """
    Compare sample to others with ssdeep.
    """

    name = "ssdeep_compare"
    version = '1.0.3'
    description = "Compare samples using ssdeep."
    supported_types = ['Sample']

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        if config:
            # The values are submitted as a list for some reason.
            data = {'threshold': config['threshold'][0]}
        else:     
            data = {}
            fields = forms.SSDeepRunForm().fields
            for name, field in fields.iteritems():
                data[name] = field.initial
        return forms.SSDeepRunForm(data)

    @staticmethod
    def get_config(existing_config):
        # There are no longer config options for this service.
        return {}

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.SSDeepRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    def run(self, obj, config):
        threshold = config.get("threshold", 50)
        target_ssdeep = obj.ssdeep
        target_md5 = obj.md5
        target_mimetype = obj.mimetype
        if not target_ssdeep:
            logger.error = "Could not get the target ssdeep value for sample"
            self._error("Could not get the target ssdeep value for sample")
            return
        # setup the sample space to compare against
        # first use the mimetype as a comparator if available
        query_filter = {}
        if target_mimetype:
            query_filter['mimetype'] = target_mimetype
        # then use only samples with a multiple of chunksize
        chunk_size = int(target_ssdeep.split(":")[0])
        query_filter["$or"] = []
        query_filter["$or"].append({"ssdeep": {"$regex": "^%d:" % chunk_size * 2}})
        query_filter["$or"].append({"ssdeep": {"$regex": "^%d:" % chunk_size}})
        query_filter["$or"].append({"ssdeep": {"$regex": "^%d:" % (chunk_size / 2)}})
        result_filter = {'md5': 1, 'ssdeep': 1, 'description':1}
        candidate_space = Sample.objects(__raw__=query_filter).only(*result_filter)
        match_list = []
        for candidate in candidate_space:
            if "ssdeep" in candidate:
                score = pydeep.compare(target_ssdeep, candidate["ssdeep"])
                if score >= threshold and candidate["md5"] != target_md5:
                    match_list.append({'md5': candidate["md5"], 'description': candidate["description"], 'score': score})
        # finally sort the results
        match_list.sort(key=lambda sample: sample["score"], reverse=True)
        for match in match_list:
            self._add_result("ssdeep_match (MD5)", match["md5"], {'description': match["description"], 'score': match["score"]})
