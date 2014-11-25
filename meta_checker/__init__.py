import logging

from crits.services.core import Service, ServiceConfigError
from crits.samples.sample import Sample
from crits.services.analysis_result import AnalysisResult

class MetaChecker(Service):
    """
    Compare metadata of this sample to others
    """

    name = "meta_checker"
    version = '1.0.2'
    supported_types = ['Sample']
    description = "Compare metadata of this sample to others."

    @staticmethod
    def valid_for(obj):
        # Make sure there are AnalysisResults for this object.
        results = AnalysisResult.objects(object_type=obj._meta['crits_type'],
                                         object_id=str(obj.id))
        if len(results) == 0:
            raise ServiceConfigError("Object must have analysis results.")

    @staticmethod
    def get_config(existing_config):
        # This service no longer users config options, so blow away any
        # existing configs.
        return {}

    def run(self, obj, config):
        my_md5 = obj.md5
        my_results = AnalysisResult.objects(object_type=obj._meta['crits_type'],
                                            object_id=str(obj.id))

        completed_results = []
        for result_doc in my_results:
            # skip our own results so we don't get nasty feedback
            if result_doc["service_name"] == self.name:
                continue

            for result in result_doc["results"]:
                if "md5" in result:
                    res_type = "md5"
                else:
                    res_type = "result"
                res_hash = "{0}-{1}".format(result_doc["service_name"], result[res_type])
                if result[res_type] and res_hash not in completed_results:
                    total_count = self._get_meta_count(res_type, result[res_type])
                    count_result = {
                        'service':          result_doc["service_name"],
                        'type':             res_type,
                        res_type:           result[res_type],
                        'count':            total_count,
                    }
                    self._add_result("meta_count_{0}".format(res_type), result["result"], count_result)
                    completed_results.append(res_hash)

    def _get_meta_count(self, meta_type, meta_val):
        query_field = "results.{0}".format(meta_type)
        query = {query_field: meta_val}
        total_count = AnalysisResult.objects(object_type='Sample',
                                             __raw__=query).only('id').count()
        return total_count
