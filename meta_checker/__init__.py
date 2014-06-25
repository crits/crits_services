import logging

from crits.services.core import ServiceConfigOption
from crits.services.db import DatabaseService as Service

logger = logging.getLogger(__name__)

DEFAULT_MAX=1000

class MetaChecker(Service):
    """
    Compare metadata of this sample to others
    """

    name = "meta_checker"
    version = '1.0.2'
    type_ = Service.TYPE_CUSTOM
    purpose = "comparison"
    supported_types = ['Sample']
    required_fields = ['md5']
    description = "Compare metadata of this sample to others."
    default_config = [
        ServiceConfigOption('max_result',
                            ServiceConfigOption.INT,
                            description="Max result threshold for showing metadata",
                            required=True,
                            private=False,
                            default=DEFAULT_MAX),
    ]

    def _get_meta_count(self, meta_type, meta_val):
        query_field = "analysis.results.{0}".format(meta_type)
        query = {query_field: meta_val}
        total_count = self._fetch_meta(query, {'md5': 1}).count()
        return total_count

    def _scan(self, obj):
        max_result = self.config.get("max_result", DEFAULT_MAX)
        my_md5 = obj.md5
        my_results = obj.analysis
        if len(my_results) == 0:
            logger.error = "Could not get analysis results for %s" % my_md5
            self._error("Could not get analysis results for %s" % my_md5)
            return
        completed_results = []
        for result_set in my_results:
            # skip our own results so we don't get nasty feedback
            if result_set["service_name"] == self.name:
                continue
            for result in result_set["results"]:
                if "md5" in result:
                    res_type = "md5"
                else:
                    res_type = "result"
                res_hash = "{0}-{1}".format(result_set["service_name"], result[res_type])
                if result[res_type] and res_hash not in completed_results:
                    total_count = self._get_meta_count(res_type, result[res_type])
                    count_result = {
                        'service':          result_set["service_name"],
                        'type':             res_type,
                        res_type:           result[res_type],
                        'count':            total_count,
                    }
                    self._add_result("meta_count_{0}".format(res_type), result["result"], count_result)
                    completed_results.append(res_hash)
