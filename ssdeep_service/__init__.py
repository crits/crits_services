import logging
import pydeep

from crits.services.core import ServiceConfigOption
from crits.services.db import DatabaseService as Service

logger = logging.getLogger(__name__)

class SSDeepService(Service):
    """
    Compare sample to others with ssdeep.
    """

    name = "ssdeep_compare"
    version = '1.0.2'
    type_ = Service.TYPE_CUSTOM
    purpose = "comparison"
    supported_types = ['Sample']
    # TODO: Figure out how to do this.
    #required_fields = ['ssdeep', 'mimetype']
    default_config = [
        ServiceConfigOption('threshold',
                            ServiceConfigOption.INT,
                            description="Min threshold for match",
                            required=True,
                            private=False,
                            default=50),
    ]

    def _scan(self, context):
        threshold = self.config.get("threshold", 50)
        target_ssdeep = context.sample_dict.get('ssdeep', None)
        target_md5 = context.md5
        target_mimetype = context.sample_dict.get('mimetype', None)
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
        result_filter = {'md5': 1, 'ssdeep': 1}
        candidate_space = self._fetch_meta(query_filter, result_filter)
        match_list = []
        for candidate in candidate_space:
            if "ssdeep" in candidate:
                score = pydeep.compare(target_ssdeep, candidate["ssdeep"])
                if score >= threshold and candidate["md5"] != target_md5:
                    match_list.append({'md5': candidate["md5"], 'score': score})
        # finally sort the results
        match_list.sort(key=lambda sample: sample["score"], reverse=True)
        for match in match_list:
            self._add_result("ssdeep_match", match["md5"], {'md5': match["md5"], 'score': match["score"]})
