# (c) 2014, Adam Polkosnik, <adam.polkosnik@ny.frb.org> || <apolkosnik@gmail.com>

from crits.services.core import Service, ServiceConfigOption, ServiceConfigError
from codetective import get_type_of, show


DEFAULT_END = -1
DEFAULT_START = 0
DEFAULT_ANALYZE = True
DEFAULT_MODULES = ["win", "web", "unix", "db", "other"]


class CodetectiveService(Service):
    """
    A tool to determine the crypto/encoding algorithm used according to traces of its representation
    """

    name = "codetective"
    version = '0.0.1'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('start_offset',
                            ServiceConfigOption.INT,
                            description="Start offset",
                            required=False,
                            private=False,
                            default=DEFAULT_START),

        ServiceConfigOption('end_offset',
                            ServiceConfigOption.INT,
                            description="End offset",
                            required=True,
                            private=False,
                            default=DEFAULT_END),

        ServiceConfigOption('filters',
                            ServiceConfigOption.MULTI_SELECT,
                            description="Filter by source of your string",
                            choices=DEFAULT_MODULES,
                            default=DEFAULT_MODULES,
                            required=False,
                            private=False),

        ServiceConfigOption('analyze',
                            ServiceConfigOption.BOOL,
                            description="show more details whenever possible - expands shadow files fields",
                            required=False,
                            private=False,
                            default=DEFAULT_ANALYZE),

    ]

    @staticmethod
    def valid_for(context):
        # Only run if there's data
        return context.has_data()

    def _doit(self, data, filters, analyze):
        self._log('info',"filters:%s analyze:%x" %(filters, analyze))
        (results,result_details) = get_type_of(data, filters)
        for key in results.keys():
                if(len(results[key]) > 0):
#                        print '%s:' % key,results[key]
#                        self._add_result('Codetective', "%s" % key, {'Value': repr(results[key])})
                        if analyze:
                                for codetype in results[key]:
                                        if codetype in result_details.keys():
#                                                print '\t',result_details[codetype]
                                                self._add_result('Codetective', "%s" % result_details[codetype], {'Confidence': key})
        if(len(results['confident']) + len(results['likely']) + len(results['possible']) == 0):
                print 'unknown! ;('
                self._add_result('Codetective', "%s" % "unknown", {'Value': "unknown"})
        return results

    def _scan(self, context):
        start_offset = self.config.get("start_offset", DEFAULT_START)
        end_offset = self.config.get("end_offset", DEFAULT_END)
        analyze = self.config.get("analyze", DEFAULT_ANALYZE)
        filters = self.config.get("filters", DEFAULT_MODULES)
        #filters = ['win','web', 'unix', 'db', 'other']
        self._doit(context.data[start_offset:end_offset], filters, analyze )
        #self._add_result('Codetective', "%.1f" % output, {'Value': output})

