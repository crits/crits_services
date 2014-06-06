import hashlib

from crits.services.core import Service, ServiceConfigOption

DEFAULT_START = 0
DEFAULT_END = 0

class CarverService(Service):
    name = "carver"
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
                            required=False,
                            private=False,
                            default=DEFAULT_END),
    ]

    @staticmethod
    def valid_for(obj):
        return not obj.filedata.grid_id == None

    def _scan(self, obj):
        start_offset = self.config.get("start_offset", DEFAULT_START)
        end_offset = self.config.get("end_offset", DEFAULT_END)
        # Start must be 0 or higher. If end is greater than zero it must
        # also be greater than end_offset.
        if start_offset < 0 or (end_offset > 0 and start_offset > end_offset):
            self._error("Invalid offsets.")
            return

        data = obj.filedata.read()[start_offset:end_offset]
        if not data:
            self._error("No data.")
        else:
            self._add_file(data, filename=hashlib.md5(data).hexdigest(), log_msg="Carved file with MD5: {0}", relationship="Contains")
        return
