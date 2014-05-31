import logging
import os
import subprocess

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)


class UpxService(Service):
    """
    Attempt to unpack a binary using UPX.
    """

    name = "upx"
    version = '1.0.2'
    type_ = Service.TYPE_UNPACKER
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('upx_path',
                            ServiceConfigOption.STRING,
                            description="Location of the upx binary.",
                            default='/usr/bin/upx',
                            required=True,
                            private=True),
    ]

    @classmethod
    def _validate(cls, config):
        upx_path = config.get("upx_path", "")
        if not upx_path:
            raise ServiceConfigError("Must specify UPX path.")

        if not os.path.isfile(upx_path):
            raise ServiceConfigError("UPX path does not exist.")

        if not os.access(upx_path, os.X_OK):
            raise ServiceConfigError("UPX path is not executable.")

        if not 'upx' in upx_path.lower():
            raise ServiceConfigError("Executable does not appear"
                                         " to be UPX.")

    def _scan(self, context):
        upx_path = self.config.get("upx_path", "")

        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [upx_path, "-q", "-d", filename]

            # UPX does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output = proc.communicate()[0]
            self._debug(output)

            if proc.returncode:
                # UPX return code of 1 indicates an error.
                # UPX return code of 2 indicates a warning (usually, the
                # file was not packed by UPX).
                msg = ("UPX could not unpack the file.")
                self._warning(msg)
                return

            with open(tmp_file, "rb") as newfile:
                data = newfile.read()

            #TODO: check to make sure file was modified (new MD5), indicating
            # it was actually unpacked
            self._add_file(data,
                           log_msg="UPX unpacked file with MD5: {0}",
                           relationship="Packed_From")
