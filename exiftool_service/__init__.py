import logging
import os
import subprocess

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)


class exiftoolService(Service):
    """
    Display metadata information about the files using exiftool utility.
    """

    name = "exiftool"
    version = '0.1.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('exiftool_path',
                            ServiceConfigOption.STRING,
                            description="Location of the exiftool binary.",
                            default='/usr/local/bin/exiftool',
                            required=True,
                            private=True),
        ServiceConfigOption('exiftool_args',
                            ServiceConfigOption.STRING,
                            description="Arguments for the exiftool binary.",
                            default='-v',
                            required=True,
                            private=False),
    ]

    @classmethod
    def _validate(cls, config):
        exiftool_args = config.get("exiftool_args", "")
        exiftool_path = config.get("exiftool_path", "")
        if not exiftool_path:
            raise ServiceConfigError("Must specify exiftool path.")

        if not os.path.isfile(exiftool_path):
            raise ServiceConfigError("exiftool path does not exist.")

        if not os.access(exiftool_path, os.X_OK):
            raise ServiceConfigError("exiftool path is not executable.")

        if not 'exiftool' in exiftool_path.lower():
            raise ServiceConfigError("Executable does not appear"
                                         " to be exiftool.")

    def _scan(self, context):
        exiftool_path = self.config.get("exiftool_path", "")
        exiftool_args = self.config.get("exiftool_args", "")

        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [exiftool_path, exiftool_args ,filename]

            # EXIFTOOL does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            #output = proc.communicate()[0]
            #self._debug(output)
            if proc.returncode:
                msg = ("EXIFTOOL could not process the file.")
                self._warning(msg)
                return

            for line in iter(proc.stdout.readline,''):
                self._debug(line)
                #out = filter(None, re.split("[,=]+",line))
                #out = re.split("[,=]+",line)
                out = line.strip("+| \n\r")
                self._add_result('exiftool', out) 

