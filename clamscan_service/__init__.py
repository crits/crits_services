# (c) 2014, Adam Polkosnik <adam.polkosnik@ny.frb.org> 
# 
import logging
import os
import subprocess

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)


class clamscanService(Service):
    """
    Display metadata information about the files using clamscan utility.
    """

    name = "clamscan"
    version = '0.0.1'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('clamscan_path',
                            ServiceConfigOption.STRING,
                            description="Location of the clamscan binary.",
                            default='/usr/bin/clamscan',
                            required=True,
                            private=True),
        ServiceConfigOption('clamscan_args',
                            ServiceConfigOption.STRING,
                            description="Arguments for the clamscan binary.",
                            default='--no-summary --dumpcerts --detect-structured',
                            required=True,
                            private=False),
    ]

    @classmethod
    def _validate(cls, config):
        clamscan_args = config.get("clamscan_args", "")
        clamscan_path = config.get("clamscan_path", "")
        if not clamscan_path:
            raise ServiceConfigError("Must specify clamscan path.")

        if not os.path.isfile(clamscan_path):
            raise ServiceConfigError("clamscan path does not exist.")

        if not os.access(clamscan_path, os.X_OK):
            raise ServiceConfigError("clamscan path is not executable.")

        if not 'clamscan' in clamscan_path.lower():
            raise ServiceConfigError("Executable does not appear"
                                         " to be clamscan.")

    def _scan(self, context):
        clamscan_path = self.config.get("clamscan_path", "")
        clamscan_args = self.config.get("clamscan_args", "")

        # The _write_to_file() context manager will delete this file at the
        # end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            # force --no-summary, and we are redirecting stderr anyway
            args = [clamscan_path, '--no-summary']
            args = args + clamscan_args.split()
            args.append(filename)
            self._debug(args)

            # clamscan does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output = proc.communicate()[0]
            self._debug(output)
            out=output.split()
            if proc.returncode not in (0, 1):
                msg = ("clamscan could not process the file.")
                self._warning(msg)
                return

            if proc.returncode == 1:
                self._add_result('clamscan',out[1], {'Status': out[2]})
            else:
                self._add_result('clamscan', out[0][:-1], {'Status': out[1]})

