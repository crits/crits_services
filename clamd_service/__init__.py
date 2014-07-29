# (c) 2014, Adam Polkosnik <adam.polkosnik@ny.frb.org> 
# 
import logging
import os
import pyclamd

from crits.services.core import Service, ServiceConfigOption
from crits.services.core import ServiceConfigError

logger = logging.getLogger(__name__)


class clamdService(Service):
    """
    Display metadata information about the files using clamd utility.
    """

    name = "clamd"
    version = '0.0.2'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('clamd_sock_path',
                            ServiceConfigOption.STRING,
                            description="Location of the clamd unix socket (if using the socket)",
                            default='/var/run/clamav/clamd.ctl',
                            private=True),
        ServiceConfigOption('clamd_host_name',
                            ServiceConfigOption.STRING,
                            description="hostname or ip address of the clamd daemon",
                            default='127.0.0.1',
                            private=True),
        ServiceConfigOption('clamd_host_port',
                            ServiceConfigOption.INT,
                            description="TCP port number of clamd daemon",
                            default='3310',
                            private=True),
        ServiceConfigOption('clamd_force_reload',
                            ServiceConfigOption.BOOL,
                            description="Force clamd to reload signature database",
                            private=False,
                            default=False),
    ]

    @classmethod
    def _validate(cls, config):
        clamd_sock_path = str(config.get("clamd_sock_path", ""))
        clamd_host_name = str(config.get("clamd_host_name", ""))
        clamd_host_port = int(config.get("clamd_host_port", ""))
        if not clamd_sock_path and (not clamd_host_name or not clamd_host_port):
            raise ServiceConfigError("Must specify clamd Unix socket path or IP and port.")



    def _scan(self, context):
        clamd_sock_path = str(self.config.get("clamd_sock_path", ""))
        clamd_host_name = str(self.config.get("clamd_host_name", ""))
        clamd_host_port = int(self.config.get("clamd_host_port", ""))
        clamd_force_reload = self.config.get("clamd_force_reload", "")

        try:
            self._debug('Attempting Unix socket connection to clamd')
            cd = pyclamd.ClamdUnixSocket(clamd_sock_path)
            result = cd.ping()
        except pyclamd.ConnectionError: 
            try:
                self._debug('Attempting Network connection to clamd')
                cd = pyclamd.ClamdNetworkSocket(clamd_host_name, clamd_host_port)
                result = cd.ping()
            except pyclamd.ConnectionError: 
                logger.error("clamd: Can\'t connect to Clamd\'s network socket.")
                self._error("clamd: Can\'t connect to Clamd\'s network socket.")
                return

        if clamd_force_reload:
            self._debug(cd.reload())
        cd_version = cd.version()
        self._debug(cd_version)
        try:
            output = cd.scan_stream(context.data)
        except pyclamd.BufferTooLongError:
                logger.error("clamd: BufferTooLongError.")
                self._error("clamd: BufferTooLongError.")
                return
        except pyclamd.ConnectionError:
                logger.error("clamd: Can\'t connect to Clamd\'s socket.")
                self._error("clamd: Can\'t connect to Clamd\'s  socket.")
                return

        self._debug(output)
        if output: 
            out = output['stream']
            self._add_result('clamd',out[1], {'Status': out[0]})
        else:
            self._add_result('clamd','None' , {'Status': 'NOT FOUND'})

