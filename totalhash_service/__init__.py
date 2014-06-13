# Copyright (c) 2014, The MITRE Corporation. All rights reserved.

# Source code distributed pursuant to license agreement.

import hashlib
import logging
import urllib2
import hmac

from django.conf import settings

from crits.services.core import Service, ServiceConfigOption

logger = logging.getLogger(__name__)


class TotalHashService(Service):
    """
    (PE Clustering) as implemented by Team Cymru' PEhash http://totalhash.com/pehash-source-code/.

    Optionally look up the resulting hash on totalhash.
    """

    name = "totalhash"
    version = '0.1.0'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('th_api_key',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from Totalhash.",
                            required=True,
                            private=True),
        ServiceConfigOption('th_user',
                            ServiceConfigOption.STRING,
                            description="Required. Obtain from Totalhash.",
                            required=True,
                            private=True),
        ServiceConfigOption('th_query_url',
                            ServiceConfigOption.STRING,
                            default='https://api.totalhash.com/',
                            required=True,
                            private=True),
    ]

    def _scan(self, obj):
        # If we have an API key, go ahead and look it up.
        key = str(self.config.get('th_api_key', ''))
        user = self.config.get('th_user', '')
        url = self.config.get('th_query_url', '')

        h = obj.sha1

        if not key:
            self._add_result('Analysis Link', url + "/analysis/" + h)
            self._info("No API key, not checking Totalhash.")
            return

        signature = hmac.new(key, msg=h, digestmod=hashlib.sha256).hexdigest()
        params = "/analysis/" + h + "&id=" + user + "&sign=" + signature
        req = urllib2.Request(url + params)

        if settings.HTTP_PROXY:
            proxy = urllib2.ProxyHandler({'https': settings.HTTP_PROXY})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)

        try:
            response = urllib2.urlopen(req)
            data = response.read()
        except Exception as e:
            logger.info("Totalhash: network connection error (%s)" % e)
            self._info("Network connection error checking totalhash (%s)" % e)
            return

        from lxml import etree
        try:
            root = etree.fromstring(data)
        except Exception as e:
            logger.error("Totalhash: parse error (%s)" % e)
            self._error("Error parsing results: %s" % e)
            return

        self._add_result('Analysis Metadata', root.attrib['time'])

        it = root.getiterator('av')
        for av in it:
            stats = {
                'scanner': av.attrib['scanner'],
                'timestamp': av.attrib['timestamp']
            }
            self._add_result('AV', av.attrib['signature'], stats)

        it = root.getiterator('process')
        for proc in it:
            filename = proc.attrib['filename']
            # Some entries appear with an empty filename and nothing else.
            if filename == '':
                continue
            pid = proc.attrib['pid']

            dlls = []
            for dll in proc.findall('dll_handling_section/load_dll'):
                dlls.append(dll.attrib['filename'])

            files = []
            for file_ in proc.findall('filesystem_section/create_file'):
                info = {
                    'Filename': file_.attrib['srcfile'],
                    'Action': 'create'
                }
                files.append(info)
            for file_ in proc.findall('filesystem_section/delete_file'):
                info = {
                    'Filename': file_.attrib['srcfile'],
                    'Action': 'delete'
                }
                files.append(info)

            procs = []
            for cp in proc.findall('process_section/create_process'):
                info = {
                    'Cmdline': cp.attrib['cmdline'],
                    'Target PID': cp.attrib['targetpid'],
                    'Action': 'create'
                }
                procs.append(info)
            for op in proc.findall('process_section/open_process'):
                info = {
                    'Target PID': op.attrib['targetpid'],
                    'API': op.attrib['apifunction'],
                    'Action': 'open'
                }
                procs.append(info)

            hosts = []
            for host in proc.findall('winsock_section/getaddrinfo'):
                hosts.append(host.attrib['requested_host'])

            mutexes = []
            for mutex in proc.findall('mutex_section/create_mutex'):
                mutexes.append(mutex.attrib['name'])

            hooks = []
            for hook in proc.findall('windows_hook_section/set_windows_hook'):
                hooks.append(hook.attrib['hookid'])

            regs = []
            for reg in proc.findall('registry_section/set_value'):
                info = {
                    'Key': reg.attrib['key'],
                    'Value': reg.attrib['value'],
                    'Action': 'set'
                }
                regs.append(info)

            svcs = []
            for svc in proc.findall('service_section/create_service'):
                info = {
                    'Display Name': svc.attrib['displayname'],
                    'Image Path': svc.attrib['imagepath'],
                    'Action': 'create'
                }
                svcs.append(info)
            for svc in proc.findall('service_section/start_service'):
                info = {
                    'Display Name': svc.attrib['displayname'],
                    'Action': 'start'
                }
                svcs.append(info)

            sysinfo = []
            for si in proc.findall('system_info_section/check_for_debugger'):
                sysinfo.append(si.attrib['apifunction'])

            stats = {
                'PID': pid,
                'Loaded DLLs': ', '.join([dll for dll in dlls]),
                'Files': files,
                'Processes': procs,
                'Requested hosts': ', '.join([host for host in hosts]),
                'Created mutexes': ', '.join([mutex for mutex in mutexes]),
                'Registry keys': regs,
                'Created services': svcs,
                'Hooks': ', '.join([hook for hook in hooks]),
                'System checks': ', '.join([si for si in sysinfo])
            }
            self._add_result('Processes', filename, stats)

        it = root.getiterator('running_process')
        for proc in it:
            stats = {
                'PID': proc.attrib['pid'],
                'PPID': proc.attrib['ppid']
            }
            self._add_result('Running processes', proc.attrib['filename'], stats)

        it = root.getiterator('flows')
        for flow in it:
            info =  {
                'Source IP': flow.attrib['src_ip'],
                'Source Port': flow.attrib['src_port'],
                'Dest Port': flow.attrib['dst_port'],
                'Bytes': flow.attrib['bytes']
            }

            if flow.attrib['protocol'] == '6':
                proto = 'TCP'
            elif flow.attrib['protocol'] == '17':
                proto = 'UDP'
            else:
                proto = flow.attrib['protocol']

            info['Protocol'] = proto

            self._add_result('Flows', flow.attrib['dst_ip'], info)

        it = root.getiterator('dns')
        for dns in it:
            info = {
                'Type': dns.attrib['type'],
                'IP': dns.attrib.get('ip', 'Not resolved.')
            }
            self._add_result('DNS', dns.attrib['rr'], info)
        it = root.getiterator('http')
        for http in it:
            info =  {
                'User Agent': http.attrib['user_agent'],
                'Type': http.attrib['type']
            }

            self._add_result('HTTP', http.text, info)
