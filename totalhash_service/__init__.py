# Copyright (c) 2016, The MITRE Corporation. All rights reserved.

# Source code distributed pursuant to license agreement.

import hashlib
import logging
import urllib2
import hmac

from django.conf import settings
from django.template.loader import render_to_string

from crits.services.core import Service

from . import forms

logger = logging.getLogger(__name__)


class TotalHashService(Service):
    """
    (PE Clustering) as implemented by Team Cymru' PEhash http://totalhash.com/pehash-source-code/.

    Optionally look up the resulting hash on totalhash.
    """

    name = "totalhash"
    version = '0.1.0'
    supported_types = ['Sample']
    description = "Look up a sample on totalhash."

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.TotalHashConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.TotalHashConfigForm(initial=config),
                                 'config_error': None})
        form = forms.TotalHashConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}
        display_config['TH API Key'] = config['th_api_key']
        display_config['TH User'] = config['th_user']
        display_config['TH Query URL'] = config['th_query_url']
        return display_config

    @staticmethod
    def save_runtime_config(config):
        del config['th_api_key']
        del config['th_user']

    def run(self, obj, config):
        # If we have an API key, go ahead and look it up.
        key = str(config.get('th_api_key', ''))
        user = config.get('th_user', '')
        url = config.get('th_query_url', '')

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
