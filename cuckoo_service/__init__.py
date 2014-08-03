from cStringIO import StringIO
import fnmatch
from hashlib import md5
import os
import tarfile
import time

import requests

from crits.services.core import Service, ServiceConfigOption


PACKAGES = ['auto', 'exe', 'dll', 'pdf', 'doc']
IGNORED_FILES = [
    "SharedDataEvents*",
]


class CuckooService(Service):
    """
    Analyze a sample using Cuckoo Sandbox.
    """

    name = 'cuckoo'
    version = '1.0.1a1'
    type_ = Service.TYPE_CUSTOM
    supported_types = ['Sample']
    default_config = [
        ServiceConfigOption('timeout',
                            ServiceConfigOption.INT,
                            default=0,
                            description="Maximum time (in seconds) to allow "
                            "the analysis to run. Leave as '0' to use the "
                            "timeout specified in Cuckoo's conf/cuckoo.conf "
                            "(default is 120)."),
        ServiceConfigOption('machine',
                            ServiceConfigOption.STRING,
                            default="",
                            description="Name of the machine to use for the "
                            "analysis. Leave blank to use the first available "
                            "machine. 'all' for ALL machines."),
        ServiceConfigOption('host',
                            ServiceConfigOption.STRING,
                            default='',
                            required=True,
                            private=True,
                            description="Hostname or IP of the API server "
                            "running Cuckoo sandbox."),
        ServiceConfigOption('port',
                            ServiceConfigOption.STRING,
                            default='8090',
                            required=True,
                            private=True,
                            description="Port on the Cuckoo sandbox server "
                            "that api.py is listening on."),
        ServiceConfigOption('proxy host',
                            ServiceConfigOption.STRING,
                            default='',
                            private=True,
                            description="Hostname or IP of web proxy, if "
                            "needed to access the Cuckoo sandbox server."),
        ServiceConfigOption('proxy port',
                            ServiceConfigOption.STRING,
                            default='',
                            private=True,
                            description="Port used for HTTP Proxy, if needed "
                            "to access the Cuckoo sandbox server."),
        ServiceConfigOption('webui_host',
                            ServiceConfigOption.STRING,
                            default='',
                            private=True,
                            description="Hostname or IP of the Cuckoo "
                            "web interface."),
        ServiceConfigOption('webui_port',
                            ServiceConfigOption.STRING,
                            default='',
                            private=True,
                            description="Port on the Cuckoo sandbox server "
                            "that manage.py is listening on."),
        ServiceConfigOption('package',
                            ServiceConfigOption.SELECT,
                            default=0,
                            choices=PACKAGES,
                            description="The Cuckoo analysis package to run",),
        ServiceConfigOption('existing task id',
                            ServiceConfigOption.INT,
                            default=0,
                            description="DEVELOPMENT ONLY: Fetch results from "
                            "an existing analysis task rather than running "
                            "the sample in the sandbox. Use '0' to run a new "
                            "analysis"),
        ServiceConfigOption('ignored files',
                            ServiceConfigOption.LIST,
                            default=IGNORED_FILES,
                            description="File paths (may include wildcards) "
                            "that are not automatically resubmitted.")
    ]

    @property
    def base_url(self):
        return 'http://%s:%s' % (self.config.get('host'),
                                 self.config.get('port'))

    @property
    def proxies(self):
        proxy_host = self.config.get('proxy host')
        proxy_port = self.config.get('proxy port')
        if proxy_host:
            proxy = proxy_host + ':' + proxy_port
        else:
            proxy = ''
        return {'http': proxy, 'https': proxy}

    def get_machines(self):
        machinelist = requests.get(self.base_url + '/machines/list',
                                   proxies=self.proxies)
        machinelist = dict(machinelist.json())['machines']
        ids = []
        for x in machinelist:
            ids.append(x.get('name'))
            machineid = x.get('name')
            self._info("Found machine ID %s" % machineid)
        return ids

    def submit_task(self, context):
        files = {'file': (context.filename, context.data)}

        payload = {}

        package = str(self.config.get('package'))
        if package != 'auto':
            payload['package'] = package

        timeout = self.config.get('timeout')
        if timeout:
            payload['timeout'] = timeout

        tasks = {}

        machine = self.config.get('machine', "").lower()
        if machine == "all":
            # Submit a new task with otherwise the same info to each machine
            for each in self.get_machines():
                task_id = self.post_task(files, payload, each)
                if task_id is not None:
                    tasks[each] = task_id

        elif machine:  # Only one Machine ID requested
            task_id = self.post_task(files, payload, machine)
            if task_id is not None:
                tasks[machine] = task_id

        else:  # If Machine not set
            task_id = self.post_task(files, payload)
            if task_id is not None:
                tasks['any'] = task_id

        # return dictionary of Tasks
        return tasks

    def post_task(self, files, payload, machine=None):
        """
        Post a new analysis task to Cuckoo.

        Args:
            files: file information
            payload (dict): task options
            machine (str): the machine label to submit to (or None if any
                machine)

        Returns:
            Task ID or None
        """
        if machine:
            payload['machine'] = machine
        else:
            machine = "any"

        r = requests.post(self.base_url + '/tasks/create/file',
                          files=files, data=payload,
                          proxies=self.proxies)

        # TODO: check return status codes
        if r.status_code != requests.codes.ok:
            msg = "Failed to submit file to machine '%s'." % machine
            self._error(msg)
            self._debug(r.text)
            return None

        task_id = dict(r.json())['task_id']
        self._info("Submitted Task ID %s for machine %s" % (task_id, machine))

        return task_id

    def get_task(self, task_id):
        r = requests.get(self.base_url + '/tasks/view/%s' % task_id,
                         proxies=self.proxies)

        if r.status_code != requests.codes.ok:
            self._warning("No task with ID %s found?" % task_id)
            return None

        return dict(r.json())['task']

    def get_report(self, task_id):
        r = requests.get(self.base_url + '/tasks/report/%s' % task_id,
                         proxies=self.proxies)

        if r.status_code != requests.codes.ok:
            self._warning("No report for task with ID %s found?" % task_id)
            return {}

        return dict(r.json())

    def get_dropped(self, task_id):
        r = requests.get(self.base_url + '/tasks/report/%s/dropped' % task_id,
                         proxies=self.proxies)

        if r.status_code != requests.codes.ok:
            self._warning("Could not fetch dropped files for task ID %s" %
                          task_id)
            return None

        return r.content

    def get_pcap(self, task_id):
        r = requests.get(self.base_url + '/pcap/get/%s' % task_id,
                         proxies=self.proxies)

        if r.status_code != requests.codes.ok:
            self._warning("Could not fetch PCAP for task ID %s" %
                          task_id)
            return None

        return r.content

    def run_cuckoo(self, machine_id, task_id):
        # We start by waiting for 5 seconds, then 10, then 15, etc. up to
        # 60 seconds. The total time allowed for execution, processing, and
        # analysis is around 6 minutes.
        delay = 5
        step = 5
        max_delay = 60

        while delay <= max_delay:
            taskinfo = self.get_task(task_id)
            status = taskinfo.get('status', "UNKNOWN")

            if status == 'reported':
                time.sleep(1)

                # If an invalid 'machine' was specified, no error will be
                # raised by Cuckoo, but no results will be returned.
                if not taskinfo.get('guest'):
                    self._error("No matching machine found, "
                                "analysis was not performed.")
                    return

                self._info("Task completed successfully.")

                report = self.get_report(task_id)

                # Get machine/analysis info
                self._process_info(report.get('info'), machine_id)
                # Get signatures that fired
                self._process_signatures(report.get('signatures'))

                self._process_behavior(report.get('behavior'))
                self._process_network(report.get('network'))

                self._debug("Fetching .tar.bz2 with dropped files")
                dropped = self.get_dropped(task_id)
                self._debug("Received %d bytes" % len(dropped))
                self._process_dropped(dropped)
                pcap = self.get_pcap(task_id)
                self._process_pcap(pcap)

                return

            elif status == 'failure':
                for err in taskinfo.get('errors', []):
                    self._error(err)
                return

            else:
                msg = "Status: %s, waiting %d seconds to try again."
                self._debug(msg % (status, delay))
                self._notify()
                time.sleep(delay)
                delay += step

        self._error("Cuckoo did not complete before timeout")

    def _scan(self, context):
        task_id = self.config.get('existing task id')
        if task_id:
            self._info("Reusing existing task with ID: %s" % task_id)
            task_id = {'existing_task': task_id}
        else:
            task_id = self.submit_task(context)
            if not task_id:
                return
            if len(task_id) > 1:
                tasks = ', '.join(str(v) for k, v in task_id.iteritems())
                self._info("Successfully submitted tasks with IDs: %s" % tasks)
            else:
                self._info("Successfully submitted task with ID: %s" % task_id)

        self._notify()

        for m, t in task_id.iteritems():
            self.run_cuckoo(m, t)

    def _process_info(self, info, machine_id):
        if not info:
            return
        self._debug("Processing Analysis Info")

        if machine_id in ('existing_task', 'any'):
            machine_name = info.get('machine').get('name')
            if not machine_name:
                self._info("Could not get machine name (Cuckoo <= 1.1)")
        else:
            machine_name = machine_id
        webui_host = self.config.get('webui_host')
        webui_port = self.config.get('webui_port')

        data = {}
        data['started'] = info.get('started')
        data['ended'] = info.get('ended')

        #  If there is a webui set up and configured, give the link
        if webui_host:
            link = 'http://%s:%s/analysis/%s' % (webui_host,
                                                 webui_port,
                                                 info.get('id'))
            data['analysis link'] = link
        else:
            data['analysis_id'] = info.get('id')

        self._add_result('info', str(machine_name), data)

    def _process_signatures(self, signatures):
        if not signatures:
            return

        self._debug("Processing Signatures")

        for signature in signatures:
            subtype = 'signature'
            result = signature['description']
            data = {'severity': signature['severity'],
                    'name': signature['name']}

            self._add_result(subtype, result, data)

    def _process_behavior(self, behavior):
        if not behavior:
            return

        self._debug("Processing Behavior")

        for process in behavior.get('processes'):
            subtype = 'process'
            result = process.get('process_name', '')
            data = {'process_id': process.get('process_id', ''),
                    'parent_id': process.get('parent_id', ''),
                    'first_seen': process.get('first_seen', '')}
            self._add_result(subtype, result, data)

        # Turn this "inside out" since each 'call' is a result, but it should
        # inherit the process name and ID from the enclosing 'process'
#        for process in behavior.get('processes'):
#            proc_description = "%s (%s)" % (process.get('process_name'),
#                                            process.get('process_id'))
#            for call in process.get('calls'):
#                subtype = 'api_call'
#                result = call.get('api')
#                # We're modifying the results here, but since we're only doing
#                # it once I think it's OK.
#                data = call
#                # We're using 'api' as the 'result' so we can get rid of it.
#                del data['api']
#                data['process'] = proc_description
#                self._add_result(subtype, result, data)

        for file_ in behavior.get('summary').get('files'):
            self._add_result('file', str(file_), {})

        for regkey in behavior.get('summary').get('keys'):
            self._add_result('registry_key', str(regkey), {})

        for mutex in behavior.get('summary').get('mutexes'):
            self._add_result('mutex', str(mutex), {})

    def _process_network(self, network):
        if not network:
            return

        # network is a dict of lists
        self._debug("Processing Network indicators")
        self._notify()

        # this is a list of IPs as strings
        for host in network.get('hosts'):
            self._add_result('Host', str(host), {})

        # domain is a dict with keys ip and domain
        for domain in network.get('domains'):
            self._add_result('Domain', domain.get('domain'),
                             {'ip': domain.get('ip')})

        # Adds IPs resolved from Domains as strings
        for domain in network.get('domains'):
            if domain.get('ip'):
                host = domain.get('ip')
                self._add_result('Resolved IP', str(host),
                                 {'domain': domain.get('domain')})

        # http is a dict with keys body uri user-agent method host version path
        # data port
        for http in network.get('http'):
            if http.get('uri'):
                self._add_result('HTTP Request', http.get('uri'), http)

        # Index User-Agent
        for http in network.get('http'):
            if http.get('user-agent'):
                # set {} as data to avoid too much redundancy
                self._add_result('User-Agent', http.get('user-agent'), {})

    def _process_dropped(self, dropped):
        # Dropped is a byte string of the .tar.bz2 file
        self._debug("Processing dropped files.")
        self._notify()

        # TODO: Error handling
        t = tarfile.open(mode='r:bz2', fileobj=StringIO(dropped))

        ignored = self.config.get('ignored files', [])
        for f in t.getmembers():
            if not f.isfile():
                continue

            data = t.extractfile(f).read()
            name = os.path.basename(f.name)
            if any([fnmatch.fnmatch(name, x) for x in ignored]):
                self._debug("Ignoring file: %s" % name)
                continue

            self._info("New file: %s (%d bytes, %s)" % (name, len(data),
                                                        md5(data).hexdigest()))
            self._add_file(data, name)

        t.close()

    def _process_pcap(self, pcap):
        self._debug("Processing PCAP.")
        self._notify()
        # TODO: Error handling...
        self._add_file(pcap, collection='PCAP')
