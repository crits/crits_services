from io import BytesIO
import fnmatch
from hashlib import md5
import os
import tarfile
import time

import requests

from django.template.loader import render_to_string

from crits.samples.handlers import handle_file
from crits.pcaps.handlers import handle_pcap_file
from crits.core.user_tools import get_user_organization
from crits.services.core import Service, ServiceConfigError
from crits.vocabulary.relationships import RelationshipTypes
from crits.indicators.indicator import Indicator
from crits.samples.sample import Sample
from crits.vocabulary.acls import SampleACL, PCAPACL

from . import forms


class CuckooService(Service):
    """
    Analyze a sample using Cuckoo Sandbox.
    """

    name = 'cuckoo'
    version = '1.0.5'
    supported_types = ['Sample', 'IP', 'Domain', 'Indicator']
    description = ("Analyze a Sample, IP, Domain, and Indicator" +
                   " using Cuckoo Sandbox.")

    @staticmethod
    def parse_config(config):
        # When editing a config we are given a string.
        # When validating an existing config it will be a list.
        # Convert it to a list of strings.
        machines = config.get('machine', [])
        if isinstance(machines, basestring):
            config['machine'] = [machine for machine in machines.split('\r\n')]
        errors = []
        if not config['host']:
            errors.append("Cuckoo host required.")
        if not config['port']:
            errors.append("Cuckoo port required.")
        if not config['machine']:
            errors.append("List of machines required.")
        if errors:
            raise ServiceConfigError(errors)

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.CuckooConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @classmethod
    def generate_config_form(self, config):
        # Convert machines to newline separated strings
        config['machine'] = '\r\n'.join(config['machine'])
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.
                                    CuckooConfigForm(initial=config),
                                 'config_error': None})
        form = forms.CuckooConfigForm
        return form, html

    @staticmethod
    def _tuplize_machines(machines):
        return [(machine, machine) for machine in machines]

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        machines = CuckooService._tuplize_machines(config['machine'])
        return render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.CuckooRunForm(machines=machines,
                                                             initial=config),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def bind_runtime_form(analyst, config):
        machines = CuckooService._tuplize_machines(config['machine'])

        if 'tor' not in config:
            config['tor'] = False
        if 'procmemdump' not in config:
            config['procmemdump'] = False

        # The integer values are submitted as a list for some reason.
        # Package and machine are submitted as a list too.
        data = {'timeout': config['timeout'][0],
                'tor': config['tor'],
                'procmemdump': config['procmemdump'],
                'options': config['options'][0],
                'enforce_timeout': config['enforce_timeout'],
                'existing_task_id': config['existing_task_id'][0],
                'package': config['package'][0],
                'ignored_files': config['ignored_files'][0],
                'machine': config['machine'][0],
                'tags': config['tags'][0]}

        return forms.CuckooRunForm(machines=machines, data=data)

    @staticmethod
    def valid_for(obj):
        valid_types = ('Domain', 'File Name', 'IPv4 Address', 'URI')
        if isinstance(obj, Indicator) and obj.ind_type not in valid_types:
            raise ServiceConfigError("Invalid Indicator Type: %s" %
                                     obj.ind_type)
        if isinstance(obj, Sample) and obj.filedata.grid_id is None:
            raise ServiceConfigError("Invalid Sample Data: Missing File Data")

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.CuckooConfigForm().fields
        for name, field in fields.iteritems():
            if name == 'machine':
                display_config[field.label] = '\r\n'.join(config[name])
            else:
                display_config[field.label] = config[name]

        return display_config

    @property
    def base_url(self):
        if self.config.get('secure'):
            proto = 'https'
        else:
            proto = 'http'
        return '%s://%s:%s' % (proto, self.config.get('host'),
                               self.config.get('port'))

    @property
    def proxies(self):
        proxy_host = self.config.get('proxy_host')
        proxy_port = self.config.get('proxy_port')
        if proxy_host:
            proxy = proxy_host + ':' + str(proxy_port)
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

    def submit_task(self, obj):
        # Sets the configuration option that was provided in the runtime form
        files = {}
        payload = {}
        options = {}

        package = str(self.config.get('package'))
        if package != 'auto':
            payload['package'] = package

        timeout = self.config.get('timeout')
        if timeout:
            payload['timeout'] = timeout

        enforce_timeout = self.config.get('enforce_timeout')
        if enforce_timeout:
            payload['enforce_timeout'] = 'True'

        tor = self.config.get('tor')
        if tor:
            options['tor'] = 'yes'

        procmemdump = self.config.get('procmemdump')
        if procmemdump:
            options['procmemdump'] = 'yes'

        options = ",".join(list(map(lambda option: '{0}={1}'.format(option,
                           options[option]), options.keys())))
        custom_options = str(self.config.get('options'))
        if custom_options:
            if len(options) > 0:
                options += ","
            options += custom_options

        tags = str(self.config.get('tags'))

        machine = self.config.get('machine', '')

        # Set files to the appropriate TLO
        if self.obj._meta['crits_type'] == 'Domain':
            files = {'url': ('', obj.domain)}
        elif self.obj._meta['crits_type'] == 'IP':
            files = {'url': ('', obj.ip)}
        elif self.obj._meta['crits_type'] == 'Sample':
            files = {'file': (obj.filename, obj.filedata.read())}
        elif self.obj._meta['crits_type'] == 'Indicator':
            files = {'url': ('', obj.value)}

        # Runs the task on the selected machines and returns the
        # submitted task_id.
        return self.submit_on_selected_machine(files, payload, machine,
                                               tags, options)

    def submit_on_selected_machine(self, files, payload, machine, tags,
                                   option):
        tasks = {}

        if machine.lower() == 'all':
            # Submit a new task with otherwise the same info to each machine
            for machine in self.get_machines():
                task_id = self.post_task(files, payload, machine=machine,
                                         options=option)
                if task_id is not None:
                    tasks[machine] = task_id
        elif machine.lower() == 'any':
            task_id = self.post_task(files, payload, tags=tags,
                                     options=option)
            if task_id is not None:
                tasks['any'] = task_id
        elif machine:
            task_id = self.post_task(files, payload, machine=machine,
                                     options=option)
            if task_id is not None:
                tasks[machine] = task_id

        # Return a dictionary of tasks.
        return tasks

    def post_task(self, files, payload, machine=None, tags=None,
                  options=None):
        """
        Post a new analysis task to Cuckoo.

        Args:
            files: file information for file object or url
            payload (dict): POST parameters
            machine (str): the machine label to submit to (or None if any
                machine)
            options (dict): Task options
        Returns:
            Task ID or None
        """
        if machine:
            payload['machine'] = machine
        else:
            machine = 'any'
        if options:
            payload['options'] = options

        # Set the response object to be None.
        r = None

        if self.obj._meta['crits_type'] in ('Domain', 'IP', 'Indicator'):
            # Submit a url to the cuckoo instnace if the crits_type was an
            # Indicator, IP, or Domain.
            r = requests.post(self.base_url + '/tasks/create/url',
                              files=files, data=payload, proxies=self.proxies)
        elif self.obj._meta['crits_type'] == 'Sample':
            # Submit a file to the cuckoo instance if the crits_type was a
            # Sample.
            r = requests.post(self.base_url + '/tasks/create/file',
                              files=files, data=payload, proxies=self.proxies)

        # TODO: check return status codes
        if r.status_code != requests.codes.ok:
            msg = "Failed to submit file to machine '%s'." % machine
            self._error(msg)
            self._debug(r.text)
            return None

        response = dict(r.json())

        if 'task_ids' in response:
            task_id = response['task_ids'][0]
        else:
            task_id = response['task_id']

        self._info("Options: {0}".format(options))
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
        max_delay = 120

        self._info("Retrieving results for Task ID %s" % task_id)

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
                # If there was any error fetching the PCAP, don't try to
                # process it.
                if pcap:
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

    def run(self, obj, config):
        # Because config and obj are referenced in a lot of different places
        # as an attribute of the class, just assign it here.
        self.config = config
        self.obj = obj

        task_id = self.config.get('existing_task_id')

        if task_id:
            self._info("Reusing existing task with ID: %s" % task_id)
            task_id = {'existing_task': task_id}
        else:
            task_id = self.submit_task(obj)
            if not task_id:
                return
            if len(task_id) > 1:
                tasks = ', '.join([str(v) for v in sorted(task_id.values())])
                self._info("Successfully submitted tasks with IDs: %s" % tasks)
            else:
                self._info("Successfully submitted task with ID: %s" % task_id)

        self._notify()

        for machine, task_id in task_id.iteritems():
            try:
                self.run_cuckoo(machine, task_id)
            except Exception as e:
                self._error("Error retrieving Task ID %s: %s" % (task_id, e))

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
        user = get_user_info(str(self.current_task.user))
        if not user.has_access_to(SampleACL.WRITE):
            self._info("User does not have permission to add samples to CRITs")
            self._add_result("Processing Dropped Files Cancelled", "User does not have permission to add Samples to CRITs")
            return


        # TODO: Error handling
        t = tarfile.open(mode='r:bz2', fileobj=BytesIO(dropped))

        ignored = self.config.get('ignored_files', '').split('\r\n')
        for f in t.getmembers():
            if not f.isfile():
                continue

            data = t.extractfile(f).read()
            name = os.path.basename(f.name)
            if any([fnmatch.fnmatch(name, x) for x in ignored]):
                self._debug("Ignoring file: %s" % name)
                continue

            h = md5(data).hexdigest()
            self._info("New file: %s (%d bytes, %s)" % (name, len(data), h))

            handle_file(name, data, self.obj.source,
                        related_id=str(self.obj.id),
                        related_type=str(self.obj._meta['crits_type']),
                        campaign=self.obj.campaign,
                        source_method=self.name,
                        relationship=RelationshipTypes.RELATED_TO,
                        user=self.current_task.user)
            self._add_result("file_added", name, {'md5': h})

        t.close()

    def _process_pcap(self, pcap):
        self._debug("Processing PCAP.")
        self._notify()
        org = get_user_organization(self.current_task.user)
        user = self.current_task.user
        if not user.has_access_to(PCAPACL.WRITE):
            self._info("User does not have permission to add PCAP to CRITs")
            self._add_result("PCAP Processing Canceled", "User does not have permission to add PCAP to CRITs")
            return

        h = md5(pcap).hexdigest()
        result = handle_pcap_file("%s.pcap" % h,
                                  pcap,
                                  org,
                                  user=self.current_task.user,
                                  related_id=str(self.obj.id),
                                  related_type=self.obj._meta['crits_type'],
                                  method=self.name)
        self._add_result("pcap_added", h, {'md5': h})
