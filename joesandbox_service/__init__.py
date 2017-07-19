import hashlib
import time
import zipfile
import io
import ipaddress
import xml.etree.ElementTree as ElementTree

from django.template.loader import render_to_string

from crits.services.core import Service, ServiceConfigError

from crits.samples.handlers import handle_file
from crits.objects.handlers import add_object
from crits.screenshots.handlers import add_screenshot
from crits.pcaps.handlers import handle_pcap_file
from crits.ips.handlers import ip_add_update
from crits.domains.handlers import upsert_domain

from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.ips import IPTypes

from crits.core.user_tools import get_user_organization

from . import forms
from . import jbxapi

class _NamedFile(object):
    def __init__(self, f, name):
        self.name = name
        self.f = f

    def read(self, *args, **kwargs): return self.f.read(*args, **kwargs)
    def seek(self, *args, **kwargs): return self.f.seek(*args, **kwargs)

class JoeSandboxService(Service):
    name = 'Joe Sandbox'
    version = '1.0.0'
    supported_types = ['Sample']
    description = ("Analyze a sample using Joe Sandbox.")

    @staticmethod
    def parse_config(config):
        errors = []

        if not config['api_url']:
            errors.append("Api Url required.")
        if not config['api_key']:
            errors.append("Api Key required.")
        if config['api_key'] and not len(config['api_key']) == 64:
            errors.append("Invalid api key length.")
        if config['ssl'] and not config['inet']:
            errors.append("HTTPS inspection requires internet access.")

        if errors:
            raise ServiceConfigError(errors)

    @staticmethod
    def validate_runtime(config, db_config):
        errors = []

        if "ssl" in config and "inet" not in config:
            errors.append("HTTPS inspection requires internet access.")

        if errors:
            raise ServiceConfigError(errors)

    @staticmethod
    def get_config(existing_config):
        config = {}
        fields = forms.JoeSandboxConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.JoeSandboxConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html', {
            'name': self.name,
            'form': forms.JoeSandboxConfigForm(initial=config),
            'config_error': None
        })
        form = forms.JoeSandboxConfigForm
        return form, html

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html', {
            'name': self.name,
            'form': forms.JoeSandboxRuntimeForm(initial=config),
            'crits_type': crits_type,
            'identifier': identifier,
        })

    @staticmethod
    def bind_runtime_form(analyst, config):
        # The values are submitted as a list for some reason.
        data = {
            "systems": config["systems"][0],                    # submitted as a list
            # Boolean fileds are submitted as lists iff they are True
            "use_cache": isinstance(config["use_cache"], list),
            "ssl": isinstance(config["ssl"], list),
            "inet": isinstance(config["inet"], list),
        }
        return forms.JoeSandboxRuntimeForm(data)

    @staticmethod
    def save_runtime_config(config):
        del config['api_key']
        del config['ignore_ssl_cert']
        del config['tandc']

    def run(self, obj, config):
        # store these two because we need them in many methods
        self.obj = obj
        self.config = config

        # initialize api
        self.joe = jbxapi.joe_api(
            config["api_key"],
            apiurl=config["api_url"],
            verify_ssl=not config["ignore_ssl_cert"],
            tandc=config["tandc"]
        )

        f = _NamedFile(obj.filedata, obj.filename)
        response = self.joe.analyze(f, '',
            cache_sha256=config["use_cache"],
            systems=config["systems"],
            inet=config["inet"],
            ssl=config["ssl"],
            comments="Uploaded by CRITs"
        )

        self._debug("Submitting task")
        try:
            webids = response["webids"]
        except TypeError:
            # no webid received
            self._critical(response)
            return
        else:
            self._info("Submitted tasks with webid(s) {}".format(", ".join(str(webid) for webid in webids)))

        self._notify()

        # grab first webid
        webid = webids.pop(0)

        # poll quickly and then once every minute
        delays = [10, 20, 30] + (config["timeout"] - 1) * [60]
        for delay in delays:
            time.sleep(delay)
            response = self.joe.status(webid)

            try:
                status = response["status"]
            except TypeError:
                self._warning("Invalid response: " + str(response))
                continue

            self._info("status: {}".format(status))
            self._notify()

            if status == "finished":
                self.process_data(webid)
                try:
                    webid = webids.pop(0)
                except IndexError:
                    break
        else:
            self._error("Timed out waiting for results.")

    def process_data(self, webid):
        run = self._most_interesting_run(webid)

        html_report = self.joe.report(webid, resource="html", run=run) 
        screenshots = self.joe.report(webid, resource="shoots", run=run) 
        incident_report = ElementTree.fromstring(self.joe.report(webid, resource="irxml", run=run)) 
        pcap = self.joe.report(webid, resource="pcapslim", run=run) 
        dropped_binaries = self.joe.report(webid, resource="bins", run=run) 

        self.process_sandbox_infos(incident_report, html_report)
        self.process_detection(incident_report)
        self.process_signatures(incident_report)
        self.process_dropped_binaries(dropped_binaries, incident_report)
        self.process_screenshots(screenshots)
        self.process_domains(incident_report)
        self.process_ips(incident_report)
        self.process_pcap(pcap)

    def process_detection(self, incident_report):
        detection = "malicious" if incident_report.find("./detection/malicious").text == "true" else \
                    "suspicious" if incident_report.find("./detection/suspicious").text == "true" else \
                    "clean" if incident_report.find("./detection/clean").text == "true" else \
                    "unknown"
        score = "{0} ({1} to {2})".format(
            incident_report.find("./detection/score").text,
            incident_report.find("./detection/minscore").text,
            incident_report.find("./detection/maxscore").text
        )
        confidence = "{0} ({1} to {2})".format(
            incident_report.find("./confidence/score").text,
            incident_report.find("./confidence/minscore").text,
            incident_report.find("./confidence/maxscore").text
        )

        self._add_result("Joe Sandbox Detection", detection, {
            "score": score,
            "confidence": confidence,
        })

        self._notify()

    def process_sandbox_infos(self, incident_report, html_report):
        errors = [e.text for e in incident_report.findall("./errors/error")]

        for error in errors:
            self._error(error)

        info = {
            "Report Id": incident_report.find("./id").text,
            "Joe Sandbox Version": incident_report.find("./version").text,
            "Architecture": incident_report.find("./arch").text,
            "System": incident_report.find("./system").text,
            "File Type": incident_report.find("./filetype").text,
        }

        # upload HTML report
        fp = io.BytesIO(html_report)
        fp.name = "report.html"
        ret = add_object(self.obj._meta['crits_type'], self.obj.id,
                         object_type=ObjectTypes.FILE_UPLOAD,
                         source=get_user_organization(self.current_task.user),
                         method=self.name,
                         reference=None,
                         file_=fp,
                         tlp=self.obj.tlp,
                         user=str(self.current_task.user))

        if ret['success']:
            md5 = hashlib.md5(html_report).hexdigest()
            info["md5"] = md5
        else:
            self._warning(ret["message"])

        self._add_result("Joe Sandbox Infos", "Report", info)
        self._notify()

    def process_dropped_binaries(self, dropped_binaries, incident_report):
        archive = zipfile.ZipFile(io.BytesIO(dropped_binaries))
        archive.setpassword("infected")
        names = archive.namelist()

        for name in names:
            binary = archive.read(name)
            ret = handle_file(name, binary, self.obj.source,
                related_id=str(self.obj.id),
                related_type=str(self.obj._meta['crits_type']),
                campaign=self.obj.campaign,
                source_method=self.name,
                relationship=RelationshipTypes.DROPPED_BY,
                user=self.current_task.user,
                is_return_only_md5=False)

            if ret['success']:
                md5 = hashlib.md5(binary).hexdigest()
                files_in_report = [f for f in incident_report.findall("./dropped/file/md5/..")
                                              if f.find('md5').text == md5.upper()]

                for report_file in files_in_report:
                    data = {
                        'md5': md5,
                        'malicious': getattr(report_file.find('malicious'), 'text', 'unknown'),
                    }
                    filepath = getattr(report_file.find('name'), 'text', name)

                    self._add_result("Dropped Files", filepath, data)
            else:
                self._warning(ret["message"])

        self._notify()

    def process_screenshots(self, screenshots):
        archive = zipfile.ZipFile(io.BytesIO(screenshots))
        names = archive.namelist()

        for name in names:
            screenshot = archive.read(name)

            ret = add_screenshot(description='Screenshot from Joe Sandbox', 
                tags=[],
                source=get_user_organization(self.current_task.user),
                method=self.name,
                reference=self.obj.filename, 
                tlp=self.obj.tlp,
                analyst=str(self.current_task.user), 
                screenshot=io.BytesIO(screenshot), 
                screenshot_ids=[],
                oid=str(self.obj.id), 
                otype=self.obj._meta['crits_type'])

            if ret['success']:
                md5 = hashlib.md5(screenshot).hexdigest()
                self._add_result("Screenshots", "Screenshot", {'md5': md5})
            else:
                self._warning(ret["message"])

        self._notify()

    def process_domains(self, incident_report):
        domains = incident_report.findall("./contacted/domains/domain")

        for domain in domains:
            ret = upsert_domain(domain.text,
                                source=get_user_organization(self.current_task.user),
                                username=str(self.current_task.user),
                                related_id=str(self.obj.id),
                                related_type=self.obj._meta['crits_type'],
                                relationship_type=RelationshipTypes.CONNECTED_TO)

            if ret['success']:
                malicious = domain.get('malicious', 'unknown')
                self._add_result("Domains", domain.text, {'malicious': malicious})
            else:
                self._warning(ret["message"])

        self._notify()

    def process_ips(self, incident_report):
        ips = incident_report.findall("./contacted/ips/ip")
        for ip in ips:
            ret = ip_add_update(ip.text, self._ip_type(ip.text),
                                source=get_user_organization(self.current_task.user),
                                source_method=self.name,
                                source_tlp=self.obj.tlp,
                                user=self.current_task.user,
                                related_id=str(self.obj.id),
                                related_type=self.obj._meta['crits_type'],
                                relationship_type=RelationshipTypes.CONNECTED_TO)

            if ret['success']:
                malicious = ip.get('malicious', 'unknown')
                self._add_result("IPs", ip.text, {'malicious': malicious})
            else:
                self._warning(ret["message"])

        self._notify()

    def process_pcap(self, pcap):
        md5 = hashlib.md5(pcap).hexdigest()

        filename = "{}.pcap".format(self.obj.filename)
        ret = handle_pcap_file(filename,
                               pcap,
                               # This is inconsistent with the rest of the code.
                               # However, due to a bug using get_user_organization(self.current_task.user)
                               # raises an exception
                               source_name=self.obj.source,
                               method=self.name,
                               tlp=self.obj.tlp,
                               reference=self.obj.filename,
                               user=str(self.current_task.user),
                               related_id=str(self.obj.id),
                               related_type=self.obj._meta['crits_type'])

        self._add_result("PCAPs", filename, {'md5': md5})

        self._notify()

    def process_signatures(self, incident_report):
        signatures = incident_report.findall("./signatures/signare") # typo is present in the report
        for sig in signatures:
            self._add_result("Important Signatures", sig.text)

        self._notify()

    def _ip_type(self, ip_string):
        """ Return the IP address version given an IP as the IP. """

        ip = ipaddress.ip_address(unicode(ip_string))
        if ip.version == 4:
            return IPTypes.IPV4_ADDRESS
        elif ip.version == 6:
            return IPTypes.IPV6_ADDRESS
        else:
            raise ValueError("Unkown IP version: {}".format(ip.version))

    def _most_interesting_run(self, webid):
        status_dict = self.joe.status(webid)
        run_count = status_dict["runnames"].count(";")

        reports = [self.joe.report(webid, resource="irjsonfixed", run=i) for i in range(run_count)]

        index_max_score, _ = max(enumerate(reports), key=lambda pair: pair[1]["analysis"]["detection"]["score"])
        return index_max_score
