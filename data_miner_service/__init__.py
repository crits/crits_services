import re
import logging

from crits.services.core import Service
from crits.raw_data.raw_data import RawData
from crits.samples.sample import Sample
from crits.domains.domain import TLD
from crits.indicators.indicator import Indicator
from crits.core.data_tools import make_ascii_strings

logger = logging.getLogger(__name__)


class DataMinerService(Service):
    """
    Mine data for useful information

    Currently this service only runs on RawData and Samples. This could be
    expanded to work on email bodies + headers or other top-level objects which
    contain a chunk of data ripe for parsing potential indicators.
    """

    name = "DataMiner"
    version = '1.0.0'
    type_ = Service.TYPE_CUSTOM
    template = "data_miner_service_template.html"
    supported_types = ['RawData', 'Sample']
    required_fields = []
    default_config = [
        ]

    def _scan(self, obj):
        if isinstance(obj, RawData):
            data = obj.data
        elif isinstance(obj, Sample):
            if obj.filedata.grid_id == None:
                self._info("No data to parse.")
                return

            samp_data = obj.filedata.read()
            data = make_ascii_strings(data=samp_data)
            if not data:
                self._debug("Could not find sample data to parse.")
                return
        else:
            self._debug("This type is not supported by this service.")
            return
        ips = extract_ips(data)
        for ip in ips:
            tdict = {'Type': "IP Address"}
            id_ = Indicator.objects(value=ip).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential IP Address', ip, tdict)
        domains = extract_domains(data)
        for domain in domains:
            tdict = {'Type': "Domain"}
            id_ =  Indicator.objects(value=domain).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential Domains', domain, tdict)
        emails = extract_emails(data)
        for email in emails:
            tdict = {'Type': "Email"}
            id_ = Indicator.objects(value=email).only('id').first()
            if id_:
                tdict['exists'] = str(id_.id)
            self._add_result('Potential Emails', email, tdict)

# hack of a parser to extract potential ip addresses from data
def extract_ips(data):
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, data)]
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip)
    return ips

# hack of a parser to extract potential domains from data
def extract_domains(data):
    pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    domains = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_domains = []
    for item in domains:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_domains.append(item)
            except:
                pass
    return final_domains

# hack of a parser to extract potential emails from data
def extract_emails(data):
    pattern = r'[a-zA-Z0-9-\.\+]+@.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?[\.[a-zA-Z]{2,}'
    emails = [each for each in re.findall(pattern, data) if len(each) > 0]
    final_emails = []
    for item in emails:
        if len(item) > 1 and item.find('.') != -1:
            try:
                tld = item.split(".")[-1]
                check = TLD.objects(tld=tld).first()
                if check:
                    final_emails.append(item)
            except:
                pass
    return final_emails
