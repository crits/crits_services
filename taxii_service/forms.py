# (c) 2013, The MITRE Corporation.  All rights reserved.
# Source code distributed pursuant to license agreement.

from django import forms

from crits.core.user_tools import user_sources
from crits.core.handlers import get_source_names, collect_objects

from crits.service_env import manager

from crits.domains.domain import Domain
from crits.emails.email import Email
from crits.events.event import Event
from crits.indicators.indicator import Indicator
from crits.ips.ip import IP
from crits.pcaps.pcap import PCAP
from crits.samples.sample import Sample

from . import formats

class TAXIIForm(forms.Form):
    supported_types = ['Domain', 'Email', 'Indicator', 'IP', 'PCAP', 'Sample', 'RawData', 'Certificate']
    error_css_class = 'error'
    required_css_class = 'required'
    rcpts = forms.MultipleChoiceField(required=True,
                                      label="Recipients",
                                      help_text="Recipients",
                                      widget=forms.SelectMultiple)
    certificates = forms.MultipleChoiceField(required=False,
                                 label="Certificates",
                                 help_text="Certificates to include")
    domains = forms.MultipleChoiceField(required=False,
                                 label="Domains",
                                 help_text="Domains to include")
    emails = forms.MultipleChoiceField(required=False,
                                label="Emails",
                                help_text="Emails to include")
    indicators = forms.MultipleChoiceField(required=False,
                                    label="Indicators",
                                    help_text="Indicators to include")
    ips = forms.MultipleChoiceField(required=False,
                                    label="IPs",
                                    help_text="IPs to include")
    pcaps = forms.MultipleChoiceField(required=False,
                                    label="PCAPs",
                                    help_text="PCAPs to include")
    rawdatas = forms.MultipleChoiceField(required=False,
                                    label="Raw Data",
                                    help_text="Raw Data to include")
    samples = forms.MultipleChoiceField(required=False,
                                 label="Samples",
                                 help_text="Samples to include")

    def __init__(self, username, item, *args, **kwargs):
	"""
	    Initialize the form.
	    Populates form fields based on context object (item) and its related items.
	    The way the form fields are populated ensures that only STIXifyable / CybOXable
	    options are provided.
	"""
        super(TAXIIForm, self).__init__(*args, **kwargs)
    	sc = manager.get_config('taxii_service')

	# set recipients to intersection of user's sources and the sources that have 
	# TAXII feeds configured, to avoid giving user options that are going to cause failure
	user_srcs = user_sources(username)
	taxii_srcs = [crtfile.split(',')[0] for crtfile in sc['certfiles']]
        self.fields['rcpts'].choices = [(n, n) for n in set(user_srcs).intersection(taxii_srcs)]

	# populate all of the multi choice fields with valid options
	# from the context CRITs object's related items.
	item_type = item._meta['crits_type']
	for _type in self.supported_types:
	    collected = collect_objects(item_type, item.id, 1, 100, 100, [_type], user_srcs)
	    self.fields["%ss" % _type.lower()].choices = filter_and_format_choices(collected, item, _type)

    def get_chosen_relations(self):
	"""
	    Convert multi choice field selections to a flat array of { id, type } dicts.
	"""
	data = self.cleaned_data
	chosen = []
	for _type in self.supported_types:
	    for item in data.get("%ss" % _type.lower(), []):
		chosen.append({'_id' : item, '_type' : _type})
	return chosen

def filter_and_format_choices(choice_opts, item, _type):
    """
	Given a list of CRITs options, filter out options matching the given item
	and format those options for display as a choice in a multi-select box.

	:param choice_opts A dict of CRITs objects in (id, json_repr) format
	:param item The item being viewed for TAXII service
	:param _type The type of objects represented in the choice_opts dict
    """

    ret_opts = [] # return storage array
    item_type = item._meta['crits_type'] # get the type of the subject
    choice_fmt = formats.get_format(_type) # get the formatting option for the current CRITs type
    for choice in choice_opts:
    	obj = choice_opts.get(choice)[1]
	if _type == Indicator._meta['crits_type'] and not obj.has_cybox_repr():
	    # this indicator can't currently be converted to CybOX, so don't offer as option in UI
	    continue
    	if item.id != obj.id or item_type != _type: 
	    # only process if the item isn't the current context crits item
	    ret_opts.append((choice, choice_fmt.format(obj)))
    return ret_opts

