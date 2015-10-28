# (c) 2013, The MITRE Corporation.  All rights reserved.
# Source code distributed pursuant to license agreement.

from django import forms

from crits.core.user_tools import user_sources, get_user_organization
from crits.core.handlers import get_source_names, collect_objects
from crits.core.class_mapper import class_from_type
from crits.services.handlers import get_config


from . import formats

class TAXIIForm(forms.Form):
    rcpts = forms.MultipleChoiceField(required=True,
                                      label="Recipients",
                                      help_text="Recipients",
                                      widget=forms.SelectMultiple)

    def __init__(self, username, item, *args, **kwargs):
        """
        Initialize the form.
        Populates form fields based on context object (item) and its related items.
        The way the form fields are populated ensures that only STIXifyable / CybOXable
        options are provided.
        """
        super(TAXIIForm, self).__init__(*args, **kwargs)
        sc = get_config('taxii_service')

        # Avoid options that cause failure: set recipients to intersection of
        # user's sources and the sources that have TAXII feeds configured
        user_srcs = user_sources(username)
        taxii_srcs = [crtfile.split(',')[0] for crtfile in sc['certfiles']]
        self.fields['rcpts'].choices = [(n, n) for n in set(user_srcs).intersection(taxii_srcs)]

        # populate all of the multi choice fields with valid options
        # from the context CRITs object's related items.
        for _type in get_supported_types(): # TODO the hardcoded args to collect_objects should be revisited
            collected = collect_objects(item._meta['crits_type'], item.id, 1, 100, 100, [_type], user_srcs)
            field = forms.MultipleChoiceField(required=False, label=_type)
            field.choices = filter_and_format_choices(collected, item, _type)
            self.fields[_type] = field

    def get_chosen_relations(self):
        """
        Convert multi choice field selections to a flat array of { id, type } dicts.
        """
        data = self.cleaned_data
        chosen = []
        for _type in get_supported_types():
            for item in data.get(_type, []):
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

    from .handlers import has_cybox_repr

    ret_opts = [] # return storage array
    item_type = item._meta['crits_type'] # get the type of the subject
    choice_fmt = formats.get_format(_type) # get the formatting option for the current CRITs type
    for choice in choice_opts:
        obj = choice_opts.get(choice)[1]
        if _type == class_from_type("Indicator")._meta['crits_type'] and not has_cybox_repr(obj):
            # this indicator can't currently be converted to CybOX, so don't offer as option in UI
            continue
        if item.id != obj.id or item_type != _type:
            # only process if the item isn't the current context crits item
            ret_opts.append((choice, choice_fmt.format(obj).encode('utf-8')))
    return ret_opts

def get_supported_types():
    """
    Get a list of supported types for TAXII service.
    """
    supported_types = ['Certificate',
                       'Domain',
                       'Email',
                       'Indicator',
                       'IP',
                       'PCAP',
                       'RawData',
                       'Sample']
    return supported_types

class TAXIIServiceConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    hostname = forms.CharField(required=True,
                               label="Hostname",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="TAXII server hostname.")

    https = forms.BooleanField(required=False,
                               label="HTTPS",
                               initial=True,
                               help_text="Connect using HTTPS.")


    keyfile = forms.CharField(required=True,
                             label="Keyfile",
                             initial='',
                             widget=forms.TextInput(),
                             help_text="Location of your keyfile.")

    certfile = forms.CharField(required=True,
                              label="Certfile",
                              initial='',
                              widget=forms.TextInput(),
                              help_text="Location of your certificate.")

    data_feed = forms.CharField(required=True,
                                label="Data Feed",
                                initial='',
                                widget=forms.TextInput(),
                                help_text="Your TAXII data feed name.")

    create_events = forms.BooleanField(required=False,
                                       label="Events",
                                       initial=False,
                                       help_text="Create events for all STIX documents.")

    certfiles = forms.CharField(required=True,
                                label="Configuration",
                                initial='',
                                widget=forms.Textarea(attrs={'cols': 80,
                                                            'rows': 10}),
                                help_text="Comma delimited list of CRITs"
                                          " source name, TAXII feed name, and"
                                          " certificate file on disk for that"
                                          " source.")

    def __init__(self, *args, **kwargs):
        super(TAXIIServiceConfigForm, self).__init__(*args, **kwargs)


class UploadStandardsForm(forms.Form):
    """
    Django form for uploading a standards document.
    """

    error_css_class = 'error'
    required_css_class = 'required'
    filedata = forms.FileField()
    source = forms.ChoiceField(required=True)
    reference = forms.CharField(required=False)
    make_event = forms.BooleanField(required=False, label="Create event", initial=True)

    def __init__(self, username, *args, **kwargs):
        super(UploadStandardsForm, self).__init__(*args, **kwargs)
        self.fields['source'].choices = [(c.name,
                                          c.name) for c in get_source_names(True,
                                                                            True,
                                                                            username)]
        self.fields['source'].initial = get_user_organization(username)
