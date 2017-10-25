# (c) 2013, The MITRE Corporation.  All rights reserved.
# Source code distributed pursuant to license agreement.

from django import forms

from crits.core.user_tools import user_sources, get_user_organization
from crits.core.handlers import get_source_names, collect_objects
from crits.core.class_mapper import class_from_type
from crits.services.handlers import get_config
from crits.vocabulary.indicators import IndicatorCI

from datetime import datetime
from dateutil.tz import tzutc

from . import formats
from . import taxii

def get_taxii_feeds(user_srcs):
    # Avoid options that cause failure: set recipients to intersection of
    # user's sources and the sources that have TAXII feeds configured
    sc = get_config('taxii_service')
    taxii_feeds = []
    try:
        for svr in sc.taxii_servers:
            for fid in sc['taxii_servers'][svr]['feeds']:
                fd = sc['taxii_servers'][svr]['feeds'][fid]
                if fd['source'] in user_srcs:
                    taxii_feeds.append(("%s - %s" % (svr, fid),
                                        "%s - %s" % (svr, fd['feedname'])))
    except (AttributeError, KeyError):
        taxii_feeds = []

    return taxii_feeds

class TAXIISendForm(forms.Form):
    rcpts = forms.MultipleChoiceField(required=False,
                                      label="Recipient",
                                      help_text="Recipient Feeds",
                                      widget=forms.SelectMultiple)

    def __init__(self, username, item, *args, **kwargs):
        """
        Initialize the form.
        Populates form fields based on context object (item) and its related
        items. The way the form fields are populated ensures that only
        STIXifyable / CybOXable options are provided.
        """
        kwargs.setdefault('label_suffix', ':')
        super(TAXIISendForm, self).__init__(*args, **kwargs)
        sc = get_config('taxii_service')
        user_srcs = user_sources(username)
        self.fields['rcpts'].choices = get_taxii_feeds(user_srcs)

        # populate all of the multi choice fields with valid options
        # from the context CRITs object's related items.
        for _type in get_supported_types():
            collected = collect_objects(item._meta['crits_type'], item.id,
                                        1, sc['max_rels'], sc['max_rels'],
                                        [_type], user_srcs, False)
            field = forms.MultipleChoiceField(required=False, label=_type)
            field.choices = filter_and_format_choices(collected, item, _type)
            self.fields[_type] = field

    def get_chosen_relations(self):
        """
        Convert multi choice field selections to a flat array
        of { id, type } dicts.
        """
        data = self.cleaned_data
        chosen = []
        for _type in get_supported_types():
            for item in data.get(_type, []):
              chosen.append({'_id' : item, '_type' : _type})
        return chosen

class TAXIIPollForm(forms.Form):
    feeds = forms.MultipleChoiceField(required=True,
                 label="TAXII Feeds",
                 help_text="Feeds to poll for data",
                 widget=forms.SelectMultiple(attrs={'style':"height:200px;"}))

    import_all = forms.BooleanField(required=False, initial=False,
                            label="Skip preview and import all data into CRITs")

    use_last = forms.BooleanField(required=False, initial=True,
                                  label='Get all messages since last full poll')

    begin = forms.DateTimeField(required=False,
                                label='Exclusive Begin Timestamp',
                                initial = datetime.now(tzutc()))

    end = forms.DateTimeField(required=False,
                              label='Inclusive End Timestamp',
                              initial = datetime.now(tzutc()))

    def __init__(self, username, *args, **kwargs):
        """
        Initialize the form.
        """
        kwargs.setdefault('label_suffix', ':')
        super(TAXIIPollForm, self).__init__(*args, **kwargs)
        sc = get_config('taxii_service')
        user_srcs = user_sources(username)
        self.fields['feeds'].choices = get_taxii_feeds(user_srcs)


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
    choice_fmt = formats.get_format(_type) # get formatting option for current CRITs type
    ind_crits_type = class_from_type("Indicator")._meta['crits_type']
    for choice in choice_opts:
        obj = choice_opts.get(choice)[1]
        if _type == ind_crits_type and not has_cybox_repr(obj):
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

    namespace = forms.CharField(required=True,
                  label="Namespace (URI)",
                  initial='http://example.com',
                  widget=forms.TextInput(),
                  help_text="The XML namespace to use in STIX documents.")

    ns_prefix = forms.CharField(required=True,
                  label="Namespace Prefix",
                  initial='example',
                  widget=forms.TextInput(),
                  help_text="The XML namespace prefix to use in STIX IDs.")

    header_events = forms.BooleanField(required=False,
                  label="Pkg Header Events",
                  initial=False,
                  help_text="Create an Event from each STIX package header & relate all items to it.")

    obs_as_ind = forms.BooleanField(required=False,
                  label="Observable as Indicator",
                  initial=False,
                  help_text="Create indicators for all qualifying observables instead of Domain and IP TLOs")

    max_rels = forms.IntegerField(required=True,
                                  label="Maximum Related",
                                  initial=200,
                                  min_value=0,
                                  max_value=5000,
                                  widget=forms.TextInput(),
                                  help_text="The maximum number of related "
                                            "items, of each type, that can "
                                            "be selected for a TAXII message.")

    tserver_attrs = {'size': 10,
                     'style':"height:100px; background-image: none"}
    taxii_servers = forms.ChoiceField(required=False,
                  label="TAXII Servers",
                  initial={},
                  widget=forms.Select(attrs=tserver_attrs))

    def __init__(self, choices=[], *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(TAXIIServiceConfigForm, self).__init__(*args, **kwargs)
        self.fields['taxii_servers'].choices = choices

class TAXIIServerConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    servername = forms.CharField(required=True,
                                 label="Server Name",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Give this server a name "
                                           "(Letters, Numbers, and Spaces).")

    cur_sname = forms.CharField(required=False,
                                label="Current Server Name",
                                initial='',
                                widget=forms.HiddenInput())

    hostname = forms.CharField(required=True,
                               label="Hostname",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="TAXII server hostname. (Omit URI "
                                         "scheme, e.g. 'http://')")

    https = forms.BooleanField(required=False,
                               label="HTTPS",
                               initial=True,
                               help_text="Connect using HTTPS.")

    port = forms.CharField(required=False,
                           label="Port",
                           initial='',
                           widget=forms.TextInput(),
                           help_text="TAXII server port. "
                                     "Leave blank for default.")

    ppath = forms.CharField(required=True,
                            label="Poll Path",
                            initial='/poll/',
                            widget=forms.TextInput(),
                            help_text="Path used when polling the TAXII server.")

    ipath = forms.CharField(required=True,
                            label="Inbox Path",
                            initial='/inbox/',
                            widget=forms.TextInput(),
                            help_text="Path used when sending data to the TAXII server.")

    version = forms.ChoiceField(required=True,
                                label="TAXII Version",
                                choices = [('1.1','1.1'),('1.0','1.0'),
                                           ('0', 'Unknown')],
                                initial='0',
                                help_text="The TAXII version supported "
                                          "by this server.")

    keyfile = forms.CharField(required=False,
                              label="Private Keyfile",
                              initial='',
                              widget=forms.TextInput(),
                              help_text="Path to authentication keyfile, "
                                        "if required.")

    lcert = forms.CharField(required=False,
                            label="Local Certificate",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="Path to authentication certificate "
                                      "file, if required.")

    user = forms.CharField(required=False,
                            label="Username",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="Username, if required.")

    pword = forms.CharField(required=False,
                            label="Password",
                            initial='',
                            widget=forms.PasswordInput(render_value=True),
                            help_text="Password, if required.")

    tserver_attrs = {'size': 10,
                     'style':"height:100px; background-image: none"}
    feeds = forms.ChoiceField(required=False,
                              label="TAXII Feeds",
                              widget=forms.Select(attrs=tserver_attrs))

    def __init__(self, choices=[], *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(TAXIIServerConfigForm, self).__init__(*args, **kwargs)
        self.fields['feeds'].choices = choices

class TAXIIFeedConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    srv_name = forms.CharField(required=True,
                               label="Current Server Name",
                               initial='',
                               widget=forms.HiddenInput())

    feedname = forms.CharField(required=False,
                               label="Feed Name",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="A TAXII feed (collection) on this server.")

    fid = forms.CharField(required=False,
                          label="Feed ID",
                          initial='',
                          widget=forms.HiddenInput())

    source = forms.ChoiceField(required=True,
                               label="CRITs Source",
                               help_text="The CRITs Source name to associate"
                                         " with this feed.")

    fcert = forms.CharField(required=False,
                            label="Encryption Certificate",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="Path to cert file used to encrypt STIX "
                                      "packages. Leave blank for no encryption.")

    fkey = forms.CharField(required=False,
                           label="Decryption Key",
                           initial='',
                           widget=forms.TextInput(),
                           help_text="Path to key file used to decrypt STIX "
                                     "packages, if available.")

    subID = forms.CharField(required=False,
                            label="Subscription ID",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="The subscription ID for this "
                                      "feed, if required.")

    last_poll = forms.CharField(required=False,
                            label="Last Poll (Read-Only)",
                            widget=forms.TextInput(attrs={'readonly':"True"}),
                            help_text="The end timestamp of the last full "
                            "poll. Future polls begin with this date/time.")

    def_conf = forms.ChoiceField(required=True,
                                 label="Default Confidence",
                                 help_text="Indicators with no Confidence "
                                           "are assigned this value.")

    def_impact = forms.ChoiceField(required=True,
                                   label="Default Impact",
                                   help_text="Indicators with no Impact "
                                             "are assigned this value.")

    def __init__(self, username, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(TAXIIFeedConfigForm, self).__init__(*args, **kwargs)

        srcs = get_source_names(True, True, username)
        self.fields['source'].choices = [(c.name, c.name) for c in srcs]
        self.fields['source'].initial = get_user_organization(username)

        ind_ci = IndicatorCI.values()
        self.fields['def_conf'].choices = [(c, c.title()) for c in ind_ci]
        self.fields['def_conf'].initial = 'unknown'
        self.fields['def_impact'].choices = [(c, c.title()) for c in ind_ci]
        self.fields['def_impact'].initial = 'unknown'


class UploadStandardsForm(forms.Form):
    """
    Django form for uploading a standards document.
    """

    error_css_class = 'error'
    required_css_class = 'required'
    filedata = forms.FileField(label="XML File or Zip of XML Files")
    source = forms.ChoiceField(required=True)
    use_hdr_src = forms.BooleanField(required=False, initial=True,
                        label="Use STIX Header Information Source, if possible")
    reference = forms.CharField(required=False)
    import_all = forms.BooleanField(required=False, initial=False,
                            label="Skip preview and import all data into CRITs")
    make_event = forms.BooleanField(required=False, label="Create event", initial=True)

    def __init__(self, username, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(UploadStandardsForm, self).__init__(*args, **kwargs)

        srcs = get_source_names(True, True, username)
        self.fields['source'].choices = [(c.name, c.name) for c in srcs]
        self.fields['source'].initial = get_user_organization(username)
