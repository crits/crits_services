from django import forms

class SplunkSearchConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    splunk_url = forms.CharField(required=True,
                                 label="Splunk URL",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Full URL of your Splunk API instance (e.g. https://192.168.1.100:8089/)")
    splunk_browse_url = forms.CharField(required=True,
                                        label="Splunk Browse URL",
                                        initial='',
                                        widget=forms.TextInput(),
                                        help_text="Full URL of Splunk instance for your browser (e.g. https://192.168.1.100:8000/)")
    splunk_user = forms.CharField(required=True,
                                  label="Splunk username",
                                  initial='',
                                  widget=forms.TextInput(),
                                  help_text="Username for Splunk instance")
    password = forms.CharField(required=True,
                                  label="Password",
                                  initial='',
                                  widget=forms.PasswordInput(),
                                  help_text="Password for Splunk instance")
    search_limit = forms.CharField(required=True,
                                   label="Search limit",
                                   initial='10',
                                   widget=forms.NumberInput(),
                                   help_text="Sets a limit to your searches so the db doesn't get flooded")
    splunk_timeout = forms.CharField(required=True,
                                     label = "Splunk timeout",
                                     initial='180',
                                     widget=forms.NumberInput(),
                                     help_text="Sets a timeout limit for a given Splunk search to run")
    search_earliest = forms.CharField(required=True,
                                      label="Earliest",
                                      initial='-2d@d',
                                      widget=forms.TextInput(),
                                      help_text="Using Splunk time syntax, this value will be the earliest your search runs.")
    search_config = forms.CharField(required=True,
                                    label="Search Config",
                                    initial='/opt/crits/crits_services/splunk_search_service/searches.json',
                                    widget=forms.TextInput(),
                                    help_text="Full path of your Splunk search config file.")
    url_search = forms.BooleanField(required=False,
                                   label="URL Search",
                                   initial='',
                                   widget=forms.CheckboxInput(),
                                   help_text="Explicitly run Splunk searches based on potential URls mined from this object.")
    domain_search = forms.BooleanField(required=False,
                                   label="Domain Search",
                                   initial='',
                                   widget=forms.CheckboxInput(),
                                   help_text="Explicitly run Splunk searches based on potential domains mined from this object.")
    ip_search = forms.BooleanField(required=False,
                                   label="IP Search",
                                   initial='',
                                   widget=forms.CheckboxInput(),
                                   help_text="Explicitly run Splunk searches based on potential IPs mined from this object.")
    email_addy_search = forms.BooleanField(required=False,
                                   label="Email Search",
                                   initial='',
                                   widget=forms.CheckboxInput(),
                                   help_text="Explicitly run Splunk searches based on potential Email Addresses mined from this object.")
    hash_search = forms.BooleanField(required=False,
                                   label="Hash Search",
                                   initial='',
                                   widget=forms.CheckboxInput(),
                                   help_text="Explicitly run Splunk searches based on potential hashes mined from this object.")
    ignore_filetypes = forms.CharField(required=False,
                                       label="Ignore filetypes",
                                       initial='^[A-Za-z0-9]*( image data|ASCII text| archive data)',
                                       widget=forms.TextInput(),
                                       help_text="This is a regular expression telling the service we want to ignore certain samples if they are uploaded and this service is launched on triage.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix',':')
        super(SplunkSearchConfigForm, self).__init__(*args, **kwargs)
