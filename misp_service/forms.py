from django import forms

class MispConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    misp_url = forms.CharField(required=True,
                               label="MISP URL",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="Full URL of your MISP instance.")
    misp_key = forms.CharField(required=True,
                               label="MISP API Key",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="MISP API Key for interacting with your MISP instance.")
    default_tags = forms.CharField(required=False,
                                  label="Global Event Tag",
                                  initial='',
                                  widget=forms.TextInput(),
                                  help_text="Comma-separated list of tags to add to every newly created MISP event.")
    event_prefix = forms.CharField(required=False,
                                   label="Event Prefix",
                                   initial='',
                                   widget=forms.TextInput(),
                                   help_text="Prefix to add to each MISP event info field (e.g. [ORG])")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(MispConfigForm, self).__init__(*args, **kwargs)