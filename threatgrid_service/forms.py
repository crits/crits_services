from django import forms

class ThreatGRIDConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    api_key = forms.CharField(required=True,
                                label="API Key",
                                widget=forms.TextInput(),
                                help_text="Obtain an API key from a ThreatGRID device.",
                                initial='')
    host = forms.CharField(required=True,
                                label="ThreatGRID URL",
                                widget=forms.TextInput(),
                                initial='https://threatgrid.com/')
    auto_submit = forms.BooleanField(required=False,
                                label="Auto Submit",
                                initial=False,
                                help_text="Automatically submit samples during triage.")
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatGRIDConfigForm, self).__init__(*args, **kwargs)

class ThreatGRIDRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    submit = forms.BooleanField(required=False,
                                  label="Submit",
                                  help_text="Submit sample if not found.",
                                  initial=True)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatGRIDRunForm, self).__init__(*args, **kwargs)
