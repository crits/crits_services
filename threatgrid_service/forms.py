from django import forms

class ThreatGRIDConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    api_key = forms.CharField(required=True,
                                label="API Key",
                                widget=forms.TextInput(),
                                help_text="Obtain API key from ThreatGRID device (user settings tab).",
                                initial='')
    api_url = forms.CharField(required=True,
                                label="ThreatGRID API URL",
                                widget=forms.TextInput(),
                                initial='https://threatgrid.com/')

    def __init__(self, *args, **kwargs):
        super(ThreatGRIDConfigForm, self).__init__(*args, **kwargs)
