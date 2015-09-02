from django import forms

class ThreatreconConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    tr_api_key = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from Threatrecon.",
                                 initial='')
    tr_query_url = forms.CharField(required=True,
                                   label="Query URL",
                                   widget=forms.TextInput(),
                                   initial='https://api.threatrecon.co/api/v1/search')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatreconConfigForm, self).__init__(*args, **kwargs)
