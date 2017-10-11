from django import forms

class OTXConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    api_key = forms.CharField(required=True,
                               label="API key",
                               initial=""
                               widget=forms.TextInput(),
                               help_text="API key OTX")
                               
    otx_server = forms.CharField(required=True,
                               label="OTX server",
                               initial="https://otx.alienvault.com/",
                               widget=forms.TextInput(),
                               help_text="URL for OTX server")
                               
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(OTXConfigForm, self).__init__(*args, **kwargs)

