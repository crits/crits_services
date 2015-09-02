from django import forms


class FarsightConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    farsight_api_key = forms.CharField(required=True,
                                     label="API Key",
                                     widget=forms.TextInput(),
                                     help_text="Obtain API key from Farsight.",
                                     initial='')
    farsight_api_url = forms.CharField(required=True,
                                       label="API URL",
                                       widget=forms.TextInput(),
                                       initial='https://api.dnsdb.info')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(FarsightConfigForm, self).__init__(*args, **kwargs)
