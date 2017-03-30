from django import forms

class OpenDNSConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    Investigate_API_Token = forms.CharField(required=True,
                                            label="API Token",
                                            widget=forms.TextInput(),
                                            help_text="Obtain from OpenDNS.",
                                            initial='')
    Investigate_URI = forms.CharField(required=True,
                                      label="Query URL",
                                      widget=forms.TextInput(),
                                      initial='https://investigate.api.opendns.com/')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(OpenDNSConfigForm, self).__init__(*args, **kwargs)
