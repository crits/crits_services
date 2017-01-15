from django import forms
class XFEConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    xfe_api_key = forms.CharField(required=True,
                                     label="API Key",
                                     widget=forms.TextInput(),
                                     help_text="API key from X-Force Exchange.",
                                     initial='')
									 
    xfe_api_password = forms.CharField(required=True,
                                     label="API Password",
                                     widget=forms.TextInput(),
                                     help_text="API password from X-Force Exchange.",
                                     initial='')
									 
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(XFEConfigForm, self).__init__(*args, **kwargs)

