from django import forms

class ThreatExchangeConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    app_id = forms.CharField(required=True,
                             label="App ID",
                             initial='',
                             widget=forms.TextInput(),
                             help_text="Facebook ThreatExchange App ID.")
    app_secret = forms.CharField(required=True,
                             label="App Secret",
                             initial='',
                             widget=forms.PasswordInput(),
                             help_text="Facebook ThreatExchange App Secret.")
    headers = forms.CharField(required=False,
                              label="Headers",
                              initial='',
                              widget=forms.TextInput(),
                              help_text="Custom headers for requests.")
    verify = forms.BooleanField(required=False,
                                label="Verify",
                                initial=False,
                                help_text="Verify requests.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatExchangeConfigForm, self).__init__(*args, **kwargs)
