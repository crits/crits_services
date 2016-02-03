from django import forms


class ShodanConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    shodan_api_key = forms.CharField(required=True,
                                     label="API Key",
                                     widget=forms.TextInput(),
                                     help_text="Obtain API key from Shodan.",
                                     initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ShodanConfigForm, self).__init__(*args, **kwargs)
