from django import forms

class TotalHashConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    th_api_key = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain from TotalHash.",
                                 initial='')
    th_user = forms.CharField(required=True,
                              label="Username",
                              widget=forms.TextInput(),
                              initial='')
    th_query_url = forms.CharField(required=True,
                                   label="Query URL",
                                   widget=forms.TextInput(),
                                   initial='https://api.totalhash.com/')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(TotalHashConfigForm, self).__init__(*args, **kwargs)
