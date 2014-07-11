from django import forms

class PassiveTotalConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pt_api_key = forms.CharField(required=True,
                                 label="API Key",
                                   widget=forms.TextInput(),
                                 initial='')
    pt_query_url = forms.CharField(required=True,
                                   label="Query URL",
                                   widget=forms.TextInput(),
                                   initial='https://www.passivetotal.org/api/query/')

    def __init__(self, *args, **kwargs):
        super(PassiveTotalConfigForm, self).__init__(*args, **kwargs)
