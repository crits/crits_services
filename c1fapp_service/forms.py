from django import forms

class C1fappConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    cif_api_key = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from www.c1fapp.com",
                                 initial='')
    cif_query_url = forms.CharField(required=True,
                                   label="Query URL",
                                   widget=forms.TextInput(),
                                   initial='https://www.c1fapp.com/cifapp/api/')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(C1fappConfigForm, self).__init__(*args, **kwargs)
