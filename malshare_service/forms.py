from django import forms

class MalShareConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    malshare_api_key = forms.CharField(required=True,
                                 label="MalShare API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from MalShare.",
                                 initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(MalShareConfigForm, self).__init__(*args, **kwargs)
