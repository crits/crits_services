from django import forms

class BackscatterConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    api_key = forms.CharField(required=True,
                              label="API Key",
                              widget=forms.TextInput(),
                              help_text="Obtain API key from Backscatter.io",
                              initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(BackscatterConfigForm, self).__init__(*args, **kwargs)

# Saving for future use if the service needs runtime configuration
#class BackscatterRunForm(forms.Form):
#    error_css_class = 'error'
#    required_css_class = 'required'
#
#    def __init__(self, *args, **kwargs):
#        kwargs.setdefault('label_suffix', ':')
#        super(BackscatterRunForm, self).__init__(*args, **kwargs)
