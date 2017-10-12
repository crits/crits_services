from django import forms
import os

class UrlAnalysisConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    tlp_value = forms.CharField(required=True,
                               label="Tlp value",
                               initial='red',
                               widget=forms.TextInput(),
                               help_text="Select TLP value.")
                               
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(UrlAnalysisConfigForm, self).__init__(*args, **kwargs)

