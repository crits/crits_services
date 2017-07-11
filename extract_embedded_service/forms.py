from django import forms

class ExtractEmbeddedConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    clamscan_path = forms.CharField(required=True,
                               label="clamscan binary",
                               initial='/usr/bin/clamscan',
                               widget=forms.TextInput(),
                               help_text="Full path to clamscan binary.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ExtractEmbeddedConfigForm, self).__init__(*args, **kwargs)
