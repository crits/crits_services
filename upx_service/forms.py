from django import forms

class UPXConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    upx_path = forms.CharField(required=True,
                               label="UPX Binary",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="Full path to UPX binary.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(UPXConfigForm, self).__init__(*args, **kwargs)
