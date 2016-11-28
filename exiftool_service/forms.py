from django import forms

class ExiftoolConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    exiftool_path = forms.CharField(required=True,
                               label="exiftool Binary",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="Full path to exiftool binary.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ExiftoolConfigForm, self).__init__(*args, **kwargs)
