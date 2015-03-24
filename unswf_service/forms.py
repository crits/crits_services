from django import forms

class UnswfConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    flare_path = forms.CharField(required=True,
                               label="Flare Binary",
                               initial='/usr/local/bin/flare',
                               widget=forms.TextInput(),
                               help_text="Full path to Flare binary.")

    def __init__(self, *args, **kwargs):
        super(UnswfConfigForm, self).__init__(*args, **kwargs)
