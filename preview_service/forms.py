from django import forms

class previewConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pdftoppm_path = forms.CharField(required=True,
                               label="pdftoppm binary",
                               initial='/usr/bin/pdftoppm',
                               widget=forms.TextInput(),
                               help_text="Full path to pdftoppm binary.")

    antiword_path = forms.CharField(required=True,
                               label="antiword binary",
                               initial='/usr/bin/antiword',
                               widget=forms.TextInput(),
                               help_text="Full path to antiword binary.")
                               
    tlp_value = forms.ChoiceField(required=True,
                               label="Tlp value",
                               initial='red',
                               widget=forms.Select,
                               help_text="Select TLP value.")
                               
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super( previewConfigForm, self).__init__(*args, **kwargs)
        self.fields['Tlp value'].choices = [("red", "TLP red"),
                                            ("amber", "TLP amber"),
                                            ("green", "TLP green"),
                                            ("white", "TLP white")]

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(previewConfigForm, self).__init__(*args, **kwargs)
