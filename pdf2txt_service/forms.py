from django import forms

class pdf2txtConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pdf2txt_path = forms.CharField(required=True,
                               label="pdftotext binary",
                               initial='/usr/bin/pdftotext',
                               widget=forms.TextInput(),
                               help_text="Full path to pdftotext binary.")
    antiword_path = forms.CharField(required=True,
                               label="antiword binary",
                               initial='/usr/bin/antiword',
                               widget=forms.TextInput(),
                               help_text="Full path to antiword binary.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(pdf2txtConfigForm, self).__init__(*args, **kwargs)
