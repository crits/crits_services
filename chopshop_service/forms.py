from django import forms

class FileCarverForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    types = forms.CharField(required=False,
                            label="HTTP Content types",
                            widget=forms.TextInput(),
                            help_text="Types to carve (blank for all).")
    http_req = forms.BooleanField(required=False,
                                  label="HTTP request",
                                  help_text="Carve HTTP requests.")
    http_resp = forms.BooleanField(required=False,
                                   label="HTTP response",
                                   initial=True,
                                   help_text="Carve HTTP responses.")
    smtp = forms.BooleanField(required=False,
                              label="SMTP",
                              help_text="Carve SMTP.")
    raw = forms.BooleanField(required=False,
                              label="Raw",
                              help_text="Carve raw TCP (one per side).")

    def __init__(self, *args, **kwargs):
        super(FileCarverForm, self).__init__(*args, **kwargs)
