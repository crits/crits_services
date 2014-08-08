from django import forms

class OPSWATConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    url = forms.CharField(required=True,
                          label="OPSWAT URL",
                          widget=forms.TextInput(),
                          initial='',
                          help_text="URL for the OPSWAT REST API, example: "
                                    "http://example.org:8008/metascan_rest/scanner?method=scan&archive_pwd=infected")

    def __init__(self, *args, **kwargs):
        super(OPSWATConfigForm, self).__init__(*args, **kwargs)
