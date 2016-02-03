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
    use_proxy = forms.BooleanField(required=False,
                                   label="Proxy",
                                   initial=False,
                                   help_text="Use proxy for connecting to OPSWAT service")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(OPSWATConfigForm, self).__init__(*args, **kwargs)
