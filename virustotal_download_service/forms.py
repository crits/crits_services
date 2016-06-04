from django import forms

class VirusTotalDLConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    vt_api_key = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from VirusTotal.",
                                 initial='')
    vt_download_url = forms.CharField(required=True,
                                      label="Download URL",
                                      widget=forms.TextInput(),
                                      initial='https://www.virustotal.com/intelligence/download')
    size_limit = forms.IntegerField(required=True,
                                    label="Size Limit (Bytes)",
                                    widget=forms.NumberInput(),
                                    help_text="Maximum size of downloaded binary, in bytes.",
                                    initial='50000000')
    run_triage = forms.BooleanField(required=False,
                                    initial=True,
                                    label='Re-Run Triage?',
                                    help_text="Re-run Triage after Sample is downloaded.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(VirusTotalDLConfigForm, self).__init__(*args, **kwargs)

class VirusTotalDLRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    size_limit = forms.IntegerField(required=True,
                                    label="Size Limit",
                                    widget=forms.NumberInput(),
                                    help_text="Maximum size of downloaded binary, in bytes.",
                                    initial='50000000')
    replace_sample = forms.BooleanField(required=False,
                                        initial=False,
                                        label='Replace Sample?',
                                        help_text="Replace sample in CRITs, if exists, with sample from VirusTotal.")
    run_triage = forms.BooleanField(required=False,
                                    initial=False,
                                    label='Run Triage after Download?',
                                    help_text="Run Triage on this Sample after download from VT.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(VirusTotalDLRunForm, self).__init__(*args, **kwargs)
