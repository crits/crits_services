from django import forms

class VirusTotalConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    vt_api_key = forms.CharField(required=True,
                                 label="API Key",
                                 widget=forms.TextInput(),
                                 help_text="Obtain API key from VirusTotal.",
                                 initial='')
    vt_query_url = forms.CharField(required=True,
                                   label="File URL",
                                   widget=forms.TextInput(),
                                   initial='https://www.virustotal.com/vtapi/v2/file/report')
    vt_domain_url = forms.CharField(required=True,
                                    label="Domain URL",
                                    widget=forms.TextInput(),
                                    initial='https://www.virustotal.com/vtapi/v2/domain/report')
    vt_ip_url = forms.CharField(required=True,
                                label="IP URL",
                                widget=forms.TextInput(),
                                initial='https://www.virustotal.com/vtapi/v2/ip-address/report')

    def __init__(self, *args, **kwargs):
        super(VirusTotalConfigForm, self).__init__(*args, **kwargs)
