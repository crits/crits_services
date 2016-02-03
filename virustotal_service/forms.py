from django import forms

class VirusTotalConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    vt_api_key_private = forms.BooleanField(required=False,
                                initial=False,
                                label='Private key?',
                                help_text="Is the key a private key?")
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
    vt_network_url = forms.CharField(required=True,
                                label="Network URL",
                                widget=forms.TextInput(),
                                initial='https://www.virustotal.com/vtapi/v2/file/network-traffic')


    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(VirusTotalConfigForm, self).__init__(*args, **kwargs)

class VirusTotalRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    vt_add_pcap = forms.BooleanField(required=False,
                                     initial=False,
                                     label='PCAP',
                                     help_text="Add PCAP file")
    vt_add_domains = forms.BooleanField(required=False,
                                        initial=False,
                                        label='Domain',
                                        help_text="Add Domains")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(VirusTotalRunForm, self).__init__(*args, **kwargs)
