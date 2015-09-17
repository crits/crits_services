from django import forms

class VirusTotalConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    vt_api_key_private = forms.BooleanField(required=False,
                                initial=False,
                                label='Private key?',
                                help_text="Is the key a private key?")
    vt_add_domains = forms.BooleanField(required=False,
                                initial=False,
                                label='Add Domains?',
                                help_text="Should we always add domains?")
    vt_add_pcap = forms.BooleanField(required=False,
                                initial=False,
                                label='Pull PCAP?',
                                help_text="If available, should we pull the pcap file?")
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
    vt_upload_unknown_sample = forms.BooleanField(required=False,
                                initial=True,
                                label='Upload unknown samples to VT?',
                                help_text="If VT does not know a sample, should we upload it for analysis?")
    vt_wait_for_processing = forms.CharField(required=False,
                                label="Wait for processing",
                                initial='5',
                                widget=forms.TextInput(),
                                help_text="How many minutes should we give VT to process newly uploaded samples?")

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
    vt_upload_unknown_sample = forms.BooleanField(required=False,
                                initial=False,
                                label='Upload unknown samples to VT?',
                                help_text="If VT does not know a sample, should we upload it for analysis?")
    vt_wait_for_processing = forms.CharField(required=False,
                                label="Wait for processing",
                                initial='5',
                                widget=forms.TextInput(),
                                help_text="How many minutes should we give VT to process newly uploaded samples?")

    def __init__(self, *args, **kwargs):
        super(VirusTotalRunForm, self).__init__(*args, **kwargs)
