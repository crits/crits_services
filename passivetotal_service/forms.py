from django import forms


class PassiveTotalConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pt_username = forms.CharField(
        required=True,
        label="Username",
        widget=forms.TextInput(),
        help_text="Email address used to login to PassiveTotal.",
        initial=''
    )
    pt_api_key = forms.CharField(
        required=True,
        label="API Key",
        widget=forms.TextInput(),
        help_text="Obtain API key from PassiveTotal.",
        initial=''
    )
    prompt_user = forms.BooleanField(
        required=False,
        initial=False,
        label="Prompt before running service",
        help_text="This service will run several different queries. Prompting before the service run allows you to select which services you want to use. By default, all of them are selected, but you can deselect them."
    )

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PassiveTotalConfigForm, self).__init__(*args, **kwargs)


class PassiveTotalRuntimeForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    dns = forms.BooleanField(
        required=False,
        initial=True,
        label="Passive DNS",
        help_text="Run a passive DNS query."
    )
    whois = forms.BooleanField(
        required=False,
        initial=True,
        label="WHOIS",
        help_text="Run a WHOIS query."
    )
    whois_email_search = forms.BooleanField(
        required=False,
        initial=True,
        label="Email Search",
        help_text="WHOIS email search."
    )
    ssl = forms.BooleanField(
        required=False,
        initial=True,
        label="SSL Certificates",
        help_text="Run a SSL certificate query."
    )
    ssl_history = forms.BooleanField(
        required=False,
        initial=True,
        label="Passive SSL",
        help_text="Run an SSL history query."
    )
    subdomain = forms.BooleanField(
        required=False,
        initial=True,
        label="Subdomains",
        help_text="Run a subdomain query."
    )
    enrichment = forms.BooleanField(
        required=False,
        initial=True,
        label="Enrichment",
        help_text="Run an enrichment query."
    )
    tracker = forms.BooleanField(
        required=False,
        initial=True,
        label="Trackers",
        help_text="Run a tracker query."
    )
    component = forms.BooleanField(
        required=False,
        initial=True,
        label="Components",
        help_text="Run a component query."
    )
    osint = forms.BooleanField(
        required=False,
        initial=True,
        label="OSINT",
        help_text="Run an OSINT query."
    )
    malware = forms.BooleanField(
        required=False,
        initial=True,
        label="Malware",
        help_text="Run a malware query."
    )

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PassiveTotalRuntimeForm, self).__init__(*args, **kwargs)