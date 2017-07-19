from django import forms

class JoeSandboxConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    api_url = forms.URLField(label="Joe Sandbox Api Url",
                             initial="https://jbxcloud.joesecurity.org/api/")

    api_key = forms.CharField(label="Joe Sandbox Api Key",
                              initial="")

    tandc = forms.BooleanField(required=False,
                               label="Accept T&C (Joe Sandbox Cloud only)",
                               initial=False,
                               help_text="https://jbxcloud.joesecurity.org/download/termsandconditions.pdf")

    timeout = forms.IntegerField(label="Analysis Timeout (minutes)",
                                 initial=60,
                                 help_text="Combined maximum time to wait for the queue and analyses.")

    ignore_ssl_cert = forms.BooleanField(required=False,
                                         label="Do not verify SSL certificate of the api host",
                                         initial=False)

    systems = forms.CharField(required=False,
                              label="Analysis Systems (comma separated)",
                              initial="",
                              help_text="Leave empty for automatic Windows selection.")

    use_cache = forms.BooleanField(required=False,
                                   label="Check Cache",
                                   initial=True,
                                   help_text="Return reports from cache if available.")

    inet = forms.BooleanField(required=False,
                              label="Internet Access",
                              help_text="Windows only",
                              initial=True)

    ssl = forms.BooleanField(required=False,
                              label="HTTPS",
                              help_text="Windows only: Inspect encrypted HTTPS traffic.",
                              initial=False)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(JoeSandboxConfigForm, self).__init__(*args, **kwargs)

class JoeSandboxRuntimeForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    systems = JoeSandboxConfigForm.base_fields["systems"]
    use_cache = JoeSandboxConfigForm.base_fields["use_cache"]
    inet = JoeSandboxConfigForm.base_fields["inet"]
    ssl = JoeSandboxConfigForm.base_fields["ssl"]

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(JoeSandboxRuntimeForm, self).__init__(*args, **kwargs)
