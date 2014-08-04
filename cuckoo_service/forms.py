from django import forms

class CuckooConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    host = forms.CharField(required=True,
                           label="Host",
                           initial='',
                           widget=forms.TextInput(),
                           help_text="Hostname or IP of the API server.")
    port = forms.IntegerField(required=True,
                              label="Cuckoo API server port.",
                              initial=8090)
    proxy_host = forms.CharField(required=False,
                                 label="Proxy host",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Proxy host, if needed.")
    proxy_port = forms.IntegerField(required=False,
                                    label="Proxy port.",
                                    initial=0)
    webui_host = forms.CharField(required=False,
                                 label="WebUI host",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Hostname of Cuckoo web interface.")
    webui_port = forms.IntegerField(required=False,
                                    label="WebUI port.",
                                    initial=0)

    def __init__(self, *args, **kwargs):
        super(CuckooConfigForm, self).__init__(*args, **kwargs)

class CuckooRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    timeout = forms.IntegerField(required=False,
                                 label="Timeout",
                                 help_text="Maximum time (in seconds) to "
                                           "allow the analysis to run. Leave "
                                           "as 0 to use the timeout specified "
                                           " in the Cuckoo configuration.",
                                 initial=0)
    machine = forms.CharField(required=False,
                              label="Machine",
                              initial='',
                              widget=forms.TextInput(),
                              help_text="Name of the machine to use for the "
                                        "analysis. Leave blank to use the "
                                        "first available machine. 'all' for "
                                        " ALL machines.")
    package = forms.ChoiceField(required=True,
                                label="Package",
                                choices=[("auto", "auto"),
                                         ("exe", "exe"),
                                         ("dll", "dll"),
                                         ("pdf", "pdf"),
                                         ("doc", "doc")],
                                help_text="Analysis package to run.")
    existing_task_id = forms.IntegerField(required=False,
                                 label="Existing task ID",
                                 help_text="DEVELOPMENT ONLY: Fetch results "
                                 "from an existing analysis task rather than "
                                 "running the sample in the sandbox. Use '0' "
                                 "to run a new analysis.",
                                 initial=0)
    ignored_files = forms.ChoiceField(required=False,
                                      label="Ignored files",
                                      choices=[("", ""),
                                               ("SharedDataEvents*", "SharedDataEvents*")],
                                      help_text="File paths that are not "
                                                "automatically resubmitted.")

    def __init__(self, *args, **kwargs):
        super(CuckooRunForm, self).__init__(*args, **kwargs)
