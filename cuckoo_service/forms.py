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
                              label="Cuckoo API server port",
                              initial=8090)
    secure = forms.BooleanField(required=False,
                                label="Secure?",
                                initial=False,
                                help_text="Use https for the API.")
    proxy_host = forms.CharField(required=False,
                                 label="Proxy host",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Proxy host, if needed.")
    proxy_port = forms.IntegerField(required=False,
                                    label="Proxy port",
                                    initial=0)
    webui_host = forms.CharField(required=False,
                                 label="WebUI host",
                                 initial='',
                                 widget=forms.TextInput(),
                                 help_text="Hostname of Cuckoo web interface.")
    webui_port = forms.IntegerField(required=False,
                                    label="WebUI port",
                                    initial=0)
    machine = forms.CharField(required=True,
                              label="Machine",
                              initial='',
                              widget=forms.Textarea(attrs={'cols': 40,
                                                           'rows': 6}),
                              help_text="Newline separated list of machines to "
                                        "use for the analysis. Use 'all' for "
                                        "ALL machines and 'any' for first "
                                        "available.")
    timeout = forms.IntegerField(required=False,
                                 label="Timeout",
                                 help_text="Maximum time (in seconds) to "
                                           "allow the analysis to run. Leave "
                                           "as 0 to use the timeout specified "
                                           " in the Cuckoo configuration.",
                                 initial=0)
    enforce_timeout = forms.BooleanField(required=False,
                                         label="Enforce Timeout?",
                                         initial=False,
                                         help_text="Always wait the timeout "
                                                   "period.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
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

    enforce_timeout = forms.BooleanField(required=False,
                                         label="Enforce timeout",
                                         initial=False,
                                         help_text="Always wait the timeout "
                                                   "period.")
    machine = forms.ChoiceField(required=True,
                              label="Machine",
                              initial=[],
                              help_text="Name of the machine to use for the "
                                        "analysis.")
    tags = forms.CharField(required=False,
                           label="Machine tags",
                           help_text="Machine tags separated by commas")

    package = forms.ChoiceField(required=True,
                                label="Package",
                                choices=[("auto", "auto"),
                                         ("exe", "exe"),
                                         ("dll", "dll"),
                                         ("pdf", "pdf"),
                                         ("doc", "doc")],
                                help_text="Analysis package to run.")

    tor = forms.BooleanField(required=False,
                             label="Use Tor",
                             initial=False,
                             help_text="Enable Tor while running this sample (cuckoo-modified fork feature)")

    procmemdump = forms.BooleanField(required=False,
                                     label="Analyze process memory",
                                     initial=False,
                                     help_text="Dump and analyze process memory (Processing takes longer)")

    existing_task_id = forms.IntegerField(required=False,
                                 label="Existing task ID",
                                 help_text="DEVELOPMENT ONLY: Fetch results "
                                 "from an existing analysis task rather than "
                                 "running the sample in the sandbox. Use '0' "
                                 "to run a new analysis.",
                                 initial=0)

    options = forms.CharField(required=False,
                              label="Options",
                              help_text="A Cuckoo task options string (e.g. foo=yes,bar=yes)")

    ignored_files = forms.CharField(required=False,
                                    label="Ignored files",
                                    initial='SharedDataEvents*',
                                    widget=forms.Textarea(attrs={'cols': 40,
                                                                 'rows': 6}),
                                    help_text="File paths that are not "
                                              "automatically resubmitted.")

    def __init__(self, machines=[], *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(CuckooRunForm, self).__init__(*args, **kwargs)

        self.fields['machine'].choices = machines
        initial = [choice[0] for choice in machines]
        self.fields['machine'].initial = initial

