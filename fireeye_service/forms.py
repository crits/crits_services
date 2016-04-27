from django import forms

class FireeyeConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    host = forms.CharField(required=True,
                            label="Host",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="Hostname or IP for the Fireye CMS appliance.")
    username = forms.CharField(required=True,
                                label="Username",
                                initial='',
                                widget=forms.TextInput(),
                                help_text="Username")
    password = forms.CharField(required=True,
                                label="Password",
                                initial='',
                                widget=forms.TextInput(),
                                help_text="Password")
    machine = forms.CharField(required=True,
                                label="Machines",
                                initial='',
                                widget=forms.Textarea(attrs={'cols': 40,'rows': 6}),
                                help_text="Newline separated list of machines to use for analysis.")
    proxy_host = forms.CharField(required=False,
                                    label="Proxy host",
                                    initial='',
                                    widget=forms.TextInput(),
                                    help_text="Proxy host, if needed.")
    proxy_port = forms.IntegerField(required=False,
                                    label="Proxy port",
                                    initial=0)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(FireeyeConfigForm, self).__init__(*args, **kwargs)

class FireeyeRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    timeout = forms.IntegerField(required=False,
                                    label="Timeout",
                                    help_text="Maximum time (in seconds) to allow the analysis to run.",
                                    initial=500)
    machine = forms.ChoiceField(required=True,
                                label="Machine",
                                initial=[],
                                help_text="Name of the machine to use for the analysis.")

    def __init__(self, machines=[], *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(FireeyeRunForm, self).__init__(*args, **kwargs)

        self.fields['machine'].choices = machines
        initial = [choice[0] for choice in machines]
        self.fields['machine'].initial = initial
