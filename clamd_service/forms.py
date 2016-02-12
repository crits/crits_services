from django import forms

class clamdServiceConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    clamd_sock_path = forms.CharField(required=False,
                                 label="UNIX socket",
                                 widget=forms.TextInput(),
                                 help_text="Location of the clamd unix socket (if using the socket).",
                                 initial='/var/run/clamav/clamd.ctl')
    clamd_host_name = forms.CharField(required=False,
                                   label="Hostname",
                                   widget=forms.TextInput(),
                                   help_text="hostname or ip address of the clamd daemon.",
                                   initial='127.0.0.1')
    clamd_host_port = forms.IntegerField(required=False,
                                    label="Port",
                                    help_text="TCP port number of clamd daemon.",
                                    initial=3310)
    clamd_force_reload = forms.BooleanField(required=False,
                                label="Reload",
                                help_text="Force clamd to reload signature database.",
                                initial=False)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(clamdServiceConfigForm, self).__init__(*args, **kwargs)
