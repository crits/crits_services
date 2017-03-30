from django import forms

class ThreatExchangeConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    app_id = forms.CharField(required=True,
                             label="App ID",
                             initial='',
                             widget=forms.TextInput(),
                             help_text="Facebook ThreatExchange App ID.")
    app_secret = forms.CharField(required=True,
                             label="App Secret",
                             initial='',
                             widget=forms.PasswordInput(),
                             help_text="Facebook ThreatExchange App Secret.")
    headers = forms.CharField(required=False,
                              label="Headers",
                              initial='',
                              widget=forms.TextInput(),
                              help_text="Custom headers for requests.")
    verify = forms.BooleanField(required=False,
                                label="Verify",
                                initial=False,
                                help_text="Verify requests.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatExchangeConfigForm, self).__init__(*args, **kwargs)

class ThreatExchangePrivacyGroupForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    name = forms.CharField(required=True,
                           label="Name",
                           initial='',
                           widget=forms.TextInput(),
                           help_text="Privacy Group Name.")
    description = forms.CharField(required=True,
                             label="Description",
                             initial='',
                              widget=forms.Textarea(
                                    attrs={'cols': '40', 'rows': '3'}),
                             help_text="Privacy Group Description.")
    members = forms.CharField(required=True,
                              label="Members",
                              initial='',
                              widget=forms.Textarea(
                                    attrs={'cols': '40', 'rows': '3'}),
                              help_text="Comma-separated list of member IDs.")
    members_can_see = forms.BooleanField(required=False,
                                label="Members Can See",
                                initial=False,
                                help_text="Members can see this group.")
    members_can_use = forms.BooleanField(required=False,
                                label="Members Can Use",
                                initial=False,
                                help_text="Members can use this group.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ThreatExchangePrivacyGroupForm, self).__init__(*args, **kwargs)
