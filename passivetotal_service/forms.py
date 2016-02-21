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

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PassiveTotalConfigForm, self).__init__(*args, **kwargs)


class PassiveTotalRuntimeForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PassiveTotalRuntimeForm, self).__init__(*args, **kwargs)

        self.fields['dns'] = forms.BooleanField(
            required=False,
            initial=True,
            label="Passive DNS",
            help_text="Perform a passive DNS query."
        )