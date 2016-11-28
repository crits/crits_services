from django import forms

class WHOISConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pydat_url = forms.CharField(required=False,
                                label="pyDat URL",
                                widget=forms.TextInput(),
                                help_text="Base URL for pyDat.",
                                initial='')
    dt_api_key = forms.CharField(required=False,
                                 label="DT API Key",
                                 widget=forms.TextInput(),
                                 help_text="DomainTools API key.",
                                 initial='')
    dt_username = forms.CharField(required=False,
                                  label="DT Username",
                                  widget=forms.TextInput(),
                                  help_text="DomainTools username.",
                                  initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(WHOISConfigForm, self).__init__(*args, **kwargs)

class WHOISRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    live_query = forms.BooleanField(required=False,
                                    label="Live",
                                    help_text="Perform a live query.")

    def __init__(self, pydat_url=None, dt_api_key=None, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(WHOISRunForm, self).__init__(*args, **kwargs)

        # If pyDat or DomainTools are configured, add a checkbox and
        # prefer them. Otherwise, prefer the live query.
        if pydat_url:
            self.fields['pydat_query'] = forms.BooleanField(required=False,
                                                            initial=True,
                                                            label="pyDat",
                                                            help_text="Perform a pyDat query.")
        if dt_api_key:
            self.fields['dt_query'] = forms.BooleanField(required=False,
                                                         initial=True,
                                                         label='DT',
                                                         help_text="Perform a DomainTools query.")

        if not pydat_url and not dt_api_key:
            self.fields['live_query'].initial = True
            self.data['live_query'] = True
