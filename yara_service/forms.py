from django import forms

class YaraConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    sigfiles = forms.CharField(required=True,
                               label="Signature files",
                               widget=forms.Textarea(attrs={'cols': 40,
                                                           'rows': 6}),
                               help_text="Newline separated list of signature files.")

    distribution_url = forms.CharField(required=False,
                                       label="Distribution URL",
                                       widget=forms.TextInput(),
                                       help_text="Distribution URL. Leave blank if not distributed.")
    exchange = forms.CharField(required=False,
                               label="Routing key",
                               widget=forms.TextInput(),
                               help_text="Distribution exchange. Leave blank if not distributed.")
    routing_key = forms.CharField(required=False,
                                  label="Routing key",
                                  widget=forms.TextInput(),
                                  help_text="Distribution routing key. Leave blank if not distributed.")

    def __init__(self, *args, **kwargs):
        super(YaraConfigForm, self).__init__(*args, **kwargs)

class YaraRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    sigfiles = forms.MultipleChoiceField(required=True,
                                         label="Signature files",
                                         widget=forms.SelectMultiple,
                                         help_text="Signature files to use.")

    def __init__(self, sig_choices, api_keys=None, *args, **kwargs):
        super(YaraRunForm, self).__init__(*args, **kwargs)
        self.fields['sigfiles'].choices = sig_choices
        # Default to all signature files.
        initial = [choice[0] for choice in sig_choices]
        self.fields['sigfiles'].initial = initial

        if api_keys:
            self.fields['api_key'] = forms.ChoiceField(widget=forms.Select,
                                                       required=False,
                                                       label="API key",
                                                       choices=api_keys,
                                                       help_text="API key to use.")
