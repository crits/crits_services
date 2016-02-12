from django import forms

class YaraConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    sigdir = forms.CharField(required=True,
                             label="Signature directory",
                             initial='',
                             widget=forms.TextInput(),
                             help_text="Directory where signature files are.")
    sigfiles = forms.CharField(required=True,
                               label="Signature files",
                               initial=[],
                               widget=forms.Textarea(attrs={'cols': 40,
                                                           'rows': 6}),
                               help_text="Newline separated list of signature files.")

    distribution_url = forms.CharField(required=False,
                                       label="Distribution URL",
                                       initial='',
                                       widget=forms.TextInput(),
                                       help_text="Distribution URL. Leave blank if not distributed.")
    exchange = forms.CharField(required=False,
                               label="Exchange",
                               initial='',
                               widget=forms.TextInput(),
                               help_text="Distribution exchange. Leave blank if not distributed.")
    routing_key = forms.CharField(required=False,
                                  label="Routing key",
                                  initial='',
                                  widget=forms.TextInput(),
                                  help_text="Distribution routing key. Leave blank if not distributed.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(YaraConfigForm, self).__init__(*args, **kwargs)

class YaraRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    sigfiles = forms.MultipleChoiceField(required=True,
                                         label="Signature files",
                                         widget=forms.SelectMultiple,
                                         help_text="Signature files to use.")

    def __init__(self, sigfiles=[], api_keys=[], *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(YaraRunForm, self).__init__(*args, **kwargs)

        self.fields['sigfiles'].choices = sigfiles
        # Default to all signature files.
        initial = [choice[0] for choice in sigfiles]
        self.fields['sigfiles'].initial = initial
        self.fields['sigfiles'].widget.attrs['style'] = 'resize: both; overflow: auto;'

        if api_keys:
            self.fields['api_key'] = forms.ChoiceField(widget=forms.Select,
                                                       required=False,
                                                       label="API key",
                                                       choices=api_keys,
                                                       help_text="API key.")
