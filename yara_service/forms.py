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
                                         widget=forms.SelectMultiple(),
                                         help_text="Newline separated list of signature files.")

    def __init__(self, *args, **kwargs):
        super(YaraRunForm, self).__init__(*args, **kwargs)
