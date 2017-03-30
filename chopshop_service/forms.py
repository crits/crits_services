from django import forms

class FileCarverForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    types = forms.CharField(required=False,
                            label="HTTP Content types",
                            widget=forms.TextInput(),
                            help_text="Types to carve (blank for all).")
    http_req = forms.BooleanField(required=False,
                                  label="HTTP request",
                                  help_text="Carve HTTP requests.")
    http_resp = forms.BooleanField(required=False,
                                   label="HTTP response",
                                   initial=True,
                                   help_text="Carve HTTP responses.")
    smtp = forms.BooleanField(required=False,
                              label="SMTP",
                              help_text="Carve SMTP.")
    raw = forms.BooleanField(required=False,
                              label="Raw",
                              help_text="Carve raw TCP (one per side).")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(FileCarverForm, self).__init__(*args, **kwargs)

class ChopShopConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    basedir = forms.CharField(required=True,
                              initial='',
                              label="ChopShop base directory",
                              help_text="The base directory where all the modules and libraries exist.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ChopShopConfigForm, self).__init__(*args, **kwargs)

class ChopShopRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    choices = [('HTTP', 'HTTP'), ('DNS', 'DNS')]
    modules = forms.MultipleChoiceField(required=True,
                                        label='Protocols',
                                        choices=choices,
                                        initial=['HTTP', 'DNS'],
                                        widget=forms.CheckboxSelectMultiple,
                                        help_text="Generate metadata for these protocols.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ChopShopRunForm, self).__init__(*args, **kwargs)
