from django import forms


class RATDecoderConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    decodersdir = forms.CharField(required=True,
                             label="Decoder directory",
                             initial='/data/crits_services/ratdecoder_service/decoders/',
                             widget=forms.TextInput(),
                             help_text="Directory where decoder files are.")
    yaradir = forms.CharField(required=True,
                             label="Decoder Yara directory",
                             initial='/data/crits_services/ratdecoder_service/yaraRules/',
                             widget=forms.TextInput(),
                             help_text="Directory where decoder files are.")
                             
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(RATDecoderConfigForm, self).__init__(*args, **kwargs)

class RATDecoderRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(RATDecoderRunForm, self).__init__(*args, **kwargs)
