from django import forms

class MMBotConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'

    model = forms.CharField(required=True,
                            label="Model Path",
                            initial='',
                            widget=forms.TextInput(),
                            help_text="Path where the model pickle and vocab is stored")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(MMBotConfigForm, self).__init__(*args, **kwargs)

