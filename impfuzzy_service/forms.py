from django import forms

class impfuzzyRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    threshold = forms.IntegerField(required=True,
                                   label="Threshold",
                                   help_text="Minimum threshold for match.",
                                   initial=50)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(impfuzzyRunForm, self).__init__(*args, **kwargs)
