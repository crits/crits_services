from django import forms

class EntropyCalcRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    start = forms.IntegerField(required=True,
                               label="Start offset",
                               initial=0)
    end = forms.IntegerField(required=True,
                             label="End offset",
                             initial=-1)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(EntropyCalcRunForm, self).__init__(*args, **kwargs)
