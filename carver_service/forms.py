from django import forms

class CarverRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    start = forms.IntegerField(required=True,
                               label="Start offset",
                               initial=0)
    end = forms.IntegerField(required=True,
                             label="End offset",
                             initial=0)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(CarverRunForm, self).__init__(*args, **kwargs)
