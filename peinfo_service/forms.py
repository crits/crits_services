from django import forms

class PEInfoRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    resource = forms.BooleanField(required=False,
                                  label="Resources",
                                  help_text="New samples from resources.",
                                  initial=True)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(PEInfoRunForm, self).__init__(*args, **kwargs)
