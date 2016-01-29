from django import forms

class CHMInfoRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    chm_items = forms.BooleanField(required=False,
                                  label="Items",
                                  help_text="New samples from CHM Items (insert child pages).",
                                  initial=True)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(CHMInfoRunForm, self).__init__(*args, **kwargs)
