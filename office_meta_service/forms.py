from django import forms

class OfficeMetaRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    save_streams = forms.BooleanField(required=False,
                               label="Save streams",
                               help_text="Add embedded streams as new samples.",
                               initial=True)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(OfficeMetaRunForm, self).__init__(*args, **kwargs)
