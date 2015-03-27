from django import forms

class PDFInfoRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pdf_objects = forms.BooleanField(required=False,
                                  label="Objects",
                                  help_text="New samples from suspicious PDF objects.",
                                  initial=True)

    def __init__(self, *args, **kwargs):
        super(PDFInfoRunForm, self).__init__(*args, **kwargs)
