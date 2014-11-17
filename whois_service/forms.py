from django import forms

class WHOISConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pydat_url = forms.CharField(required=False,
                                label="pyDat URL",
                                widget=forms.TextInput(),
                                help_text="Base URL for pyDat.",
                                initial='')

    def __init__(self, *args, **kwargs):
        super(WHOISConfigForm, self).__init__(*args, **kwargs)

class WHOISRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    live_query = forms.BooleanField(required=False,
                                    label="Live",
                                    help_text="Perform a live query.")

    def __init__(self, pydat_url=None, *args, **kwargs):
        super(WHOISRunForm, self).__init__(*args, **kwargs)

        # If pyDat is configured, add a checkbox and prefer that.
        # Otherwise, prefer the live query.
        if pydat_url:
            self.fields['pydat_query'] = forms.BooleanField(required=False,
                                                            initial=True,
                                                            label="pyDat",
                                                            help_text="Perform a pyDat query.")
        else:
            self.fields['live_query'].initial = True
