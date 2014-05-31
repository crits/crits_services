from django import forms

from snugglefish import SnuggleIndex

class SnugglefishSearchForm(forms.Form):
    """Form for the snugglefish service's search dialog."""
    error_css_class = 'error'
    required_css_class = 'required'
    indexes = forms.MultipleChoiceField(required=True,
                                        label="Indexes",
                                        help_text="Indexes to search.",
                                        widget=forms.SelectMultiple)
    searchString = forms.CharField(required=True,
                                   label="Search For",
                                   widget=forms.TextInput(),
                                   help_text="Search string.")

    def __init__(self, *args, **kwargs):
        super(SnugglefishSearchForm, self).__init__(*args, **kwargs)
        snuggles = SnuggleIndex.objects()
        self.fields['indexes'].choices = [(sng.name, sng.name)
                                          for sng in snuggles if sng.count]
