from django import forms

class CodetectiveServiceConfigForm(forms.Form):
    DEFAULT_MODULES = ["win", "web", "crypto", "personal", "unix", "db", "other"]
    error_css_class = 'error'
    required_css_class = 'required'
    filters = forms.CharField(required=False,
                                 label="Filters",
                                 widget=forms.TextInput(),
                                 help_text="Filter by source of your string",
                                 initial=DEFAULT_MODULES)
    
    def __init__(self, *args, **kwargs):
        super(CodetectiveServiceConfigForm, self).__init__(*args, **kwargs)

class CodetectiveServiceRunForm(forms.Form):
    DEFAULT_MODULES = ["win", "web", "crypto", "personal", "unix", "db", "other"]
    error_css_class = 'error'
    required_css_class = 'required'
    start_offset = forms.IntegerField(required=False,
                                 label="certainty",
                                 help_text="Certainty: (0-100).",
                                 initial=45)
    start_offset = forms.IntegerField(required=False,
                                 label="Start offset",
                                 help_text="Start offset of your search.",
                                 initial=0)
    end_offset = forms.IntegerField(required=False,
                                 label="End offset",
                                 help_text="End offset of your search.",
                                 initial=-1)
    analyze = forms.BooleanField(required=False,
                                 label="Analyze",
                                 help_text="show more details whenever possible - expands shadow files fields",
                                 initial=True)
    
    def __init__(self, *args, **kwargs):
        super(CodetectiveServiceRunForm, self).__init__(*args, **kwargs)

