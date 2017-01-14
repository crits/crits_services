from django import forms


class Bit9ConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
<<<<<<< 3f179aafac25719c29b6d751275f24c25b8fa8c0
    bit9_api_key = forms.CharField(required=True, 
                                label="API Key:", 
                                widget=forms.TextInput(), 
                                help_text="API key from Bit9.",
                                initial='')
                                
    bit9_server = forms.CharField(required=True, 
                                label="Bit9 Server URL:", 
                                widget=forms.TextInput(), 
                                help_text="Bit9 server hostname/IP URL: (https://bit9.myorganization.com).",
                                initial='')
=======
    bit9_api_key = forms.CharField(required=True, label="API Key:", widget=forms.TextInput(), help_text="API key from Bit9.",initial='')
    bit9_server = forms.CharField(required=True, label="Bit9 Server URL:", widget=forms.TextInput(), help_text="Bit9 server hostname/IP URL: (https://bit9.myorganization.com).",initial='')
>>>>>>> commit

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(Bit9ConfigForm, self).__init__(*args, **kwargs)
