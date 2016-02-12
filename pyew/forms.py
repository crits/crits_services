from django import forms

class pyewConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pyew = forms.CharField(required=True,
                           initial='',
                           label='Pyew Script',
                           help_text="Full path to pyew py file.")
    port = forms.CharField(required=True,
                           initial='9876',
                           label='Port',
                           help_text="Port the pyew websocket is listening on.")
    secure = forms.BooleanField(required=False,
                                initial=True,
                                label='HTTPs',
                                help_text="Use secure websockets.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(pyewConfigForm, self).__init__(*args, **kwargs)
