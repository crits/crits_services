from django import forms

class pyewConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    pyew = forms.CharField(required=True,
                           initial='',
                           label = "Full path to pyew py file.")
    port = forms.CharField(required=True,
                           initial='9876',
                           label="Port the pyew websocket is listening on.")
    secure = forms.BooleanField(required=False,
                                initial=True,
                                label="Use secure websockets.")

    def __init__(self, *args, **kwargs):
        super(pyewConfigForm, self).__init__(*args, **kwargs)
