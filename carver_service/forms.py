from django import forms

class CarverRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    OPERATIONS = (
        ('None', 'No-op' ),
        ('B64D', 'Base64 Decode'),
        ('XORB', 'XOR bytes'),
        ('ROBL', 'Rotate each carved byte'),
        ('SHBL', 'Shift each carved byte'),
        ('ADDL', 'Add/Subtract value to each carved byte'),
        )
    start = forms.IntegerField(required=True,
                               label="Start offset",
                               initial=0)
    end = forms.IntegerField(required=True,
                             label="End offset",
                             initial=-1)
    ops = forms.ChoiceField(choices=OPERATIONS,
                               label="Perform an operation on carved region",
                               initial='None')
    ops_parm = forms.CharField(required=False,
                               label="Hex value 0x00 - 0xff, with optional sign (+/-) in front",
                               initial=0)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(CarverRunForm, self).__init__(*args, **kwargs)
