import os
from django import forms

class ExtractEmbeddedConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    clamscan_path = forms.CharField(required=True,
                               label="clamscan binary",
                               initial=os.path.dirname(os.path.realpath(__file__))+'/static_analysis/clamav-devel/clamscan/clamscan',
                               widget=forms.TextInput(),
                               help_text="Full path to clamscan binary.")
    analysis_path = forms.CharField(required=True,
                               label="Analysis static tool",
                               initial=os.path.dirname(os.path.realpath(__file__))+'/static_analysis/analysis.py',
                               widget=forms.TextInput(),
                               help_text="Full path to analysis static tool. (https://github.com/lprat/static_analysis)")
    yararules_path = forms.CharField(required=True,
                               label="Yara rules",
                               initial=os.path.dirname(os.path.realpath(__file__))+'/static_analysis/yara_rules/',
                               widget=forms.TextInput(),
                               help_text="Yara rules path for analysis static tool.")
    pattern_path = forms.CharField(required=True,
                               label="Pattern DB",
                               initial=os.path.dirname(os.path.realpath(__file__))+'/static_analysis/pattern.db',
                               widget=forms.TextInput(),
                               help_text="Pattern DB path for extract data")
    tlp_value = forms.CharField(required=True,
                               label="Tlp value",
                               initial='red',
                               widget=forms.TextInput(),
                               help_text="Indicate TLP value.")                            
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ExtractEmbeddedConfigForm, self).__init__(*args, **kwargs)

class ExtractEmbeddedRunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    debug_log = forms.BooleanField(required=False,
                                    initial=False,
                                    label="Debug",
                                    help_text="Insert debug info in log.")
    import_file = forms.BooleanField(required=False,
                                    initial=True,
                                    label="Import",
                                    help_text="Import extracted file in CRITS as sample.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(ExtractEmbeddedRunForm, self).__init__(*args, **kwargs)
