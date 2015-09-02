from django import forms

class TCPDumpForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    bpf = forms.CharField(required=False,
                          label="BPF Filter",
                          widget=forms.TextInput(),
                          help_text="Filter content to be used in output.")
    sequence = forms.BooleanField(required=False,
                                  label="Absolute Sequence Numbers",
                                  help_text="Use absolute instead of relative sequence numbers.")
    timestamp = forms.ChoiceField(required=False,
                                  widget=forms.Select,
                                  label="Timestamps",
                                  help_text="Timestamp printing on each dump line.")
    verbose = forms.ChoiceField(required=False,
                                  widget=forms.Select,
                                  label="Verbosity",
                                  help_text="How much verbosity you want on output.")
    data = forms.ChoiceField(required=False,
                             widget=forms.Select,
                             label="Data Printing",
                             help_text="Adjust how you want the data of each packet printed.")
    carve = forms.BooleanField(required=False,
                               label="Save Results",
                               help_text="Save resulting PCAP to the database.")

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(TCPDumpForm, self).__init__(*args, **kwargs)
        self.fields['timestamp'].choices = [("", ""),
                                            ("-t", "(-t) Don't print"),
                                            ("-tt", "(-tt) Print unformatted"),
                                            ("-ttt", "(-ttt) Print delta between current and previous line"),
                                            ("-tttt", "(-tttt) Print in default format proceeded by date"),
                                            ("-ttttt", "(-ttttt) Print delta between current and first line")]
        self.fields['verbose'].choices = [("", ""),
                                          ("-v", "(-v) Verbose"),
                                          ("-vv", "(-vv) More verbose"),
                                          ("-vvv", "(-vvv) Most verbose")]
        self.fields['data'].choices = [("", ""),
                                       ("-A", "(-A) Print ASCII data"),
                                       ("-x", "(-x) Print hex data"),
                                       ("-xx", "(-xx) Print hex data including link level header"),
                                       ("-X", "(-X) Print hex and ascii data"),
                                       ("-XX", "(-XX) Print hex and ascii data including link level header")]

class MetaCapConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    basedir = forms.CharField(required=True,
                              label='ChopShop base directory',
                              widget=forms.TextInput(),
                              help_text="The base directory where all the ChopShop modules and libraries exist.",
                              initial='')
    tcpdump = forms.CharField(required=True,
                              label='tcpdump binary',
                              widget=forms.TextInput(),
                              help_text="Full path to the tcpdump binary.",
                              initial='')
    tshark = forms.CharField(required=True,
                              label='tshark binary',
                              widget=forms.TextInput(),
                              help_text="Full path to the tshark binary.",
                              initial='')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(MetaCapConfigForm, self).__init__(*args, **kwargs)
