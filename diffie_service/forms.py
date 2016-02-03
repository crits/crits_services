from django import forms
from crits.services.core import AnalysisTask
from crits.services.analysis_result import AnalysisResult

class DiffieConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    first = forms.ChoiceField(required=True,
                              widget=forms.Select,
                              label="First",
                              help_text="Left side analysis result.")

    second = forms.ChoiceField(required=True,
                               widget=forms.Select,
                               label="Second",
                               help_text="Right side analyis result.")

    type_ = forms.CharField(widget=forms.HiddenInput())
    id_ = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, type_, id_, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(DiffieConfigForm, self).__init__(*args, **kwargs)
        # Take each analysis result passed in as a kwarg and turn it into
        # a tuple for the form: ('id', 'service_name: start_date'). Only
        # take the ones with a status that is 'completed'.
        analysisresults = AnalysisResult.objects(object_type=type_,
                                                 object_id=id_)
        choices = []
        for ar in analysisresults:
            if ar.status == AnalysisTask.STATUS_COMPLETED:
                choices.append((ar.analysis_id, '%s: %s' % (ar.service_name,
                                                            ar.start_date)))
            
        self.fields['first'].choices = choices
        self.fields['second'].choices = choices

        self.fields['type_'].initial = type_
        self.fields['id_'].initial = id_
