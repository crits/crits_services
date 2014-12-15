from django.conf import settings

from crits.core.class_mapper import class_from_type
from crits.core.user_tools import user_sources
from crits.services.analysis_result import AnalysisResult

from . import forms

def get_diffie_config(analyst, type_, id_, data=None):
    """
    Return DiffieConfigForm for diffie service.

    Must make sure user has source access to requested type and id.

    :param analyst: The username.
    :type analyst: str
    :param type_: CRITs type.
    :type type_: str
    :param id_: CRITs ID.
    :type id_: str
    :param data: Dictionary with submitted data.
    :type data: dict
    :returns: DiffieConfigForm
    """

    results = {'success': False}

    sources = user_sources(analyst)
    klass = class_from_type(type_)
    obj = klass.objects(source__name__in=sources, id=id_).first()
    if not obj:
        results['message'] = "Either no data exists for this object or you do not have permission to view it."
        return results
    results['success'] = True
    results['form'] = forms.DiffieConfigForm(type_=type_, id_=id_, data=data)
    return results

def get_diffie_results(first, second):
    """
    Retrieve requested analysis results.

    :param first: analysis_id of first result.
    :type first: str
    :param second: analysis_id of second result.
    :type second: str
    :returns: Dictionary with first and second keys.
    """

    results = {'success': False}

    first_result = AnalysisResult.objects(analysis_id=first).first()
    if not first_result:
        results['message'] = "Unable to find first result."
        return results

    second_result = AnalysisResult.objects(analysis_id=second).first()
    if not second_result:
        results['message'] = "Unable to find second result."
        return results

    results['success'] = True
    results['first'] = first_result
    results['second'] = second_result
    return results
