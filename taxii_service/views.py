import logging
import json

from django.template import RequestContext
from django.template.loader import render_to_string
from django.shortcuts import render_to_response, HttpResponse
from django.contrib.auth.decorators import user_passes_test

from crits.core.class_mapper import class_from_id
from crits.core.user_tools import user_can_view_data

from . import handlers
from . import forms

logger = logging.getLogger(__name__)

@user_passes_test(user_can_view_data)
def taxii_agent(request):

    # Use service configuration from DB.
    result = handlers.execute_taxii_agent(analyst=request.user.username, method="TAXII Agent Web")

    return render_to_response('taxii_agent_results.html', {'result': result}, RequestContext(request))

@user_passes_test(user_can_view_data)
def get_taxii_config_form(request, crits_type, crits_id):
    if request.method == "GET":
        obj = class_from_id(crits_type, crits_id)
        if not obj:
            ret = {'success': False, 'reason': "Could not locate object in the database."}
            return HttpResponse(json.dumps(ret), content_type="application/json")

        tform = forms.TAXIIForm(request.user.username, obj)
        taxii_form = {'form' : render_to_string("_taxii_form_template.html", {'form' : tform})}
        return HttpResponse(json.dumps(taxii_form), content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def preview_taxii_service(request, crits_type, crits_id):
    """
    Download a copy of the STIX document that will be generated
    based on current TAXII Form UI selections.

    :param request The request object
    :param crits_type The type of the crits object that will be converted
    :param crits_id The ID of the crits object that will be converted
    """
    if request.method == "GET":
        return get_taxii_result(request, crits_type, crits_id, True)
    else:
        return render_to_response('error.html',
                                  {'error': "Must be GET request."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def execute_taxii_service(request, crits_type, crits_id):
    """
    Convert the given CRITs object to standards via STIX & CybOX,
    then attempt to send as a TAXII message to the configured TAXII server.

    :param request The request object
    :param crits_type The type of the crits object that will be converted
    :param crits_id The ID of the crits object that will be converted
    """
    if request.method == "POST" and request.is_ajax():
        return get_taxii_result(request, crits_type, crits_id, False)
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

def get_taxii_result(request, crits_type, crits_id, preview):
    """
    Create the STIX document representing the given CRITs object.
    If preview, download the STIX file for user to peruse, else
    wrap in a TAXII message and send to TAXII server.

    :param request The request object
    :param crits_type The type of the crits object that will be converted
    :param crits_id The ID of the crits object that will be converted
    :param preview Boolean flag indicating if this is a preview generation or message send req
    """
    obj = class_from_id(crits_type, crits_id)
    if not obj:
        ret = {'success': False, 'reason': "Could not locate object in the database."}
        return HttpResponse(json.dumps(ret), content_type="application/json")

    # did user accept responsibility for potential releasability updates?
    confirm_rel = True if "updates_confirmed" in request.POST else False

    form = forms.TAXIIForm(request.user.username, obj, request.GET if preview else request.POST)
    if form.is_valid(): # is_valid seems to ensure that multiselect data was all in original form
        rcpts = form.cleaned_data.get('rcpts', [])
        relation_choices = form.get_chosen_relations()

        data = handlers.run_taxii_service(request.user.username, obj, rcpts, preview, relation_choices, confirm_rel)
        if preview and data and 'preview' in data: # if doing preview and data available, download as file
            resp = HttpResponse(data['preview'], content_type="application/xml")
            resp['Content-Disposition'] = 'attachment; filename="STIX_preview.xml"'
            return resp
        else: # else show success/error message that has been generated
            return HttpResponse(json.dumps(data), content_type="application/json")
    else: # form doesn't validate
        data = {'success': False, 'reason': "Invalid options provided. Please fix and try again."}
        return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def upload_standards(request):
    """
    Upload a standards document.

    :param request: Django request.
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """

    std_form = forms.UploadStandardsForm(request.user, request.POST, request.FILES)
    response = {
                   'form': std_form.as_table(),
                   'success': False,
                   'message': ""
                 }

    if request.method != "POST":
        response['message'] = "Must submit via POST."
        return render_to_response('file_upload_response.html',
                                  {'response': json.dumps(response)},
                                  RequestContext(request))

    if not std_form.is_valid():
        response['message'] = "Form is invalid."
        return render_to_response('file_upload_response.html',
                                  {'response': json.dumps(response)},
                                  RequestContext(request))

    data = ''
    for chunk in request.FILES['filedata']:
        data += chunk

    make_event = std_form.cleaned_data['make_event']
    source = std_form.cleaned_data['source']

    reference = std_form.cleaned_data['reference']


    # XXX: Add reference to form and handle here?
    status = handlers.import_standards_doc(data, request.user.username, "Upload",
                                 ref=reference, make_event=make_event, source=source)

    if not status['success']:
        response['message'] = status['reason']
        return render_to_response('file_upload_response.html',
                                  {'response': json.dumps(response)},
                                  RequestContext(request))

    response['success'] = True
    response['message'] = render_to_string("import_results.html", {'failed' : status['failed'], 'imported' : status['imported']})
    return render_to_response('file_upload_response.html',
                              {'response': json.dumps(response)},
                              RequestContext(request))

def taxii_service_context(request):
    context = {}
    if request.user.is_authenticated():
        user = request.user.username
        try:
            context['upload_standards'] = forms.UploadStandardsForm(user)
        except Exception, e:
            logger.warning("Base Context UploadStandardsForm Error: %s" % e)
    return context
