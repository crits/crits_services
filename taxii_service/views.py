import json
import tempfile

from django.template import RequestContext
from django.template.loader import render_to_string
from django.shortcuts import render_to_response, HttpResponse
from django.core.servers.basehttp import FileWrapper
from django.contrib.auth.decorators import user_passes_test

from crits.core.class_mapper import class_from_id, class_from_value
from crits.core.user_tools import user_can_view_data

from . import handlers
from . import forms

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
            return HttpResponse(json.dumps(ret), mimetype="application/json")

        tform = forms.TAXIIForm(request.user.username, obj)
        taxii_form = {'form' : render_to_string("_taxii_form_template.html", {'form' : tform})}
        return HttpResponse(json.dumps(taxii_form), mimetype="application/json")
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
        return HttpResponse(json.dumps(ret), mimetype="application/json")

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
            return HttpResponse(json.dumps(data), mimetype="application/json")
    else: # form doesn't validate
        data = {'success': False, 'reason': "Invalid options provided. Please fix and try again."}
        return HttpResponse(json.dumps(data), mimetype="application/json")
    

