import logging
import json

from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.template.loader import render_to_string
from django.shortcuts import render_to_response, HttpResponse
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import user_passes_test

from crits.core.class_mapper import class_from_id
from crits.core.user_tools import user_can_view_data

from . import handlers
from . import forms

logger = logging.getLogger(__name__)

@user_passes_test(user_can_view_data)
def taxii_agent(request):
    analyst = request.user.username
    form = forms.TAXIIPollForm(analyst, request.POST or None)
    if form.is_valid():
        # Use service configuration from DB.
        feeds = [feed.split(' - ') for feed in form.cleaned_data['feeds']]
        result = handlers.poll_taxii_feeds(feeds, analyst,
                                           method="TAXII Agent Web")

        if 'all_fail' in result and result['all_fail']:
            data = {'success': False, 'msg': result['msg']}
        else:
            data = {'success': True}
            data['html'] = render_to_string("taxii_agent_results.html",
                                            {'result' : result})
        return HttpResponse(json.dumps(data), mimetype="application/json")
    return render_to_response('taxii_agent_form.html',
                              {'form': form, 'errors': form.errors},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def get_taxii_config_form(request, crits_type, crits_id):
    if request.method == "GET":
        obj = class_from_id(crits_type, crits_id)
        if not obj:
            ret = {'success': False,
                   'reason': "Could not locate object in the database."}
            return HttpResponse(json.dumps(ret), mimetype="application/json")

        tform = forms.TAXIISendForm(request.user.username, obj)
        taxii_form = {'form' : render_to_string("_taxii_form_template.html",
                                                {'form' : tform})}
        return HttpResponse(json.dumps(taxii_form),
                            mimetype="application/json")
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
    if request.method == "POST":
        return get_taxii_result(request, crits_type, crits_id, True)
    else:
        return render_to_response('error.html',
                                  {'error': "Must be POST request."},
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
    :param preview Boolean indicates if preview generation or message send req
    """
    obj = class_from_id(crits_type, crits_id)
    if not obj:
        ret = {'success': False,
               'reason': "Could not locate object in the database."}
        return HttpResponse(json.dumps(ret), mimetype="application/json")

    # did user accept responsibility for potential releasability updates?
    confirm_rel = True if "updates_confirmed" in request.POST else False

    form = forms.TAXIISendForm(request.user.username, obj, request.POST)
    if form.is_valid(): # ensures multiselect data was all in original form
        rcpts = form.cleaned_data.get('rcpts', [])
        relation_choices = form.get_chosen_relations()

        data = handlers.run_taxii_service(request.user.username, obj, rcpts,
                                          preview, relation_choices, confirm_rel)

        # if doing preview and data available, download as file
        if preview and data and 'preview' in data:
            resp = HttpResponse(data['preview'],
                                content_type="application/xml")
            c_disp = 'attachment; filename="STIX_preview.xml"'
            resp['Content-Disposition'] = c_disp
            return resp
        else: # else show success/error message that has been generated
            return HttpResponse(json.dumps(data), mimetype="application/json")
    else: # form doesn't validate
        data = {'success': False,
                'reason': "Invalid options provided. Please fix and try again."}
        return HttpResponse(json.dumps(data), mimetype="application/json")

@user_passes_test(user_can_view_data)
def configure_taxii(request, server=None):
    analyst = request.user.username
    srvr_form = forms.TAXIIServerConfigForm([(x,'') for x in range(100)],
                                            request.POST or None)
    feed_form = forms.TAXIIFeedConfigForm(request.POST or None)
    if request.method == "POST" and request.is_ajax():
        if ('remove_server' in request.POST or
            'remove_feed' in request.POST or
            'edit_feed' in request.POST):
            results = handlers.update_taxii_server_config(request.POST,
                                                          analyst)
        elif 'namespace' in request.POST:
            results = handlers.update_taxii_service_config(request.POST,
                                                           analyst)
        elif feed_form.is_valid():
            results = handlers.update_taxii_server_config(feed_form.cleaned_data,
                                                          analyst)
        if 'service' in results:
            del results['service']
        return HttpResponse(json.dumps(results), mimetype="application/json")

    if srvr_form.is_valid(): # server form passed django validation
        result = handlers.update_taxii_server_config(srvr_form.cleaned_data,
                                                     analyst)
        if result['success']:
            return HttpResponseRedirect(reverse('crits.services.views.detail',
                                                kwargs={'name':'taxii_service'}))
        srvr_form = handlers.add_feed_config_buttons(srvr_form)
        return render_to_response('taxii_server_config.html',
                                  {'form': srvr_form, 'results': result,
                                   'error': result['error']},
                                  RequestContext(request))
    elif request.method == "POST": # django form validation error occurred
        srvr_form = handlers.add_feed_config_buttons(srvr_form)
        return render_to_response('taxii_server_config.html',
                          {'form': srvr_form},
                          RequestContext(request))

    result = handlers.get_taxii_server_config(server)
    if result['success']:
        return render_to_response('taxii_server_config.html',
                          {'form': result['html'],
                           'form2': feed_form,
                           'errors': result['form'].errors},
                          RequestContext(request))
    else:
        return HttpResponseRedirect(reverse('taxii_service.views.configure_taxii'))

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
    status = handlers.import_standards_doc(data, request.user.username, "STIX Upload",
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
