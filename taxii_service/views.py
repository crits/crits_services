import logging
import json
import re
from datetime import datetime

from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.shortcuts import render, HttpResponse
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import user_passes_test

from crits.core.class_mapper import class_from_id
from crits.core.user_tools import user_can_view_data

from . import handlers
from . import forms

logger = logging.getLogger("crits." + __name__)

@user_passes_test(user_can_view_data)
def taxii_poll(request):
    """
    Poll TAXII Feed(s). Should be a GET or an AJAX POST.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """
    analyst = request.user.username
    form = forms.TAXIIPollForm(analyst, request.POST or None)
    if form.is_valid():
        # Use service configuration from DB.
        feeds = [feed.split(' - ') for feed in form.cleaned_data['feeds']]
        import_all = form.cleaned_data['import_all']
        begin = end = None
        if not form.cleaned_data['use_last']:
            begin = form.cleaned_data['begin']
            end = form.cleaned_data['end']
            if not begin:
                data = {'success': False,
                        'msg': 'Exclusive Begin Timestamp is required'}
                return HttpResponse(json.dumps(data),
                                    content_type="application/json")
        try:
            result = handlers.poll_taxii_feeds(feeds, analyst,
                                               begin, end, import_all)
            data = {'success': True}
            data['html'] = render_to_string("taxii_agent_results.html",
                                            result)
        except Exception as e:
            data = {'success': False, 'msg': str(type(e)) + str(e)}

        return HttpResponse(json.dumps(data), content_type="application/json")

    if request.is_ajax():
        msg = "<b>Form Validation Error</b><br>"
        for fld in form.errors:
            msg += "%s: %s<br>" % (form[fld].label,
                                   form.errors[fld].as_text())
        data = {'success': False, 'msg': msg}
        return HttpResponse(json.dumps(data), content_type="application/json")

    return render(request, 'taxii_agent_form.html', {'form': form, 'errors': form.errors})

@user_passes_test(user_can_view_data)
def stix_upload(request):
    """
    Manually upload a STIX document or ZIP of STIX documents.
    Should be a GET or an AJAX POST.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """
    if request.method == "POST":
        form = forms.UploadStandardsForm(request.user, request.POST, request.FILES)
    else:
        form = forms.UploadStandardsForm(request.user)

    if form.is_valid():
        filedata = request.FILES['filedata']
        analyst = request.user.username
        source = form.cleaned_data['source']
        reference = form.cleaned_data['reference']
        use_hdr_src = form.cleaned_data['use_hdr_src']
        import_all = form.cleaned_data['import_all']

        result = handlers.process_stix_upload(filedata, analyst, source,
                                              reference, use_hdr_src,
                                              import_all)
        if import_all:
            data = {'success': True, 'imported': True}
            data['html'] = render_to_string("taxii_agent_results.html",
                                            {'imported' : result})
        else:
            data = {'success': True}
            data['html'] = render_to_string("taxii_agent_preview.html",
                                            {'poll': result})

        return HttpResponse(json.dumps(data), content_type="application/json")

    if request.is_ajax():
        msg = "<b>Form Validation Error</b><br>"
        for fld in form.errors:
            msg += "%s: %s<br>" % (form[fld].label,
                                   form.errors[fld].as_text())
        data = {'success': False, 'msg': msg}
        return HttpResponse(json.dumps(data), content_type="application/json")

    return render(request, 'stix_upload_form.html', {'form': form, 'errors': form.errors})

@user_passes_test(user_can_view_data)
def list_saved_polls(request):
    """
    Get data for all saved TAXII polls. If is a POST and a TAXII message
    ID is provided, delete all content related to that poll before
    returning the list of polls. Should be an AJAX POST.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """
    if request.POST and request.body:
        polls = handlers.get_saved_polls('delete', request.body)
        data = {}
    else:
        polls = handlers.get_saved_polls('list')
        data = {'html': render_to_string("taxii_saved_polls.html",
                                         {'polls' : polls})}

    data['success'] = polls['success']
    data['msg'] = polls.get('msg')
    return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def download_taxii_content(request, tid):
    """
    Given a particular TAXII poll or block, return an XML file containing
    the date from that TAXII poll or block.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :param tid: ID of the desired TAXII poll (a datetimestamp), or block (oid)
    :param tid: string
    :returns: :class:`django.http.HttpResponse`
    """

    if '.' in tid: # this is a timestamp
        ret = handlers.get_saved_polls('download', tid)
    else: # this is an ObjectId
        ret = handlers.get_saved_block(tid)

    resp = HttpResponse(content_type='text/xml')
    resp['Content-Disposition'] = 'attachment; filename="%s"' % ret['filename']
    resp.write(ret['response'])

    return resp

@user_passes_test(user_can_view_data)
def select_deselect_block(request, block_id, select):
    """
    Given a particular block ID poll, update the "selected" field in the DB
    based on the value of the select parameter. Should be an AJAX GET.

    :param block_id: The ObjectID of the block
    :type block_id: str
    :param select: True or 1 to select, False or 0 to deselect
    :param select: int or bool
    :returns: :class:`django.http.HttpResponse`
    """
    if select in (True, 1, '1'):
        data = handlers.select_blocks([block_id])
    else:
        data = handlers.select_blocks([], [block_id])
    data = {'success': True}
    return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def select_deselect_all(request, poll_id, select):
    """
    Given a particular poll ID, update the "selected" field of the associated
    blocks in the DB based on the value of the select parameter.
    Should be an AJAX GET.

    :param poll_id: The Poll ID of blocks to be modified
    :type poll_id: str
    :param select: True or 1 to select, False or 0 to deselect
    :param select: int or bool
    :returns: :class:`django.http.HttpResponse`
    """
    if select in (True, 1, '1'):
        data = handlers.select_blocks(poll_id, [])
    else:
        data = handlers.select_blocks([], poll_id)
    data = {'success': True}
    return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def get_import_preview(request, poll_id, page=1, mult=10):
    """
    Given a particular TAXII poll, get a preview of the content that is
    available for import from that poll's data. Should be an AJAX GET.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :param poll_id: The ID of the desired TAXII poll
    :param poll_id: string
    :param page: The desired page number
    :type page: int
    :param mult: The desired number of blocks/page
    :type mult: int
    :returns: :class:`django.http.HttpResponse`
    """
    user = request.user.username
    if request.body:
        post = json.loads(request.body)
        handlers.select_blocks(post.get('checked', []),
                               post.get('unchecked', []))
    content = handlers.generate_import_preview(poll_id, user, page, mult)
    data = {'success': True}
    data['html'] = render_to_string("taxii_agent_preview.html",
                                    {'poll': content})
    return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def import_taxii_data(request):
    """
    Given a list of Mongo objectIDs, parse and import the associated
    content blocks. User can select whether to delete or keep
    unimported blocks from the same poll via the 'action' key. An action
    of "import_delete" directs the parser to delete unimported content
    from the same poll, while any other value for 'action' keeps the
    unimported content. Should be an AJAX POST.

    :param request: Django request object (Required)
    :type request: :class:`django.http.HttpRequest`
    :returns: :class:`django.http.HttpResponse`
    """
    analyst = request.user.username
    post_data = json.loads(request.body)
    poll_id = post_data.get('poll_id')
    action = post_data.get('action')
    result = handlers.import_poll(poll_id, analyst, action)

    data = {'success': result['status'], 'msg': result['msg']}
    data['html'] = render_to_string("taxii_agent_results.html",
                                    {'imported' : result})
    return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def get_taxii_config_form(request, crits_type, crits_id):
    if request.method == "GET":
        obj = class_from_id(crits_type, crits_id)
        if not obj:
            ret = {'success': False,
                   'reason': "Could not locate object in the database."}
            return HttpResponse(json.dumps(ret), content_type="application/json")

        tform = forms.TAXIISendForm(request.user.username, obj)
        taxii_form = {'form' : render_to_string("_taxii_form_template.html",
                                                {'form' : tform})}
        return HttpResponse(json.dumps(taxii_form),
                            content_type="application/json")
    else:
        return render(request, 'error.html', {'error': "Must be AJAX."})

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
        return render(request, 'error.html', {'error': "Must be POST request."})

@user_passes_test(user_can_view_data)
def execute_taxii_service(request, crits_type, crits_id):
    """
    Convert the given CRITs object to standards via STIX & CybOX,
    then attempt to send as a TAXII message to the configured TAXII server.

    :param request The request object
    :param crits_type The type of the crits object that will be converted
    :param crits_id The ID of the crits object that will be converted
    """
    try:
        if request.method == "POST" and request.is_ajax():
	        return get_taxii_result(request, crits_type, crits_id, False)
        else:
	        return render(request, 'error.html', {'error': "Must be AJAX."})
    except Exception as e:
        data = {'success': False, 'reason': str(type(e)) + str(e)}
        return HttpResponse(json.dumps(data), content_type="application/json")

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
        return HttpResponse(json.dumps(ret), content_type="application/json")

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
            utcnow = datetime.utcnow().strftime('%Y%m%dT%H%M%S')
            c_disp = 'attachment; filename="stix_preview-%s.xml"' % utcnow
            resp['Content-Disposition'] = c_disp
            return resp
        else: # else show success/error message that has been generated
            return HttpResponse(json.dumps(data), content_type="application/json")
    else: # form doesn't validate
        data = {'success': False,
                'reason': "Invalid options provided. Please fix and try again."}
        return HttpResponse(json.dumps(data), content_type="application/json")

@user_passes_test(user_can_view_data)
def configure_taxii(request, server=None):
    analyst = request.user.username
    srvr_form = forms.TAXIIServerConfigForm([(x,'') for x in range(100)],
                                            request.POST or None)
    feed_form = forms.TAXIIFeedConfigForm(analyst, request.POST or None)
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
        else:
            msg = "<b>Form Validation Error</b><br>"
            for fld in feed_form.errors:
                msg += "%s: %s<br>" % (feed_form[fld].label,
                                       feed_form.errors[fld].as_text())
            results = {'success': False, 'error': msg}

        if 'service' in results:
            del results['service']
        return HttpResponse(json.dumps(results), content_type="application/json")

    if srvr_form.is_valid(): # server form passed django validation
        result = handlers.update_taxii_server_config(srvr_form.cleaned_data,
                                                     analyst)
        if result['success']:
            return HttpResponseRedirect(reverse('crits-services-views-detail',
                                                kwargs={'name':'taxii_service'}))
        srvr_form = handlers.add_feed_config_buttons(srvr_form)
        return render(request, 'taxii_server_config.html',
                                  {'form': srvr_form, 'results': result,
                                   'error': result['error']})
    elif request.method == "POST": # django form validation error occurred
        srvr_form = handlers.add_feed_config_buttons(srvr_form)
        return render(request, 'taxii_server_config.html', {'form': srvr_form})

    result = handlers.get_taxii_server_config(server)
    if result['success']:
        return render(request, 'taxii_server_config.html',
                          {'form': result['html'],
                           'form2': feed_form,
                           'errors': result['form'].errors})
    else:
        return HttpResponseRedirect(reverse('taxii_service-views-configure_taxii'))

def taxii_service_context(request):
    context = {}
    if request.user.is_authenticated():
        user = request.user.username
        try:
            context['upload_standards'] = forms.UploadStandardsForm(user)
        except Exception, e:
            logger.warning("Base Context UploadStandardsForm Error: %s" % e)
    return context
