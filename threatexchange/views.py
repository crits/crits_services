import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template.loader import render_to_string
from django.template import RequestContext
#from django.template.loader import render_to_string

from pytx.vocabulary import ThreatExchange as tx

from crits.core.user_tools import user_can_view_data
from . import handlers
from . import forms

@user_passes_test(user_can_view_data)
def query(request):
    return render_to_response('query.html',
                              {'foo': "bar"},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def privacy_groups(request):
    return render_to_response('privacy_groups.html',
                              {'foo': "bar"},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def submit_related_query(request):
    if request.method == "POST" and request.is_ajax():
        id_ = request.POST.get('id', None)
        related_type = request.POST.get('related_type', None)
        td = {
            'descriptors': "Threat Descriptors",
            'dropped': "Malware Analyses",
            'dropped_by': "Malware Analyses",
            'families': "Malware Families",
            'related': "Threat Indicators",
            'threat_indicators': "Threat Indicators",
            'variants': "Malware Analyses"
        }
        type_ = td.get(related_type, None)
        if id_ and related_type and type_:
            url = tx.URL + tx.VERSION + id_ + '/' + related_type + '/'
            results = handlers.submit_query(request, url, type_)
            return HttpResponse(json.dumps(results),
                                content_type="application/json")
        else:
            return HttpResponse({'success': False,
                                 'message': "Need ID and valid related type."},
                                content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def submit_query(request):
    if request.method == "POST" and request.is_ajax():
        params = dict(request.POST.copy().dict())
        url = params.get('url', None)
        type_ = params.get('type', None)
        indicator_type = params.get('indicator_type', None)

        if type_:
            del params['type']
        if indicator_type is not None:

            # can probably do better validation here against the attribute
            # of the pytx "Types" enum.
            if indicator_type.strip() != "":
                params['type_'] = params.get('indicator_type')

            del params['indicator_type']

        results = handlers.submit_query(request, url, type_, params=params)
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def import_object(request):
    if request.method == "POST" and request.is_ajax():
        id_ = request.POST.get('id', None)
        type_ = request.POST.get('type', None)
        results = handlers.import_object(request, type_, id_)
        if results.get('success', False):
            if 'object' in results:
                del results['object']
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def export_object(request):
    if request.method == "POST" and request.is_ajax():
        params = dict(request.POST.copy().dict())
        type_ = params.get('tlo_type', None)
        id_ = params.get('oid', None)
        if type_:
            del params['tlo_type']
            del params['oid']
        results = handlers.export_object(request, type_, id_, params)
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_members(request):
    if request.method == "POST" and request.is_ajax():
        results = handlers.get_members()
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_groups(request):
    if request.method == "POST" and request.is_ajax():
        manage = request.POST.get("manage", None)
        results = handlers.get_groups(manage=manage)
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_dropdowns(request):
    if request.method == "POST" and request.is_ajax():
        results = handlers.get_dropdowns()
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))


@user_passes_test(user_can_view_data)
def get_privacy_group_form(request):
    if request.method == "POST" and request.is_ajax():
        initial = request.POST.copy()
        form = forms.ThreatExchangePrivacyGroupForm(initial=initial)
        template = render_to_string("privacy_form.html",
                                    {'privacy_group_form': form})
        result = {'success': True,
                'html': template}
        return HttpResponse(json.dumps(result),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def add_edit_privacy_group(request):
    if request.method == "POST" and request.is_ajax():
        id_ = request.POST.get('id', None)
        name = request.POST.get('name', None)
        description = request.POST.get('description', None)
        members = request.POST.get('members', None)
        members_can_see = request.POST.get('members_can_see', False)
        if members_can_see == "false":
            members_can_see = False
        members_can_use = request.POST.get('members_can_use', False)
        if members_can_use == "false":
            members_can_use = False
        results = handlers.add_edit_privacy_group(id_=id_,
                                                  name=name,
                                                  description=description,
                                                  members=members,
                                                  members_can_see=members_can_see,
                                                  members_can_use=members_can_use)
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))
