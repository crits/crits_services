import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext
#from django.template.loader import render_to_string

from pytx.vocabulary import ThreatType as tt
from pytx.vocabulary import MalwareAnalysisTypes as mat
from pytx.vocabulary import ThreatExchange as tx

from crits.core.user_tools import user_can_view_data
from . import handlers
#from . import forms

@user_passes_test(user_can_view_data)
def query(request):
    return render_to_response('query.html',
                              {'foo': "bar"},
                              RequestContext(request))

@user_passes_test(user_can_view_data)
def get_threat_types(request):
    if request.method == "POST" and request.is_ajax():
        threat_types = {k:v for k,v in tt.__dict__.items() if not k.startswith('__') and not callable(k)}

        return HttpResponse(json.dumps(threat_types),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_sample_types(request):
    if request.method == "POST" and request.is_ajax():
        sample_types = {k:v for k,v in mat.__dict__.items() if not k.startswith('__') and not callable(k)}
        return HttpResponse(json.dumps(sample_types),
                            content_type="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
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
        if type_:
            del params['type']
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
        results = handlers.get_groups()
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
