import json

from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext
from django.template.loader import render_to_string

from crits.core.user_tools import user_can_view_data
from . import handlers
from . import forms

@user_passes_test(user_can_view_data)
def get_pcap_pdml(request, pcap_md5):
    if request.method == "GET" and request.is_ajax():
        result = handlers.pcap_pdml_html(pcap_md5, request.user.username)
        if 'objects' in result:
            subscription = {'type': "PCAP", 'id': result['id']}
            object_html = render_to_string('objects_listing_widget.html',
                                           {'objects': result['objects'],
                                            'splunk_search_url': settings.SPLUNK_SEARCH_URL,
                                            'subscription': subscription},
                                           RequestContext(request))
            data = {'html': result['html'], 'object_html': object_html}
        else:
            data = {'html': result['html']}
        return HttpResponse(json.dumps(data), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_pcap_tcpdump(request, pcap_md5):
    if request.method == "POST" and request.is_ajax():
        form = forms.TCPDumpForm(request.POST)
        if form.is_valid():
            data = {'html': handlers.pcap_tcpdump(pcap_md5,
                                                  form,
                                                  request.user.username)}
        else:
            data = {'html': "Invalid form data"}
        return HttpResponse(json.dumps(data), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_tcpdump_config_form(request):
    if request.method == "GET" and request.is_ajax():
        tcp_form = {'form': forms.TCPDumpForm().as_table()}
        return HttpResponse(json.dumps(tcp_form), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))
