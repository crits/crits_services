import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext

from crits.core.user_tools import user_can_view_data
from . import handlers
from . import forms

@user_passes_test(user_can_view_data)
def run_filecarver(request, pcap_md5):
    if request.method == "POST" and request.is_ajax():
        form = forms.FileCarverForm(request.POST)
        if form.is_valid():
            data = handlers.chopshop_carver(pcap_md5,
                                            form.cleaned_data,
                                            request.user.username)
        else:
            data = {'success': False, 'message': "Invalid form data"}
        return HttpResponse(json.dumps(data), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))

@user_passes_test(user_can_view_data)
def get_filecarver_config_form(request):
    if request.method == "GET" and request.is_ajax():
        tcp_form = {'form': forms.FileCarverForm().as_table()}
        return HttpResponse(json.dumps(tcp_form), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))
