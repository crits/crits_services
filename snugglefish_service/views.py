import json
from django.template import RequestContext
from django.shortcuts import HttpResponse, render_to_response
from django.contrib.auth.decorators import user_passes_test

from crits.core.user_tools import user_can_view_data

from . import forms, handlers

@user_passes_test(user_can_view_data)
def snugglefish_status(request):
    return render_to_response('snugglefish_status.html', {'data': handlers.snugglefish_status()}, RequestContext(request))

@user_passes_test(user_can_view_data)
def snugglefish_search(request):
    """Handle request to execute snugglefish search."""
    form = forms.SnugglefishSearchForm(request.POST)
    if form.is_valid():
        search = form.cleaned_data['searchString']
        indexes = form.cleaned_data['indexes']
        result = handlers.snugglefish_search(indexes, search,
                                             request.user.username)
    else:
        result = []
    return render_to_response('snugglefish_results.html', {'data': result}, RequestContext(request))

@user_passes_test(user_can_view_data)
def get_snugglefish_search_form(request):
    """Load the snugglefish search form via AJAX."""
    if request.method == "GET" and request.is_ajax():
        form = {'form': forms.SnugglefishSearchForm().as_table()}
        return HttpResponse(json.dumps(form), mimetype="application/json")
    else:
        return render_to_response('error.html',
                                  {'error': "Must be AJAX."},
                                  RequestContext(request))
