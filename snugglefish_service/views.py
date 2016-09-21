import json
from django.template import RequestContext
from django.shortcuts import HttpResponse, render
from django.contrib.auth.decorators import user_passes_test

from crits.core.user_tools import user_can_view_data

from . import forms, handlers

@user_passes_test(user_can_view_data)
def snugglefish_status(request):
    return render(request, 'snugglefish_status.html', {'data': handlers.snugglefish_status()})

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
    return render(request, 'snugglefish_results.html', {'data': result})

@user_passes_test(user_can_view_data)
def get_snugglefish_search_form(request):
    """Load the snugglefish search form via AJAX."""
    if request.method == "GET" and request.is_ajax():
        form = {'form': forms.SnugglefishSearchForm().as_table()}
        return HttpResponse(json.dumps(form), content_type="application/json")
    else:
        return render(request, 'error.html', {'error': "Must be AJAX."})
