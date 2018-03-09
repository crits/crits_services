import json

from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render
from django.template.loader import render_to_string

from crits.core.user_tools import user_can_view_data
from . import handlers
from . import forms

@user_passes_test(user_can_view_data)
def diffie_results(request, type_, id_):
    if request.method == "POST" and request.is_ajax():
        results = handlers.get_diffie_config(request.user.username,
                                             type_,
                                             id_,
                                             data=request.POST)
        if results['success']:
            form = results['form']
            if form.is_valid():
                first = form.cleaned_data['first']
                second = form.cleaned_data['second']
                data = handlers.get_diffie_results(first, second)
                if data['success']:
                    # Render the results in the template and pass it back.
                    first_html = render_to_string('services_results_default.html',
                                                  {'analysis': data['first']},
                                                  request=request)
                    second_html = render_to_string('services_results_default.html',
                                                   {'analysis': data['second']},
                                                   request=request)
                    data['first'] = first_html
                    data['second'] = second_html
            else:
                data = {'success': False, 'message': "Invalid form data"}
        return HttpResponse(json.dumps(data), content_type="application/json")
    else:
        return render(request, 'error.html', {'error': "Must be AJAX."})

@user_passes_test(user_can_view_data)
def get_diffie_config_form(request, type_, id_):
    if request.method == "GET" and request.is_ajax():
        results = handlers.get_diffie_config(request.user.username,
                                             type_,
                                             id_)
        # Don't use .as_table() on the form as we want to display
        # the form horizontally.
        if 'form' in results:
            results['form'] = render_to_string('diffie_service_form.html',
                                               {'form': results['form']},
                                               request=request)
        return HttpResponse(json.dumps(results), content_type="application/json")
    else:
        return render(request, 'error.html', {'error': "Must be AJAX."})
