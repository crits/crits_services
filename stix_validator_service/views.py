import json

from django.shortcuts import render, HttpResponse
from django.contrib.auth.decorators import user_passes_test

from crits.core.user_tools import user_can_view_data

from . import handlers

@user_passes_test(user_can_view_data)
def validate(request):

    if request.method == "POST" and request.is_ajax():
        xml = request.POST['xml']
        results = {'results': handlers.validate_stix(xml)}
        return HttpResponse(json.dumps(results),
                            content_type="application/json")
    else:
        return render(request, "error.html", {"error" : 'Expected AJAX POST.'})


@user_passes_test(user_can_view_data)
def stix_validator(request):
    return render(request, "stix_validator.html", {})
