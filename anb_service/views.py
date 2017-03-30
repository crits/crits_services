import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse

from crits.core.user_tools import user_can_view_data, user_sources
from . import handlers

@user_passes_test(user_can_view_data)
def get_anb_data(request, ctype, cid):
    result = { "success": "false", "message": "No data available." }

    sources = user_sources("%s" % request.user)
    if not sources:
        return HttpResponse(json.dumps(result), content_type="application/json")

    data = handlers.execute_anb(ctype, cid, sources)
    # If any of the values are not an empty string we have data.
    for v in data.values():
        if v != "":
            result['success'] = "true"
            result['message'] = data
            break

    return HttpResponse(json.dumps(result), content_type="application/json")
