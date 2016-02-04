import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse

from crits.core.user_tools import user_can_view_data
from . import handlers

@user_passes_test(user_can_view_data)
def get_timeline(request, ctype, cid):
    result = handlers.generate_timeline(ctype, cid, "%s" % request.user)
    return HttpResponse(json.dumps(result), content_type="application/json")
