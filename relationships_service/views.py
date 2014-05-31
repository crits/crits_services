import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse

from crits.core.user_tools import user_can_view_data
from . import handlers

@user_passes_test(user_can_view_data)
def get_relationships(request, ctype, cid):
    result = { "success": False, "message": "No data available." }
    depth = request.POST.get('depth', 3)
    types = request.POST.get('types', '').split(',')

    result['message'] = handlers.gather_relationships(ctype,
                                                      cid,
                                                      "%s" % request.user,
                                                      depth,
                                                      types)
    result['success'] = True

    return HttpResponse(json.dumps(result), mimetype="application/json")
