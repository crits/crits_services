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

    return HttpResponse(json.dumps(result), content_type="application/json")

@user_passes_test(user_can_view_data)
def add_campaign(request):
    result = { "success": False }

    if not (request.method == 'POST' and request.is_ajax()):
        result["message"] = "Expected AJAX post"
        return HttpResponse(json.dumps(result), content_type="application/json")

    nodes = request.POST.get('nodes', [])
    name = request.POST.get('name', '')
    confidence = request.POST.get('confidence', 'low')
    if not nodes or not name:
        result["message"] = "Need nodes and name."
        return HttpResponse(json.dumps(result), content_type="application/json")

    try:
        nodes = json.loads(nodes)
    except Exception as e:
        result['message'] = str(e)
        return HttpResponse(json.dumps(result), content_type="application/json")

    result = handlers.add_campaign_from_nodes(name,
                                              confidence,
                                              nodes,
                                              request.user.username)
    return HttpResponse(json.dumps(result), content_type="application/json")
