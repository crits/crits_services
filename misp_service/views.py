import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse

from crits.core.user_tools import user_can_view_data
from crits.services.handlers import get_service_config
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
    
    configs = get_service_config('misp_service')
    
    result['configs'] = {'default_tags': configs['config']['Global Event Tag'],
                         'event_prefix': configs['config']['Event Prefix'],
                         'misp_url': configs['config']['MISP URL']}
    
    #result['configs'] = configs['config']
    '''
    "configs": {
		"Event Prefix": "<prefix>",
		"Global Event Tag": "<global tags>",
		"MISP API Key": "<api_key>",
		"MISP URL": "http://<misp_url>/"
	},
    '''

    return HttpResponse(json.dumps(result), content_type="application/json")
    
@user_passes_test(user_can_view_data)
def send_to_misp(request):
    result = { "success": False }
    
    if not (request.method == 'POST' and request.is_ajax()):
        result["message"] = "Expected AJAX post"
        return HttpResponse(json.dumps(result), content_type="application/json")
        
    misp_data = request.POST.get('misp_data', {})
    if not misp_data:
        result["message"] = "Something went wrong. 'misp_data' was not POSTed to the server."
        return HttpResponse(json.dumps(result), content_type="application/json")
        
    try:
        misp_data = json.loads(misp_data)
    except Exception as e:
        result["message"] = str(e)
        return HttpResponse(json.dumps(result), content_type="application/json")
        
    misp_configs = get_service_config('misp_service')
    misp_configs = misp_configs['config']
        
    result["message"] = handlers.send_to_misp(misp_data,
                                   misp_configs,
                                   request.user.username)
                                   
    result['success'] = True
    
    return HttpResponse(json.dumps(result), content_type="application/json")

@user_passes_test(user_can_view_data)
def add_campaign_misp(request):
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
