import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render_to_response
from django.template import RequestContext

from crits.core.user_tools import user_can_view_data
from . import handlers

@user_passes_test(user_can_view_data)
def get_yargen_result(request, ctype, cid):
    '''
    if request.method == "POST" and request.is_ajax():
        rule = request.POST['rule']
        result = handlers.gather_relationships(ctype, cid, "%s" % request.user)
        return HttpResponse(json.dumps(result), mimetype="application/json")
    else:
        return render_to_response("error.html", {"error" : "Expected AJAX POST" }, RequestContext(request))
    '''
    
    depth = request.POST.get('depth', 1)
    
    result = { "success": False, "message": "No data available." }
    
    result['message'] = handlers.gather_relationships(ctype,
                                                      cid,
                                                      "%s" % request.user,
                                                      depth)
                                
    result['success'] = True
    final_result = HttpResponse(json.dumps(result), mimetype="application/json")
    print final_result
    #return render_to_response("error.html", {"error" : "Debugging" }, RequestContext(request))
    return final_result
    
def run_yargen(request):
	#foreach data.message - get the filenames (labels) and obj_ids to pass to execute_yargen
	
	#relatedSamples = request.POST.get('message')
	#relatedSamples = request.POST.getlist('message')
	#relatedSamples = request.POST['message']
	relatedSamples = request.POST
	
	result = { "success": False, "message": "No data available." }
	
	#result['message'] = relatedSamples
	#result['success'] = True
	#return HttpResponse(json.dumps(result), mimetype="application/json")
	
	result['message'] = handlers.execute_yargen(relatedSamples,
												"%s" % request.user)
	result['success'] = True
	final_result = HttpResponse(json.dumps(result), mimetype="application/json")
	return final_result
	
	'''
	array should now look like this before passing to yargen.py:
		yargen_array[	
			0	=>	[
						id => '5531632c3b16cd29e4a0d2c0',
						filename => 'invoice.exe',
						filedata => '<base64 filedata>'
					]
		]
	'''

	#return yargen_array
	#return ""
