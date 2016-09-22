import json

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import HttpResponse, render

from crits.core.user_tools import user_can_view_data
from . import handlers

@user_passes_test(user_can_view_data)
def get_yara_result(request, id_):
    if request.method == "POST" and request.is_ajax():
        rule = request.POST['rule']
        result = handlers.test_yara_rule(id_, rule)
        return HttpResponse(json.dumps(result), content_type="application/json")
    else:
        return render(request, "error.html", {"error" : "Expected AJAX POST" })
