from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import user_passes_test

from crits.core.user_tools import user_can_view_data
from . import handlers


@user_passes_test(user_can_view_data)
def taxii_agent(request):

    # Use service configuration from DB.
    result = handlers.execute_taxii_agent(analyst=request.user.username, method="TAXII Agent Web")

    return render_to_response('taxii_agent_results.html', {'result': result}, RequestContext(request))
