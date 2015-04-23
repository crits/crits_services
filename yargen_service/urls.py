from django.conf.urls import patterns


urlpatterns = patterns('yargen_service.views',
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_yargen_result'),
    (r'', 'run_yargen'),
)
