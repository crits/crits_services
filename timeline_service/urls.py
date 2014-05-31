from django.conf.urls import patterns

urlpatterns = patterns('timeline_service.views',
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_timeline'),
)
