from django.conf.urls import patterns

urlpatterns = patterns('anb_service.views',
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_anb_data'),
)
