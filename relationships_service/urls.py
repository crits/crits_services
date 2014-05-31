from django.conf.urls import patterns

urlpatterns = patterns('relationships_service.views',
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_relationships'),
)
