from django.conf.urls import patterns

urlpatterns = patterns('misp_service.views',
    (r'add_campaign_misp/$', 'add_campaign_misp'),
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_relationships'),
    (r'send_to_misp/$', 'send_to_misp'),
)
'''
def register_api(v1_api):
    from misp_service.api import RelationshipsServiceResource
    v1_api.register(RelationshipsServiceResource())
'''
