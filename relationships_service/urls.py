from django.conf.urls import patterns

urlpatterns = patterns('relationships_service.views',
    (r'add_campaign/$', 'add_campaign'),
    (r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', 'get_relationships'),
)

def register_api(v1_api):
    from relationships_service.api import RelationshipsServiceResource
    v1_api.register(RelationshipsServiceResource())
