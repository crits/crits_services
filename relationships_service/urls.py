from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'add_campaign/$', views.add_campaign),
    url(r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', views.get_relationships),
]

def register_api(v1_api):
    from relationships_service.api import RelationshipsServiceResource
    v1_api.register(RelationshipsServiceResource())
