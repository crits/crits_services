from django.conf.urls import url

from . import views

def register_api(v1_api):
    from taxii_service.api import StandardsResource
    v1_api.register(StandardsResource())

urlpatterns = [
    url(r'^taxii_agent/$', views.taxii_poll),
    url(r'^taxii_agent/import/$', views.import_taxii_data),
    url(r'^taxii_agent/export/(?P<tid>\S+)$', views.download_taxii_content),
    url(r'^taxii_agent/saved/$', views.list_saved_polls),
    url(r'^taxii_agent/preview/(?P<taxii_msg_id>[\d.]+)/$', views.get_import_preview),
    url(r'^configure/$', views.configure_taxii),
    url(r'^configure/(?P<server>[\w ]+)/$', views.configure_taxii),
    url(r'^get_taxii_config_form/(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', views.get_taxii_config_form),
    url(r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', views.execute_taxii_service),
    url(r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/preview$', views.preview_taxii_service),
    url(r'^stix_upload/$', views.stix_upload),
]
