from django.conf.urls import url

from . import views

def register_api(v1_api):
    from taxii_service.api import StandardsResource
    v1_api.register(StandardsResource())

urlpatterns = [
    url(r'^taxii_agent/$', views.taxii_poll, name='taxii_service-views-taxii_poll'),
    url(r'^taxii_agent/import/$', views.import_taxii_data, name='taxii_service-views-import_taxii_data'),
    url(r'^taxii_agent/export/(?P<tid>\S+)$', views.download_taxii_content, name='taxii_service-views-download_taxii_content'),
    url(r'^taxii_agent/saved/$', views.list_saved_polls, name='taxii_service-views-list_saved_polls'),
    url(r'^taxii_agent/preview/(?P<poll_id>[\S.]+)/(?P<page>[\S.]+)/(?P<mult>[\S.]+)/$', views.get_import_preview, name='taxii_service-views-get_import_preview'),
    url(r'^taxii_agent/select/(?P<poll_id>[0-9]+\.[0-9]+)/(?P<select>[01x]*)/$', views.select_deselect_all, name='taxii_service-views-select_deselect_all'),
    url(r'^taxii_agent/select/(?P<block_id>[\S.]+)/(?P<select>[\S.]+)/$', views.select_deselect_block, name='taxii_service-views-select_deselect_block'),
    url(r'^configure/$', views.configure_taxii, name='taxii_service-views-configure_taxii'),
    url(r'^configure/(?P<server>[\w ]+)/$', views.configure_taxii, name='taxii_service-views-configure_taxii'),
    url(r'^get_taxii_config_form/(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', views.get_taxii_config_form, name='taxii_service-views-get_taxii_config_form'),
    url(r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', views.execute_taxii_service, name='taxii_service-views-execute_taxii_service'),
    url(r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/preview$', views.preview_taxii_service, name='taxii_service-views-preview_taxii_service'),
    url(r'^stix_upload/$', views.stix_upload, name='taxii_service-views-stix_upload'),
]
