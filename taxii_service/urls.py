from django.conf.urls import patterns

def register_api(v1_api):
    from taxii_service.api import StandardsResource
    v1_api.register(StandardsResource())

urlpatterns = patterns('taxii_service.views',
    (r'^taxii_agent/$', 'taxii_poll'),
    (r'^taxii_agent/import/$', 'import_taxii_data'),
    (r'^taxii_agent/export/(?P<tid>\S+)$', 'download_taxii_content'),
    (r'^taxii_agent/saved/$', 'list_saved_polls'),
    (r'^taxii_agent/preview/(?P<taxii_msg_id>[\S.]+)/(?P<page>[\S.]+)/(?P<mult>[\S.]+)/$', 'get_import_preview'),
    (r'^configure/$', 'configure_taxii'),
    (r'^configure/(?P<server>[\w ]+)/$', 'configure_taxii'),
    (r'^get_taxii_config_form/(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'get_taxii_config_form'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'execute_taxii_service'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/preview$', 'preview_taxii_service'),
    (r'^stix_upload/$', 'stix_upload'),
)
