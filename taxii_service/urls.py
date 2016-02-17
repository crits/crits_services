from django.conf.urls import patterns

def register_api(v1_api):
    from taxii_service.api import StandardsResource
    v1_api.register(StandardsResource())

urlpatterns = patterns('taxii_service.views',
    (r'^taxii_agent/$', 'taxii_agent'),
    (r'^configure/$', 'configure_taxii'),
    (r'^configure/(?P<server>[\w ]+)/$', 'configure_taxii'),
    (r'^get_taxii_config_form/(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'get_taxii_config_form'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'execute_taxii_service'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/preview$', 'preview_taxii_service'),
    (r'^upload/$', 'upload_standards'),
)
