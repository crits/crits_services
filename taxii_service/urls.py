from django.conf.urls import patterns

urlpatterns = patterns('taxii_service.views',
    (r'^taxii_agent/$', 'taxii_agent'),
    (r'^get_taxii_config_form/(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'get_taxii_config_form'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/$', 'execute_taxii_service'),
    (r'^(?P<crits_type>\S+)/(?P<crits_id>\S+)/preview$', 'preview_taxii_service'),
)
