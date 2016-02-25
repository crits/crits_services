from django.conf.urls import patterns

urlpatterns = patterns('threatexchange.views',
    (r'^query/$', 'query'),
    (r'^get_threat_types/$', 'get_threat_types'),
    (r'^get_sample_types/$', 'get_sample_types'),
    (r'^submit_query/$', 'submit_query'),
    (r'^export_object/$', 'export_object'),
    (r'^import_object/$', 'import_object'),
    (r'^get_members/$', 'get_members'),
    (r'^get_groups/$', 'get_groups'),
    (r'^get_dropdowns/$', 'get_dropdowns'),
)
