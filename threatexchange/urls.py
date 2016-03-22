from django.conf.urls import patterns

urlpatterns = patterns('threatexchange.views',
    (r'^query/$', 'query'),
    (r'^submit_query/$', 'submit_query'),
    (r'^submit_related_query/$', 'submit_related_query'),
    (r'^export_object/$', 'export_object'),
    (r'^import_object/$', 'import_object'),
    (r'^get_members/$', 'get_members'),
    (r'^get_groups/$', 'get_groups'),
    (r'^get_dropdowns/$', 'get_dropdowns'),
)
