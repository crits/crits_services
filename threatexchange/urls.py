from django.conf.urls import patterns

urlpatterns = patterns('threatexchange.views',
    (r'^query/$', 'query'),
    (r'^privacy_groups/$', 'privacy_groups'),
    (r'^submit_query/$', 'submit_query'),
    (r'^submit_related_query/$', 'submit_related_query'),
    (r'^export_object/$', 'export_object'),
    (r'^import_object/$', 'import_object'),
    (r'^get_members/$', 'get_members'),
    (r'^get_groups/$', 'get_groups'),
    (r'^get_dropdowns/$', 'get_dropdowns'),
    (r'^get_privacy_group_form/$', 'get_privacy_group_form'),
    (r'^add_edit_privacy_group/$', 'add_edit_privacy_group'),
)
