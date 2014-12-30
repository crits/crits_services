from django.conf.urls import patterns

urlpatterns = patterns('diffie_service.views',
    (r'^diffie/form/(?P<type_>\w+)/(?P<id_>\w+)/$', 'get_diffie_config_form'),
    (r'^diffie/run/(?P<type_>\w+)/(?P<id_>\w+)/$', 'diffie_results'),
)
