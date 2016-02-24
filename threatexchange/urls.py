from django.conf.urls import patterns

urlpatterns = patterns('threatexchange.views',
    (r'^query/$', 'query'),
    (r'^get_threat_types/$', 'get_threat_types'),
    (r'^get_sample_types/$', 'get_sample_types'),
    (r'^submit_query/$', 'submit_query'),
)
