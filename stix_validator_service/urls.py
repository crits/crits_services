from django.conf.urls import patterns

urlpatterns = patterns('stix_validator_service.views',
    (r'^stix_validator/$', 'stix_validator'),
    (r'^validate/$', 'validate'),
)
