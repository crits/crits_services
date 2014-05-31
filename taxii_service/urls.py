from django.conf.urls import patterns

urlpatterns = patterns('taxii_service.views',
    (r'^taxii_agent/$', 'taxii_agent'),
)
