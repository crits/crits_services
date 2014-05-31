from django.conf.urls import patterns

urlpatterns = patterns('chopshop_service.views',
    (r'^filecarver/get_form/$', 'get_filecarver_config_form'),
    (r'^filecarver/(?P<pcap_md5>.+?)/$', 'run_filecarver'),
)
