from django.conf.urls import patterns

urlpatterns = patterns('metacap_service.views',
    (r'^pdml/(?P<pcap_md5>.+?)/$', 'get_pcap_pdml'),
    (r'^tcpdump/get_form/$', 'get_tcpdump_config_form'),
    (r'^tcpdump/(?P<pcap_md5>.+?)/$', 'get_pcap_tcpdump'),
)
