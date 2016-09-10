from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^pdml/(?P<pcap_md5>.+?)/$', views.get_pcap_pdml),
    url(r'^tcpdump/get_form/$', views.get_tcpdump_config_form),
    url(r'^tcpdump/(?P<pcap_md5>.+?)/$', views.get_pcap_tcpdump),
]
