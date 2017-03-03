from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^diffie/form/(?P<type_>\w+)/(?P<id_>\w+)/$', views.get_diffie_config_form),
    url(r'^diffie/run/(?P<type_>\w+)/(?P<id_>\w+)/$', views.diffie_results),
]
