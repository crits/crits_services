from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^test_yara_rule/(?P<id_>.+?)/$', views.get_yara_result, name='yara_service-views-get_yara_result'),
]
