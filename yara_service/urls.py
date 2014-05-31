from django.conf.urls import patterns

urlpatterns = patterns('yara_service.views',
    (r'^test_yara_rule/(?P<id_>.+?)/$', 'get_yara_result'),
)
