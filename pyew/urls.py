from django.conf.urls import patterns

urlpatterns = patterns('pyew.views',
    (r'^pyew_port/$', 'pyew_port'),
    (r'^pyew_token/$', 'pyew_tokenize'),
)
