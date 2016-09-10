from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^pyew_port/$', views.pyew_port),
    url(r'^pyew_token/$', views.pyew_tokenize),
]
