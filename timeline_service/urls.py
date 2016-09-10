from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^(?P<ctype>.+?)/(?P<cid>.+?)/$', views.get_timeline),
]
