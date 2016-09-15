from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^snugglefish_search/$', views.snugglefish_search, name='snugglefish_service-views-snugglefish_search'),
    url(r'^snugglefish_status/$', views.snugglefish_status, name='snugglefish_service-views-snugglefish_status'),
    url(r'^get_snugglefish_search_form/$', views.get_snugglefish_search_form, name='snugglefish_service-views-get_snugglefish_search_form'),
]
