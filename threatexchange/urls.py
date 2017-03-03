from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^query/$', views.query),
    url(r'^privacy_groups/$', views.privacy_groups),
    url(r'^submit_query/$', views.submit_query),
    url(r'^submit_related_query/$', views.submit_related_query),
    url(r'^export_object/$', views.export_object),
    url(r'^import_object/$', views.import_object),
    url(r'^get_members/$', views.get_members),
    url(r'^get_groups/$', views.get_groups),
    url(r'^get_dropdowns/$', views.get_dropdowns),
    url(r'^get_privacy_group_form/$', views.get_privacy_group_form),
    url(r'^add_edit_privacy_group/$', views.add_edit_privacy_group),
]
