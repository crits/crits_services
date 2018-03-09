from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^main/$', views.main, name='prettythings-views-main'),
    url(r'^campaign_heatmap/$', views.campaign_heatmap, name='prettythings-views-campaign_heatmap'),
]
