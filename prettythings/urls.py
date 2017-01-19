from django.conf.urls import patterns

urlpatterns = patterns('prettythings.views',
    (r'^main/$', 'main'),
    (r'^campaign_heatmap/$', 'campaign_heatmap'),
)
