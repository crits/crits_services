from django.conf.urls import patterns

urlpatterns = patterns('snugglefish_service.views',
    (r'^snugglefish_search/$', 'snugglefish_search'),
    (r'^snugglefish_status/$', 'snugglefish_status'),
    (r'^get_snugglefish_search_form/$', 'get_snugglefish_search_form'),
)
