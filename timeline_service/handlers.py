import cgi
import urllib

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.template.loader import render_to_string

from crits.core.user_tools import user_sources
from crits.core.class_mapper import class_from_type

def generate_timeline(obj_type, obj_id, user):

    users_sources = user_sources(user)
    obj_class = class_from_type(obj_type)
    if hasattr(obj_class, 'source'):
        main_obj = obj_class.objects(id=obj_id,
                                    source__name__in=users_sources).first()
    else:
        main_obj = obj_class.objects(id=obj_id).first()
    if not main_obj:
        return {'success': False,
                'message': 'No starting object found.'}

    # timeline is a dictionary.
    # the key is the date with no time allowing us to collect a day's events.
    # the value is a list of tuples.
    # the first item in the tuple should be a datetime string for the event.
    # the second element should be a description of the event that happened.
    timeline = {}

    # creation time
    i = "<b>%s</b> was created" % obj_type
    append_to_timeline(timeline, main_obj.created, i)

    # sources
    if hasattr(main_obj, 'source'):
        for source in main_obj.source:
            if source.name in users_sources:
                name = source.name
                for instance in source.instances:
                    i = "Source <b>%s</b> provided %s with a method of <b>'%s'</b> \
                            and a reference of <b>'%s'</b>" % (name,
                                                            obj_type,
                                                            cgi.escape(str(instance.method)),
                                                            cgi.escape(str(instance.reference)))
                    append_to_timeline(timeline, instance.date, i)

    # releasability
    for release in main_obj.releasability:
        if release.name in users_sources:
            name = release.name
            for instance in release.instances:
                i = "Release to <b>%s</b> added." % cgi.escape(name)
                append_to_timeline(timeline, instance.date, i)

    # campaigns
    for campaign in main_obj.campaign:
        name = campaign.name
        confidence = campaign.confidence
        description = campaign.description
        rev = reverse('crits-campaigns-views-campaign_details', args=[name,])
        link = '<a href="%s">%s</a>' % (cgi.escape(rev), cgi.escape(name))
        i = "Campaign <b>%s</b> added with a confidence of <b>%s</b> and a \
                description of '%s'" % (link,
                                        confidence,
                                        cgi.escape(description))
        append_to_timeline(timeline, campaign.date, i)

    # objects
    for obj in main_obj.obj:
        type_ = obj.object_type
        value = obj.value
        rev = '%s?search_type=object&otype=%s&q=%s&force_full=1' \
                % (reverse('crits-core-views-global_search_listing'),
                   "%s" % (type_),
                   urllib.quote(value))
        link = '<a href="%s">%s</a>' % (cgi.escape(rev), cgi.escape(value))
        i = "<b>%s</b> object added with a value of :<br />%s" % (type_,
                                                                  link)
        append_to_timeline(timeline, obj.date, i)

    # relationships
    for rel in main_obj.relationships:
        tobj = class_from_type(rel.rel_type)
        if tobj.objects(id=rel.object_id,
                        source__name__in=users_sources).only('id').first():
            rev = reverse('crits-core-views-details', args=[rel.rel_type,
                                                            str(rel.object_id),])
            link = '<a href="%s">%s</a>' % (rev, rel.rel_type)
            i = "<b>%s</b> was added with a relationship of <b>%s</b>." % (link,
                                                             rel.relationship)
            append_to_timeline(timeline, rel.date, i)

    # comments
    cobj = class_from_type("Comment")
    comments = cobj.objects(obj_type=obj_type,
                            obj_id=obj_id)
    for comment in comments:
        comment.comment_to_html()
        i = "<b>%s</b> made a comment: %s" % (comment.analyst,
                                              cgi.escape(comment.comment))
        append_to_timeline(timeline, comment.created, i)

    analysis_results = main_obj.get_analysis_results()

    # analysis
    for analysis in analysis_results:
        analyst = analysis.analyst
        service_name = analysis.service_name
        version = analysis.version
        results = len(analysis.results)
        i = "<b>%s</b> ran <b>%s (%s)</b> and got <b>%d</b> results." % (analyst,
                                                                         service_name,
                                                                         version,
                                                                         results)
        append_to_timeline(timeline, analysis.start_date, i)

    # tickets
    for ticket in main_obj.tickets:
        i = "<b>%s</b> added Ticket <b>%s</b>" % (ticket.analyst,
                                                  cgi.escape(ticket.ticket_number))
        append_to_timeline(timeline, ticket.date, i)

    # raw data specific timeline entries
    if obj_type == "RawData":

        # inline comments
        for inline in main_obj.inlines:
            i = "<b>%s</b> made an inline comment on line <b>%d</b>: %s" % (inline.analyst,
                                                                            inline.line,
                                                                            cgi.escape(inline.comment))
            append_to_timeline(timeline, inline.date, i)

        # highlights
        for highlight in main_obj.highlights:
            i = "<b>%s</b> highlighted line <b>%d</b>: %s" % (highlight.analyst,
                                                              highlight.line,
                                                              highlight.comment)
            append_to_timeline(timeline, highlight.date, i)

        # versions
        robj = class_from_type(obj_type)
        versions = robj.objects(link_id=main_obj.link_id).only('id',
                                                               'version',
                                                               'created')
        for version in versions:
            rev = reverse('crits-raw_data-views-raw_data_details',
                          args=[str(version.id),])
            link = '<a href="%s">%d</a>' % (rev, version.version)
            i = "Version %s was added." % link
            append_to_timeline(timeline, version.created, i)

    # indicator specific timeline entries
    if obj_type == "Indicator":

        # actions
        for action in main_obj.actions:
            i = "<b>%s</b> added action <b>%s</b> to start on <b>%s</b>" \
                % (action.analyst,
                   action.action_type,
                   action.begin_date)
            i += ", set to <b>%s</b>, with a reason of: <b>%s</b>" \
                    % (action.active,
                       cgi.escape(action.reason))
            append_to_timeline(timeline, action.date, i)

        # activity
        for activity in main_obj.activity:
            i = "<b>%s</b> noted Indicator activity from <b>%s</b> to <b>%s</b> \
                    and said: %s" % (activity.analyst,
                                     activity.start_date,
                                     activity.end_date,
                                     cgi.escape(activity.description))
            append_to_timeline(timeline, activity.date, i)

    # sort timeline
    sorted_timeline = []
    keys = timeline.keys()
    keys.sort()
    for key in keys:
        k = timeline[key]
        k.sort(key=lambda tup:tup[0])
        sorted_timeline.append((key, k))

    html = render_to_string('timeline_contents.html',
                            {'timeline': sorted_timeline})

    return {'success': True,
            'message': html}


def append_to_timeline(timeline, date, item):
    dt = str(date)
    d = dt.split(" ")[0]
    add = (dt, item)
    if d not in timeline:
        timeline[d] = []
    timeline[d].append(add)
