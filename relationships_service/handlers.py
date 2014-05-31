from django.core.urlresolvers import reverse

from crits.campaigns.handlers import get_campaign_details
from crits.core.user_tools import user_sources
from crits.core.class_mapper import class_from_type

def gather_relationships(obj_type, obj_id, user, depth, types):
    objects = {}
    nodes = []
    links = []
    # These would be used if we move to force labels
    #labelAnchors = []
    #labelAnchorLinks = []

    sources = user_sources(user)
    if not sources:
        return { 'nodes': nodes, 'links': links }

    field_dict = {
        'Campaign': 'name',
        'Certificate': 'md5',
        'Comment': 'object_id',
        'Domain': 'domain',
        'Email': 'date',
        'Event': 'title',
        'Indicator': 'value',
        'IP': 'ip',
        'PCAP': 'md5',
        'RawData': 'title',
        'Sample': 'md5',
        'Target': 'email_address'
    }

    # color scheme:
    # http://colorschemedesigner.com/#00426p4O9CCPc
    color_dict = {
        'Campaign': '#FF3737',
        'Certificate': '#FFA837',
        'Comment': '#3A98DA',
        'Domain': '#33EB33',
        'Email': '#FF8989',
        'Event': '#B05151',
        'Indicator': '#B08751',
        'IP': '#90570C',
        'PCAP': '#FFCC89',
        'RawData': '#4A7797',
        'Sample': '#8CCBF8',
        'Target': '#4AA24A'
    }

    def inner_collect(obj_type, obj_id, sources, depth):
        # Don't keep going if we've already processed this object
        if obj_id in objects:
            return

        klass = class_from_type(obj_type)
        if not klass:
            return

        if hasattr(klass, 'source'):
            obj = klass.objects(id=obj_id, source__name__in=sources).first()
        else:
            obj = klass.objects(id=obj_id).first()
        if not obj:
            return

        objects[obj_id] = obj

        if depth == 0:
            return

        depth -= 1
        for r in obj.relationships:
            inner_collect(r.rel_type, str(r.object_id), sources, depth)

        # END OF INNER COLLECT

    try:
        depth = int(depth)
    except ValueError:
        depth = 3

    inner_collect(obj_type, str(obj_id), sources, depth)

    # This dictionary is used to describe the position of each object
    # in the nodes list. The key is an object ID and the value is a
    # tuple where the first item is the position in the node list and
    # the second is a list of object IDs related to this object.
    #
    # Once all the nodes are created and this dictionary is populated
    # it is used to create the links.
    #
    # Here is a simple obj_graph for three objects (A, B and C) that
    # are related such that they form a triangle (A<->B, B<->C, C<->A):
    #
    # {
    #   'A': (0, ['B', 'C']),
    #   'B': (1, ['A', 'C']),
    #   'C': (2, ['B', 'A'])
    # }
    #
    # The integers are the position in the node array and are used as
    # the target. The items in the list are used as lookups back into
    # the dictionary for the source.
    obj_graph = {}

    node_position = 0
    for (obj_id, obj) in objects.iteritems():
        if obj_id in obj_graph:
            continue

        obj_type = obj._meta['crits_type']
        if obj_type in field_dict:
            value = getattr(obj, field_dict[obj_type], '')
        else:
            value = ""

        if len(types) != 0 and obj_type not in types:
            value = ""
            href = ""
            color = "#FFFFFF"
        else:
            href = reverse('crits.core.views.details', args=(obj_type, obj_id))
            color = color_dict[obj_type]

        # For every campaign on this object, make a new node in the list.
        if hasattr(obj, 'campaign'):
            for i, campaign in enumerate(obj.campaign):
                name = "%s" % obj.campaign[i].name
                (x, campaign_details) = get_campaign_details(name, user)
                if 'error' in campaign_details:
                    continue
                campaign_id = str(campaign_details['campaign_detail'].id)
                # If this campaign already exists as a node then
                # add a relationship to the current object
                if campaign_id in obj_graph:
                    (tnode, source_ids) = obj_graph[campaign_id]
                    source_ids.append(obj_id)
                else:
                    total = 0
                    for count in campaign_details['counts'].values():
                        total += count
                    campaign = name + " (" + str(total) + ")"
                    campaign_href = reverse('crits.core.views.details', args=('Campaign', campaign_id))
                    campaign_color = color_dict['Campaign']
                    n = {
                          'label': campaign,
                          'url': campaign_href,
                          'color': campaign_color
                        }
                    nodes.append(n)
                    obj_graph[campaign_id] = (node_position, [obj_id])
                    node_position += 1

        n = {
              'label': '%s' % value,
              'url': href,
              'color': color
            }

        nodes.append(n)
        obj_graph[obj_id] = (node_position, [str(r.object_id) for r in obj.relationships])
        node_position += 1

    # This dictionary is used to track the links that have been created.
    # When a new link is created the inverse is added to this dictionary as
    # a key. This is because the link between A->B is the same as B->A. When
    # the link for A->B is made, we insert it into this dictionary and then
    # lookup the inverse when creating any new relationships. This ensures
    # that when B->A is handled it will be ignored.
    link_dict = {}

    for (tid, (tnode, source_ids)) in obj_graph.iteritems():
        for sid in source_ids:
            # If the graph is cut off the related object may not have been
            # collected. If the inverse relationship is already done, no
            # need to do this one too.
            if sid not in obj_graph or (tid + sid) in link_dict:
                continue
            link = {
                     'source': obj_graph[sid][0],
                     'target': tnode,
                     'weight': 1,
                   }
            links.append(link)
            link_dict[sid + tid] = True
        #labelAnchors.append({'node': n,
        #                     'url': href})
        #labelAnchors.append({'node': n,
        #                     'url': href})
        #alink = {
        #         'source': (len(nodes) - 1) * 2,
        #         'target': (len(nodes) - 1) * 2 + 1,
        #         'weight': 1,
        #}
        #labelAnchorLinks.append(alink)
    return {
            'nodes': nodes,
            'links': links,
            #'labelAnchors': labelAnchors,
            #'labelAnchorLinks': labelAnchorLinks,
           }
