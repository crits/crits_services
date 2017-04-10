from django.core.urlresolvers import reverse

from crits.campaigns.campaign import Campaign
from crits.campaigns.handlers import get_campaign_details
from crits.core.crits_mongoengine import EmbeddedCampaign
from crits.core.user_tools import user_sources
from crits.core.class_mapper import class_from_type, class_from_id

from pymisp import MISPEvent, PyMISP
from datetime import datetime

def gather_relationships(obj_type, obj_id, user, depth, types):
    objects = {}
    nodes = []
    links = []
    tlos = {
        'Actor': [],
        'Backdoor': [],
        'Campaign': [],
        'Certificate': [],
        'Comment': [],
        'Domain': [],
        'Email': [],
        'Event': [],
        'Exploit': [],
        'Indicator': [],
        'IP': [],
        'PCAP': [],
        'RawData': [],
        'Sample': [],
        'Target': []
    }
    # These would be used if we move to force labels
    #labelAnchors = []
    #labelAnchorLinks = []

    sources = user_sources(user)
    if not sources:
        return { 'nodes': nodes, 'links': links }

    field_dict = {
        'Actor': 'name',
        'Backdoor': 'name',
        'Campaign': 'name',
        'Certificate': 'md5',
        'Comment': 'object_id',
        'Domain': 'domain',
        'Email': 'date',
        'Event': 'title',
        'Exploit': 'name',
        'Indicator': 'value',
        'IP': 'ip',
        'PCAP': 'md5',
        'RawData': 'title',
        'Sample': 'md5',
        'Target': 'email_address'
    }

    # Define the styles for each of the data types. Absent these, the vis.js library will
    # auto-select sensible defaults
    tlo_styles_dict = {
        'Actor': {
            'shape': 'dot',
            'size': 25,
            'color': '#900C0C',
            'color_border': '#700C0C',
            'color_highlight': '#90FCFC',
            'color_highlight_border': '#900C0C'
        },
        'Backdoor': {
            'shape': 'dot',
            'size': 10,
            'color': '#5A2C75',
            'color_border': '#3A1C55',
            'color_highlight': '#7040B0',
            'color_highlight_border': '#5A2C75'
        },
        'Campaign': {
            'shape': 'dot',
            'size': 40,
            'color': '#FF3737',
            'color_border': '#D72020',
            'color_highlight': '#FF6868',
            'color_highlight_border': '#FF3737'
        },
        'Certificate': {
            'shape': 'dot',
            'size': 10,
            'color': '#FFA837',
            'color_border': '#D08020',
            'color_highlight': '#FFC060',
            'color_highlight_border': '#FFA837'
        },
        'Domain': {
            'shape': 'dot',
            'size': 20,
            'color': '#33EB33',
            'color_border': '#25C025',
            'color_highlight': '#55FF55',
            'color_highlight_border': '#33EB33'
        },
        'Email': {
            'shape': 'dot',
            'size': 25,
            'color': '#FF8989',
            'color_border': '#CF7070',
            'color_highlight': '#FFB0B0',
            'color_highlight_border': '#FF8989'
        },
        'Event': {
            'shape': 'dot',
            'size': 35,
            'color': '#B05151',
            'color_border': '#904040',
            'color_highlight': '#D07171',
            'color_highlight_border': '#B05151'
        },
        'Exploit': {
            'shape': 'dot',
            'size': 10,
            'color': '#8CA336',
            'color_border': '#709020',
            'color_highlight': '#A8CC60',
            'color_highlight_border': '#8CA336'
        },
        'Indicator': {
            'shape': 'dot',
            'size': 10,
            'color': '#B08751',
            'color_border': '#907050',
            'color_highlight': '#CCA075',
            'color_highlight_border': '#B08751'
        },
        'IP': {
            'shape': 'dot',
            'size': 20,
            'color': '#90570C',
            'color_border': '#77400C',
            'color_highlight': '#B06037',
            'color_highlight_border': '#90570C'
        },
        'PCAP': {
            'shape': 'dot',
            'size': 10,
            'color': '#FFCC89',
            'color_border': '#D0A860',
            'color_highlight': '#FFE0B0',
            'color_highlight_border': '#FFCC89'
        },
        'Raw Data': {
            'shape': 'dot',
            'size': 10,
            'color': '#4A7797',
            'color_border': '#306080',
            'color_highlight': '#6090B8',
            'color_highlight_border': '#4A7797'
        },
        'Sample': {
            'shape': 'dot',
            'size': 25,
            'color': '#8CCBF8',
            'color_border': '#70AADC',
            'color_highlight': '#A0D0FF',
            'color_highlight_border': '#8CCBF8'
        },
        'Target': {
            'shape': 'dot',
            'size': 10,
            'color': '#4AA24A',
            'color_border': '#308030',
            'color_highlight': '#60C860',
            'color_highlight_border': '#4AA24A'
        }
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

        # If we traverse into a Campaign object, walk everything tagged
        # with that campaign along with related objects.
        if obj_type == 'Campaign':
            for c in field_dict.keys():
                klass = class_from_type(c)
                # Not every object in field_dict can be tagged with a campaign.
                # For example, comments.
                if not hasattr(klass, 'campaign'):
                    continue
                tagged_objs = klass.objects(campaign__name=obj.name)
                for tobj in tagged_objs:
                    inner_collect(tobj._meta['crits_type'],
                                  str(tobj.id),
                                  sources,
                                  depth)
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

    campaign_cache = {}
    node_position = 0
    tlo_labels = {}
    tlo_relationships = {}
    for (obj_id, obj) in objects.iteritems():
        if obj_id in obj_graph:
            continue

        obj_type = obj._meta['crits_type']

        #import pprint
        
        obj_master = obj._meta
        
        
        klass = class_from_type(obj_type)
        obj = klass.objects(id=obj_id).first()
        
        # YES! THIS WORKS!
        '''
        if obj_type=="Sample":
            sample = obj.filename
        else:
            sample = vars(obj)
        '''
        # Add the obj_id and label to the tlo_labels dict
        # e.g. tlo_labels={'<md5>': '<obj_id>'}
        label = str(obj_type+" | "+getattr(obj, field_dict[obj_type], ''))
        tlo_labels[label]=str(obj.id)
        tlos[obj_type].append(obj)

        
        ### Get TLO Relationships
        tlo_relationships[str(obj_id)]={}
        
        all_relationships = obj.relationships
        for rel in all_relationships:
            tlo_relationships[str(obj_id)][str(rel.object_id)]=str(rel.relationship)

        ### A bunch of the stuff below here can probably go...

        value = getattr(obj, field_dict[obj_type], '')
        if obj_type == 'Backdoor':
            # Append a version or family
            if obj.version == '':
                value += " (family)"
            else:
                value += " (v:%s)" % obj.version
        href = reverse('crits.core.views.details', args=(obj_type, obj_id))

        if len(types) != 0 and obj_type not in types:
            continue

        # For every campaign on this object, make a new node in the list.
        if 'Campaign' in types and hasattr(obj, 'campaign'):
            for i, campaign in enumerate(obj.campaign):
                name = "%s" % obj.campaign[i].name
                if name not in campaign_cache:
                    campaign_cache[name] = get_campaign_details(name, user)
                (x, campaign_details) = campaign_cache[name]
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

                    n = dict(tlo_styles_dict['Campaign'])

                    n['label'] = campaign
                    n['url'] = campaign_href
                    n['type'] = n['group'] = 'Campaign'
                    n['crits_status'] = 'Analyzed'
                    n['id'] = campaign_id
                    nodes.append(n)
                    obj_graph[campaign_id] = (node_position, [obj_id])
                    node_position += 1

        # n will contain the vis.js-schema data  to load into the graph
        n = {}
        if obj_type in tlo_styles_dict:
            n = dict(tlo_styles_dict[obj_type])

            n['label'] = '%s' % value
        else:
            n = {
                'label': '%s' % value,
                'shape': 'dot'
            }

        n['url'] = href
        n['crits_status'] = obj['status'];
        n['id'] = obj_id
        n['type'] = n['group'] = obj_type
        n['visible'] = True

        nodes.append(n)
        obj_graph[obj_id] = (node_position, [str(r.object_id) for r in obj.relationships])
        node_position += 1

    #### PROCESS DATA FOR MISP DISPLAY ####
    
    step1 = {}
    # This should be tlos.items() if Python 3
    for obj_type, objs in tlos.iteritems():
        for obj in objs:
            if obj_type not in step1:
                step1[str(obj_type)]={}

            '''
            Changing this up so it's {'Sample': 
                                               {'58dabfca97553032a1f7f0c5': 
                                                                           {'label': '098f6bcd4621d373cade4e832627b4f6',
                                                                            'md5': '098f6bcd4621d373cade4e832627b4f6',
                                                                            'filename': 'whatever'}
                                               }
                                       }
            '''
            if str(obj.id) not in step1[str(obj_type)]:
                step1[str(obj_type)][str(obj.id)]={}
            # Set the label as the first key
            step1[str(obj_type)][str(obj.id)]['label']=str(getattr(obj, field_dict[obj_type], ''))
            # Proces objects according to type
            if str(obj_type)=="Sample":
                # Grab the Sample attributes
                step1[str(obj_type)][str(obj.id)]['filename']=str(obj.filename)
                step1[str(obj_type)][str(obj.id)]['filetype']=str(obj.filetype)
                step1[str(obj_type)][str(obj.id)]['md5']=str(obj.md5)
                step1[str(obj_type)][str(obj.id)]['mimetype']=str(obj.mimetype)
                step1[str(obj_type)][str(obj.id)]['sha1']=str(obj.sha1)
                step1[str(obj_type)][str(obj.id)]['sha256']=str(obj.sha256)
                step1[str(obj_type)][str(obj.id)]['size']=str(obj.size)
                step1[str(obj_type)][str(obj.id)]['ssdeep']=str(obj.ssdeep)
                step1[str(obj_type)][str(obj.id)]['impfuzzy']=str(obj.impfuzzy)
            elif str(obj_type)=="Email":
                # Grab the Email attributes
                step1[str(obj_type)][str(obj.id)]['email_cc']=str(obj.cc)
                step1[str(obj_type)][str(obj.id)]['email_date']=str(obj.date)
                step1[str(obj_type)][str(obj.id)]['email_from_address']=str(obj.from_address)
                step1[str(obj_type)][str(obj.id)]['email_helo']=str(obj.helo)
                step1[str(obj_type)][str(obj.id)]['email_isodate']=str(obj.isodate)
                step1[str(obj_type)][str(obj.id)]['email_message_id']=str(obj.message_id)
                step1[str(obj_type)][str(obj.id)]['email_originating_ip']=str(obj.originating_ip)
                step1[str(obj_type)][str(obj.id)]['email_reply_to']=str(obj.reply_to)
                step1[str(obj_type)][str(obj.id)]['email_sender']=str(obj.sender)
                step1[str(obj_type)][str(obj.id)]['email_subject']=str(obj.subject)
                step1[str(obj_type)][str(obj.id)]['email_to']=str(obj.to)
                step1[str(obj_type)][str(obj.id)]['email_x_originating_ip']=str(obj.x_originating_ip)
                step1[str(obj_type)][str(obj.id)]['email_x_mailer']=str(obj.x_mailer)
            elif str(obj_type)=="Domain":
                step1[str(obj_type)][str(obj.id)]['domain']=str(obj.domain)
            elif str(obj_type)=="Indicator":
                step1[str(obj_type)][str(obj.id)]['type']=str(obj.ind_type)
            elif str(obj_type)=="Event":
                step1[str(obj_type)][str(obj.id)]['event_title']=str(obj.title)
                step1[str(obj_type)][str(obj.id)]['event_type']=str(obj.event_type)
            elif str(obj_type)=="IP":
                step1[str(obj_type)][str(obj.id)]['ip']=str(obj.ip)
                #step1[str(obj_type)][str(obj.id)]['ip_type']=str(obj.ip_type)

    
    n['tlo_labels']=tlo_labels
    n['step1']=step1
    n['tlo_relationships']=tlo_relationships
    
    
    '''
    n['tlo_labels']=pprint.pformat(tlo_labels)
    n['step1']=pprint.pformat(step1)
    n['tlo_relationships']=pprint.pformat(tlo_relationships)
    '''
    
    
    
    #### END NMD Debug
        
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
                     'from': sid,
                     'to': tid
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
        
    # Get all CRITs relationship types
    from crits.vocabulary.relationships import RelationshipTypes
    rel_types=[c for c in RelationshipTypes.values(sort=True)]
    
    # Get all MISP Categories and Types
    misp_obj=MISPEvent()
    misp_cats = misp_obj.categories
    misp_types = misp_obj.category_type_mapping
    
    
    '''
    from crits.services.service import CRITsService
    svc_obj = CRITsService.objects(name='misp_service')
    misp_config = svc_obj.config.to_dict()
    '''
    
    return {
            'nodes': nodes,
            'links': links,
            'rel_types': rel_types,
            'misp_cats': misp_cats,
            'misp_types': misp_types,
            #'misp_config': misp_config,
            #'tlos': tlos,
            #'tlo_labels': tlo_labels,
            #'tlo_relationships': tlo_relationships,
            #'labelAnchors': labelAnchors,
            #'labelAnchorLinks': labelAnchorLinks,
           }

def send_to_misp(misp_data, misp_configs, user):
    
    debug_log=''
    
    misp_key = misp_configs['MISP API Key']
    misp_url = misp_configs['MISP URL']
    ssl = False
    proxies = ''
    distribution = misp_data['misp_distro']
    analysis = misp_data['misp_analysis']
    threat_level = misp_data['misp_threat']
    publish = misp_data['misp_pub']
    tags = misp_data['misp_tags']
    attributes = misp_data['attribs']
    
    dt = datetime.utcnow()
    event_date = dt.strftime('%Y-%m-%d')
    '''
    TODO: 
    + Add other options from configs 
    (misp_configs['proxies'], misp_configs['ssl'], etc)
    
    + Get Event Date from CRITs instance, rather than today
    '''
    from pprint import pformat
    # Load the PyMISP functions
    misp = PyMISP(misp_url, misp_key, ssl, 'json', proxies=proxies)
    # Build the event and tags if applicable
    misp_title = misp_data['misp_info']
    if misp_title=="None":
        # Modify this to build a more-sane Event Info if none was given
        for k,v in misp_data['attribs']:
            misp_title=k
            break
    
    if misp_data['options']['misp_dedup_events']==True:
        #Search for the event
        event = ''
        result = misp.search_index(eventinfo=misp_title)
        #debug_log+=pformat(result)
        if 'message' in result:
            if result['message']=='No matches.':
                event = misp.new_event(distribution, threat_level, analysis, 
                                       misp_title, date=event_date, published=publish)
        else:
            for evt in result['response']:
                # If the event exists, set 'event' to the event
                if evt['info']==misp_title:
                    event = {}
                    event['Event'] = evt
                    break
            if event=='':
                # Event not found, even though search results were returned
                # Build new event
                event = misp.new_event(distribution, threat_level, analysis, 
                                       misp_title, date=event_date, published=publish)
    else:
        event = misp.new_event(distribution, threat_level, analysis, 
                                misp_title, date=event_date, published=publish)
    
    misp_data['event']=event['Event']['id']
    
    if tags!=[]:
        for tag in tags:
            misp.tag(event['Event']['uuid'], str(tag.strip()))
        
    for k, v in attributes.iteritems():
        if v['misp-submit']==True:
            ind_kwargs = {}
            attr = misp.add_named_attribute(event, v['misp-type'], v['ioc'], 
                                                  category=v['misp-cat'], to_ids=v['misp-toids'], 
                                                  **ind_kwargs)
            #misp_data['debug']=attr
                        
            if 'response' in attr:
                attrib_uuid = attr['response']['Attribute']['uuid']
            elif 'message' in attr:
                kwargs = {'uuid': str(event['Event']['uuid'])}
                result = misp.search(controller='events', **kwargs)
                for evt in result['response']:
                    if evt['Event']['info']==event['Event']['info']:
                        event=evt
                        break
                single_attribute = (item for item in event['Event']['Attribute'] if item['value']==v['ioc'] 
                                and item['category']==v['misp-cat'] and item['type']==v['misp-type']).next()
                attrib_uuid = single_attribute['uuid']
            else: 
                v['tag']=''
                #misp_data['debug']=attr
            
            if v['tag']!='':
                for t in v['tag']:
                    t=t.strip()
                    misp.tag(attrib_uuid, t)
    
    return{
        'misp_data': misp_data,
        #'misp_configs': misp_configs,
        #'user': user,
        #'debug': debug_log,
    }

           
def add_campaign_from_nodes(name, confidence, nodes, user):
    result = { "success": False }

    # Make sure Campaign exists
    campaign_obj = Campaign.objects(name=name).first()
    if not campaign_obj:
        result["message"] = "Invalid campaign name."
        return result

    campaign = EmbeddedCampaign(name=name, confidence=confidence, analyst=user)

    counter = 0
    for node in nodes:
        id_ = node.get('id', None)
        type_ = node.get('type', None)

        # Must have type and id, and type must not be Campaign
        if not id_ or not type_ or type_.lower() == 'campaign':
            continue

        obj = class_from_id(type_, id_)
        if not obj:
            continue

        obj.add_campaign(campaign)
        obj.save()
        counter += 1

    result["message"] = "%s objects processed" % counter
    result["success"] = True
    return result
