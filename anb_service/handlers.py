from django.conf import settings
from crits.core.mongo_tools import mongo_connector
from crits.core.class_mapper import class_from_id
from crits.core.handlers import collect_objects
from crits.backdoors.backdoor import Backdoor
from crits.emails.email import Email
from crits.samples.sample import Sample
from crits.indicators.indicator import Indicator
from crits.ips.ip import IP
from crits.domains.domain import Domain
from crits.events.event import Event

def source_match(item_source, sources):
    for source in item_source:
        if source.name in sources:
            return True
    return False

def get_md5_objects(oid, sources, md5_list=[], x=0):
    obj_list = []
    s = class_from_id('Sample', oid)
    if not s:
        return obj_list

    if not source_match(s.source, sources):
        return obj_list

    md5_list.append(s.md5)

    for o in s.obj:
        if o.name in ['Domain Name', 'ipv4-addr', 'URL'] and source_match(o.source, sources):
            obj_list.append(o.value)
    for r in s.relationships:
        if r.rel_type == 'Sample':
            s2 = class_from_id('Sample', r.object_id)
            if not s2:
                continue

            if not source_match(s2.source, sources):
                continue

            if s2.md5 not in md5_list and x < 1:
                obj_list += get_md5_objects(r.object_id, sources, md5_list, x + 1)
    return obj_list

def get_sample_rels(rel, eid, sources):
    s_list = []
    for r in rel:
        if r.rel_type == 'Sample':
            s = class_from_id(r.rel_type, r.object_id)
            if not s:
                continue

            if not source_match(s.source, sources):
                continue

            obj_list = get_md5_objects(r.object_id, sources)
            # Walk the relationships on this sample, see if it is related to
            # a backdoor. Take the first backdoor that comes up, it may or
            # may not be the versioned one.
            backdoor_name = "None"
            for sample_r in s.relationships:
                if sample_r.rel_type == 'Backdoor':
                    backdoor = Backdoor.objects(id=sample_r.object_id).first()
                    if backdoor and source_match(backdoor.source, sources):
                        backdoor_name = backdoor.name
                        break
            s_list.append({
                'md5': s.md5,
                'email_id': eid,
                'mimetype': s.mimetype,
                'filename': s.filename,
                'backdoor': backdoor_name,
                'objects':  obj_list,
                })
    return s_list

# Given an event ID grab all related objects and generate CSV output for
# them. For each related object, repeat the process. Keep track of things
# we have seen before so we don't generate duplicate CSV entries.
def generate_anb_event_data(type_, cid, data, sources, r=0):
    related_objects = collect_objects(type_, cid, sources, depth=1)

    # Remove current object from the collected objects. The first time
    # through this function we will have already put the event in and
    # each subsequent run we will have just put another object in before
    # recursing back into this function.
    del related_objects[str(cid)]

    for (obj_id, (obj_type, level, obj)) in related_objects.iteritems():
        # If we've seen this object before, don't bother dealing with it.
        if obj_id in data['seen_objects']:
            continue

        data['seen_objects'][obj_id] = obj

        if obj_type == 'Email':
            data['emails'] += "%s,%s,%s,%s,%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.isodate,
                obj.sender,
                obj.subject,
                obj.x_originating_ip,
                obj.x_mailer)
        elif obj_type == 'Sample':
            backdoor = obj.backdoor
            if backdoor:
                backdoor_name = obj.backdoor.name
            else:
                backdoor_name = "None"
            data['samples'] += "%s,%s,%s,%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.md5,
                obj.mimetype,
                obj.filename,
                backdoor_name)
            for inner_obj in obj.obj:
                data['objects'] += "%s,%s,%s\r\n" % (
                    obj_id,
                    inner_obj.object_type,
                    inner_obj.value)
        elif obj_type == 'Indicator':
            data['indicators'] += "%s,%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.ind_type,
                obj.value)
        elif obj_type == 'IP':
            data['ips'] += "%s,%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.ip_type,
                obj.ip)
        elif obj_type == 'Domain':
            data['domains'] += "%s,%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.record_type,
                obj.domain)
        elif obj_type == 'Event':
            data['events'] += "%s,%s,%s\r\n" % (
                cid,
                obj_id,
                obj.title)
        # Recurse one more level, but go no further.
        if r < 1:
            generate_anb_event_data(obj_type, obj_id, data, sources, r=r + 1)
    return data

def execute_anb_event(cid, sources):
    # The inner dictionary is for keeping track of object IDs we have
    # already seen. The strings are for holding the CSV data.
    data = {
             'seen_objects': {},
             'emails': '',
             'samples': '',
             'objects': '',
             'events': '',
             'domains': '',
             'indicators': '',
             'ips': ''
           }

    crits_event = Event.objects(id=cid, source__name__in=sources).first()
    if not crits_event:
        return data

    # Pre-populate with our event.
    data['seen_objects'][str(crits_event.id)] = crits_event
    data['events'] += "%s,%s,%s\r\n" % (
        'None',
        crits_event.id,
        crits_event.title)

    generate_anb_event_data('Event', crits_event.id, data, sources)

    # No need to pass this back to the view.
    del data['seen_objects']

    return data

# Get every email in the campaign first, then walk each email looking for
# samples related to the email. Then get objects for those samples.
def execute_anb_campaign(cid, sources):
    data = {'emails': '', 'samples': '', 'objects': ''}

    email_list = Email.objects(campaign__name=cid, source__name__in=sources)
    if not email_list:
        return data

    md5_list = []

    for email in email_list:
        md5_list = get_sample_rels(email.relationships, str(email.id), sources)
        email.sanitize_sources(sources=sources)

        data['emails'] += "%s,%s,%s,%s,%s,%s,%s,%s\r\n" % (
            email.id,
            email.isodate,
            email.sender,
            email.subject,
            email.x_originating_ip,
            email.x_mailer,
            email.source[0].name,
            email.campaign[0].name)

        for m in md5_list:
            data['samples'] += "%s,%s,%s,%s,%s\r\n" % (
                m['email_id'],
                m['md5'],
                m['mimetype'],
                m['backdoor'],
                m['filename'])
            for o in m.get('objects', []):
                data['objects'] += "%s,%s\r\n" % (m['md5'], o)

    return data

def execute_anb(ctype, cid, sources):
    data = {
             'emails': '',
             'samples': '',
             'objects': ''
           }

    if ctype == 'Campaign':
        return execute_anb_campaign(cid, sources)
    elif ctype == 'Event':
        return execute_anb_event(cid, sources)
    else:
        return data
