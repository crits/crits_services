from django.core.urlresolvers import reverse

import pprint
import binascii

from crits.samples.sample import Sample
from crits.core.user_tools import user_sources
from crits.core.class_mapper import class_from_type, class_from_id


def gather_relationships(obj_type, obj_id, user, depth):
    objects = {}
    nodes = []
    
    sources = user_sources(user)
    
    field_dict = {
        'Actor': 'name',
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
        'Sample': 'filename',
        'Target': 'email_address'
    }
    
    if not sources:
        return 
    #if not depth:
    #    depth = 1    
    def inner_collect(obj_type, obj_id, sources, depth):
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
            #if r.rel_type=='Sample':
            inner_collect(r.rel_type, str(r.object_id), sources, depth)
                
        #END OF INNER COLLECT
        
    inner_collect(obj_type, str(obj_id), sources, depth)
    
    for (obj_id, obj) in objects.iteritems():
        obj_type = obj._meta['crits_type']
        #if obj_type == 'Sample':
        value = getattr(obj, field_dict[obj_type], '')
        href = reverse('crits.core.views.details', args=(obj_type, obj_id))
        
        n = {
              'label': '%s' % value,
              'url': href,
              'id': obj_id,
              'type': obj_type
        }
        
        if n['type']=="Sample":
            nodes.append(n)
        
    
    #print objects
    #return obj
    #return objects
    return nodes
    #END OF GATHER RELATIONSHIPS

def execute_yargen(relatedSamples, user):
	scount = 0
	yargen_array = {}
	critsMessage = ""
	
	#critsMessage = str(relatedSamples)
	#response = {"success": True, "message": critsMessage}
	#return response
	
	message = {}
	for key, val in relatedSamples.iteritems():
		newkey = key.replace(']','')
		newkeylist = newkey.split('[')
		keyCheck = message.get(int(newkeylist[1]), 'none')
		if keyCheck=='none':
			message[int(newkeylist[1])]={}
		message[int(newkeylist[1])][str(newkeylist[2])]=str(val)
		
	#critsMessage = str(message)
	#response = {"success": True, "message": critsMessage}
	#return response
		
	for sample in message:
		#critsMessage+="\r\nsample [id] - "
		#critsMessage+=str(message[sample]['id'])
		yargen_array[scount]={}
		#yargen_array[scount]['id'] = sample.id
		yargen_array[scount]['id'] = message[sample]['id']
		#yargen_array[scount]['filename'] = sample.label
		yargen_array[scount]['filename'] = message[sample]['label']
		#klass = class_from_id(sample.type, sample.id)
		#klass = class_from_id(message[sample]['type'], message[sample]['id'])
		klass = class_from_type(message[sample]['type'])
		#obj = klass.objects(id=sample.id).first()
		obj = klass.objects(id=message[sample]['id']).first()
		filedata = obj.filedata.read()
		yargen_array[scount]['filedata'] = filedata
		
		#critsMessage+="-----FILE------\r\n"
		#critsMessage+=filedata
		#critsMessage+="\r\n-------END FILE------\r\n"
		
		yargen_array[scount]['size'] = getattr(obj, 'size', '')
		scount += 1
	
	import yarGen
	
	critsMessage = yarGen.runMain(yargen_array, critsMessage)
	response = {"success": True, "message": critsMessage}
	return response
