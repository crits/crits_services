from tastypie import authorization
from tastypie.exceptions import BadRequest
from tastypie.authentication import MultiAuthentication
from mongoengine import Document, ListField, DynamicField, DictField

from django.conf import settings

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource
from crits.core.crits_mongoengine import CritsDocument

from . import handlers


# The use of GraphObject was inspired by:
# http://michalcodes4life.wordpress.com/2013/11/26/custom-tastypie-resource-from-multiple-django-models/

class GraphObject(CritsDocument, Document):
    """
    Class to store the returned data. Since the data being requested is not a
    mongoengine object we use this to store the results so it can be understood
    by tastypie.
    """

    nodes = ListField(DynamicField(DictField))
    links = ListField(DynamicField(DictField))

class RelationshipsServiceResource(CRITsAPIResource):
    """
    Class to handle everything related to the Relationships Service API.

    Currently supports GET.
    """

    class Meta:
        object_class = GraphObject
        allowed_methods = ('get',)
        resource_name = 'relationshipsservice'
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()

    def obj_get_list(self, request=None, **kwargs):
        # you have to do this if you want to use request in get_object_list
        if not request:
            request = kwargs['bundle'].request
        return self.get_object_list(request)

    def get_object_list(self, request):
        """
        Expose the objects generated in the Relationships Service via an API.

        :param request: The incoming request.
        :type request: :class:`django.http.HttpRequest`
        :returns: Resulting objects in the specified format (JSON by default).
        """

        ctype = request.GET.get('ctype', None)
        cid = request.GET.get('cid', None)
        depth = request.GET.get('depth', 3)
        types = request.GET.get('types', '')

        # If the user specifies no types, be generous.
        if types:
            types = types.split(',')
        else:
            types = settings.CRITS_TYPES.keys()

        if not ctype:
            raise BadRequest("Must specify CRITs type (ctype).")
        if not cid:
            raise BadRequest("Must specify CRITs id (cid).")

        username = request.user.username
        rels = handlers.gather_relationships(ctype, cid, username, depth, types)
        gobj = GraphObject()
        gobj.nodes = rels['nodes']
        gobj.links = rels['links']
        return [gobj]
