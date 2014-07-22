from tastypie import authorization
from tastypie.authentication import MultiAuthentication
from mongoengine import Document

from crits.core.api import CRITsApiKeyAuthentication, CRITsSessionAuthentication
from crits.core.api import CRITsSerializer, CRITsAPIResource

from crits.samples.sample import Sample
from . import handlers


class BucketObject(Document):
    """
    XXX: FINISH THIS!
    """

    stuff = ListField(StringField())

class RelationshipsServiceResource(CRITsAPIResource):
    """
    Class to handle everything related to the Relationships Service API.

    Currently supports GET.
    """

    class Meta:
        print "META"
        object_class = BucketObject
        allowed_methods = ('get',)
        resource_name = 'relationshipsservice'
        authentication = MultiAuthentication(CRITsApiKeyAuthentication(),
                                             CRITsSessionAuthentication())
        authorization = authorization.Authorization()
        serializer = CRITsSerializer()
        print "DONE"

    def obj_get_list(self, request=None, **kwargs):
        print "OBJ GET LIST"
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

        print "GET OBJECT LIST"
        #foo = handlers.gather_relationships('Sample', '53cdd9e4d6fa25b059c54ddc', request.user.username, 1, [])
        #print foo
        x = BucketObject()
        x.stuff = 'foo'
        return [x]
