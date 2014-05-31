from mongoengine import Document, StringField, IntField, ObjectIdField

from crits.core.crits_mongoengine import CritsDocument
from crits.core.fields import CritsDateTimeField

class SnuggleIndex(CritsDocument, Document):
    """Snugglefish Index Document Object"""
    meta = {
        "collection": 'snugglefish_indexes',
        "crits_type": 'snugglefish_index',
        "latest_schema_version": 1,
        "schema_doc": {
            'name': "Name of this index",
            'name': "Directory where this index lives",
            'query': "Query for this index",
            'created': "Date this index was created",
            'last_update': "Date this index was last updated",
            'last_id': "Last object ID fetched for this index",
            'total': "Total number of objects available for this index",
            'count': "Total number of objects fetched for this index"
        },
    }

    name = StringField(required=True)
    directory = StringField(required=True)
    query = StringField(required=True)
    created = CritsDateTimeField(required=True)
    last_update = CritsDateTimeField()
    last_id = ObjectIdField()
    total = IntField(default=0)
    count = IntField(default=0)

    def migrate(self):
        pass
