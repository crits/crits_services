from mongoengine import Document, StringField, ListField, BooleanField

from crits.core.crits_mongoengine import CritsDocument
from crits.core.fields import CritsDateTimeField

class Taxii(CritsDocument, Document):
    """TAXII Document Object"""
    meta = {
        # mongoengine adds fields _cls and _types and uses them to filter database
        # responses unless you disallow inheritance. In other words, we
        # can't see any of our old data unless we add _cls and _types
        # attributes to them or turn off inheritance.
        #So we'll turn inheritance off.
        # (See http://mongoengine-odm.readthedocs.org/en/latest/guide/defining-documents.html#working-with-existing-data)
        "allow_inheritance": False,
        "collection": 'taxii',
        "crits_type": 'TAXII',
        "latest_schema_version": 1,
        #NOTE: minify_defaults fields should match the MongoEngine field names, NOT the database fields
        "minify_defaults": [
            'runtime',
            'end',
            'feed'
        ],
        "schema_doc": {
            'runtime': 'The last time we made a TAXII request.',
            'end': 'End date of this taxii document.',
            'feed': 'The hostname:feed data was pulled from'
        },
    }

    runtime = CritsDateTimeField(required=True)
    end = CritsDateTimeField(required=True)
    feed = StringField(required=True)

    def migrate(self):
        pass

    @classmethod
    def get_last(cls, feed):
        return cls.objects(feed=feed).order_by('-end').first()

class TaxiiContent(CritsDocument, Document):
    """TAXII Content Block Document Object"""
    meta = {
        # mongoengine adds fields _cls and _types and uses them to filter database
        # responses unless you disallow inheritance. In other words, we
        # can't see any of our old data unless we add _cls and _types
        # attributes to them or turn off inheritance.
        #So we'll turn inheritance off.
        # (See http://mongoengine-odm.readthedocs.org/en/latest/guide/defining-documents.html#working-with-existing-data)
        "allow_inheritance": False,
        "collection": 'taxii.content',
        "crits_type": 'TAXIIContent',
        "latest_schema_version": 1,
        #NOTE: minify_defaults fields should match the MongoEngine field names, NOT the database fields
        "minify_defaults": [
            'taxii_msg_id',
            'hostname',
            'feed',
            'timestamp',
            'poll_time',
            'timerange',
            'analyst',
            'content',
            'errors',
            'import_failed'
        ],
        "schema_doc": {
            'taxii_msg_id': 'The ID of the TAXII message from which this content came',
            'hostname': 'The hostname of the TAXII server',
            'feed': 'The name of the TAXII feed/collection',
            'timestamp': 'When the content was submitted to the TAXII server',
            'poll_time': 'A timestamp representing when this data was polled',
            'timerange': 'The timerange of the TAXII poll',
            'analyst': 'The analyst who polled the data',
            'content': 'The content being stored',
            'errors': 'Any errors that prevented import of the content',
            'import_failed': 'Boolean indicating that an attempt to import failed'
        },
    }

    taxii_msg_id = StringField(required=True)
    hostname = StringField(required=True)
    feed = StringField(required=True)
    timestamp = CritsDateTimeField(required=True)
    poll_time = CritsDateTimeField(required=True)
    timerange = StringField(required=True)
    analyst = StringField(required=True)
    content = StringField(required=True)
    errors = ListField(StringField(required=True))
    import_failed = BooleanField(required=True, default=False)

    def migrate(self):
        pass
