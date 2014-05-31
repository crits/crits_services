from mongoengine import Document

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
            'end'
        ],
        "schema_doc": {
            'runtime': 'The last time we made a TAXII request.',
            'end': 'End date of this taxii document.'
        },
    }

    runtime = CritsDateTimeField(required=True)
    end = CritsDateTimeField(required=True)

    def migrate(self):
        pass

    @classmethod
    def get_last(cls):
        return cls.objects.order_by('-end').first()
