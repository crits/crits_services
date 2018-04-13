from mongoengine import Document, StringField, ListField, BooleanField

from crits.core.crits_mongoengine import CritsDocument, CritsSchemaDocument
from crits.core.fields import CritsDateTimeField

from .migrate import migrate_taxii_content

class Taxii(CritsSchemaDocument, CritsDocument, Document):
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
        "auto_create_index": False,
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

class TaxiiContent(CritsSchemaDocument, CritsDocument, Document):
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
        "auto_create_index": False,
        "crits_type": 'TAXIIContent',
        "latest_schema_version": 2,
        #NOTE: minify_defaults fields should match the MongoEngine field names, NOT the database fields
        "minify_defaults": [
            'taxii_msg_id',
            'hostname',
            'use_hdr_src',
            'feed',
            'block_label',
            'poll_time',
            'timerange',
            'analyst',
            'content',
            'errors',
            'import_failed',
            'selected'
        ],
        "schema_doc": {
            'taxii_msg_id': 'A reference to the data (ID of the TAXII message)',
            'hostname': 'The source of the data (or TAXII server hostname)',
            'use_hdr_src': 'Indicates if STIX Header Info Source is preferred',
            'feed': 'Name of the TAXII feed/collection, or ZIP file name',
            'block_label': 'STIX filename, or when block submitted to TAXII server',
            'poll_time': 'When the data was polled or uploaded',
            'timerange': 'Timerange of the TAXII poll, or indication of upload',
            'analyst': 'The analyst who retrieved or provided the data',
            'content': 'The content being stored (STIX)',
            'errors': 'Errors that occurred while parsing or importing content',
            'import_failed': 'Boolean indicating that an attempt to import failed',
            'selected': 'Boolean indicating that the block is selected for import'
        },
    }

    taxii_msg_id = StringField(required=True)
    hostname = StringField(required=True)
    use_hdr_src = BooleanField(required=True, default=False)
    feed = StringField(required=True)
    block_label = StringField(required=True)
    poll_time = CritsDateTimeField(required=True)
    timerange = StringField(required=True)
    analyst = StringField(required=True)
    content = StringField(required=True)
    errors = ListField(StringField(required=True))
    import_failed = BooleanField(required=True, default=False)
    selected = BooleanField(required=True, default=True)

    def populate(self, data, analyst, message_id, hostname, feed, block_label,
                 begin=None, end=None, poll_time=None, use_hdr_src=False,
                 errors=[], selected=True):
        """
        Populate the class attributes

        :param data: The STIX content
        :type data: string
        :param analyst: The analyst who retrieved or provided the data
        :type analyst: string
        :param message_id: A reference to the data (ID of the TAXII message)
        :type message_id: string
        :param hostname: The source of the data (or TAXII server hostname)
        :type hostname: string
        :param feed: Name of the TAXII feed/collection, or ZIP file name
        :type feed: string
        :param block_label: Filename, or when block submitted to TAXII server
        :type block_label: string
        :param begin: Exclusive begin component of the timerange that was polled
        :type begin: :class:`datetime.datetime`
        :param end: Inclusive end component of the timerange that was polled
        :type end: :class:`datetime.datetime`
        :param poll_time: When the data was polled or uploaded
        :type poll_time: :class:`datetime.datetime`
        :param use_hdr_src: Indicates if STIX Header Info Source is preferred
        :type use_hdr_src: boolean
        :param errors: Errors that occurred while parsing or importing content
        :type errors: list
        :param selected: Boolean indicating that the block is selected for import
        :type selected: boolean
        """

        if data or errors:
            self.taxii_msg_id = message_id
            self.hostname = hostname
            self.use_hdr_src = use_hdr_src
            self.feed = feed
            self.block_label = block_label
            self.poll_time = poll_time or datetime.now()
            if end: # TAXII poll will always have end timestamp
                end = end.strftime('%Y-%m-%d %H:%M:%S')
                begin = begin.strftime('%Y-%m-%d %H:%M:%S') if begin else 'None'
                self.timerange = '%s to %s' % (begin, end)
            else: # Must be a STIX file upload
                self.timerange = 'STIX File Upload'
            self.analyst = analyst
            self.content = data or ""
            self.errors = errors
            self.import_failed = False
            self.selected = True

    def migrate(self):
        migrate_taxii_content(self)
