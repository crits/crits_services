def migrate_taxii_content(self):
    """
    Migrate to the latest schema version.
    """

    migrate_1_to_2(self)

def migrate_1_to_2(self):
    """
    Migrate from schema 1 to 2.
    """

    if self.schema_version < 1:
        migrate_0_to_1(self)

    if self.schema_version == 1:
        if self.unsupported_attrs:
            if self.unsupported_attrs.timestamp:
                ts = self.unsupported_attrs.timestamp
                self.block_label = ts.strftime('%Y-%m-%d %H:%M:%S')
                del self.unsupported_attrs.timestamp
                if not self.unsupported_attrs.to_dict():
                    del self.unsupported_attrs
        self.schema_version = 2
        self.save()

def migrate_0_to_1(self):
    """
    Migrate from schema 0 to 1.
    """

    if self.schema_version < 1:
        self.schema_version = 1
