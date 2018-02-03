import struct
import hashlib

from crits.services.core import Service, ServiceConfigError
from crits.certificates.handlers import handle_cert_file
from crits.vocabulary.relationships import RelationshipTypes

from machoinfo import MachOEntity, MachOParser, MachOParserError

class MachOInfoService(Service):
    name = "machoinfo"
    version = '0.0.1'
    supported_types = ['Sample']
    description = "Generate metadata about Mach-O binaries."

    @staticmethod
    def valid_for(obj):
        if obj.filedata.grid_id == None:
            raise ServiceConfigError("Missing filedata.")

        data = obj.filedata.read()
        if len(data) < 4:
            raise ServiceConfigError("Need at least 4 bytes.")

        # Reset the read pointer.
        obj.filedata.seek(0)

        if not struct.unpack('@I', data[:4])[0] in [ MachOEntity.FAT_MAGIC,
                                                     MachOEntity.FAT_CIGAM,
                                                     MachOEntity.MH_MAGIC,
                                                     MachOEntity.MH_CIGAM,
                                                     MachOEntity.MH_MAGIC_64,
                                                     MachOEntity.MH_CIGAM_64 ]:
            raise ServiceConfigError("Bad magic.")

    def run(self, obj, config):
        data = obj.filedata.read()
        mop = MachOParser(data)
        try:
            mop.parse()
        except MachOParserError, e:
            self._error("ERROR: %s" % e)
            return

        i = 0
        for entity in mop.entities:
            result = {
                       'entity':        i,
                       'sub_files':     entity.nfat,
                       'cpu_type':      entity.cpu_type_str,
                       'cpu_subtype':   entity.cpu_subtype_str,
                       'filetype':      entity.filetype_str,
                       'flaglist':      ', '.join(entity.flaglist),
                       'commands':      len(entity.cmdlist)
                     }
            entity_string = "%s %s %s" % (entity.magic_str, entity.cpu_type_str, entity.cpu_subtype_str)
            self._add_result('Headers', entity_string, result)
            i += 1

        i = 0
        for entity in mop.entities:
            if entity.is_universal():
                i += 1
                continue # Nothing more to print for universal files
            for cmd in entity.cmdlist:
                self._add_result('Entity %i - Commands' % i, entity.cmd_name(cmd['cmd']), {})
            i += 1

        i = 0
        for entity in mop.entities:
            if entity.is_universal():
                i += 1
                continue # Nothing more to print for universal files

            # first let's do "imports"
            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_LOAD_DYLINKER:
                    self._add_result('Entity %i - %s' % (i, entity.cmd_name(cmd['cmd'])), cmd['dylinker'], {})

            for cmd in entity.cmdlist:
                if cmd['cmd'] in [MachOEntity.LC_LOAD_DYLIB, MachOEntity.LC_ID_DYLIB]:
                    result = {
                        'timestamp':        cmd.get('timestamp', ''),
                        'current_version':  cmd.get('cv', ''),
                        'compat_version':   cmd.get('cpv'),
                    }
                    self._add_result('Entity %i - %s' % (i, entity.cmd_name(cmd['cmd'])), cmd.get('dylib', ''), result)

            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_CODE_SIGNATURE:
                    e = 'Entity %i - %s' % (i, entity.cmd_name(cmd['cmd']))
                    for sig in cmd.get('signatures', []):
                        if sig['type'] == MachOEntity.CODE_DIRECTORY:
                            result = {
                                'ver':          sig['ver'],
                                'identifier':   sig['identifier'],
                                'hashtype':     sig['hashtype'],
                            }
                            self._add_result(e, sig['hash'], result)
                        elif sig['type'] == MachOEntity.CERT_BLOB:
                            data = sig['pkcs7']
                            filename = hashlib.md5(data).hexdigest()
                            handle_cert_file(filename, data, obj.source,
                                             related_id=str(obj.id),
                                             related_type=str(obj._meta['crits_type']),
                                             method=self.name,
                                             relationship=RelationshipTypes.CONTAINED_WITHIN,
                                             user=self.current_task.user)
                            self._add_result("cert_added", filename, {'md5': filename})

            e = 'Entity %i - Version Info' % i
            result = {}
            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_UUID:
                    result['uuid'] = cmd['uuid']
                elif cmd['cmd'] in [MachOEntity.LC_VERSION_MIN_MACOSX, MachOEntity.LC_VERSION_MIN_IPHONEOS]:
                    result['os_ver'] = cmd['ver']
                    result['sdk_ver'] = cmd['sdk']
                elif cmd['cmd'] == MachOEntity.LC_SOURCE_VERSION:
                    result['source_version'] = cmd['ver']
            if result:
                self._add_result(e, result['uuid'], result)

            e = 'Entity %i - Segments' % i
            j = 0
            segment_list = []
            for cmd in entity.cmdlist:
                if cmd['cmd'] in [MachOEntity.LC_SEGMENT, MachOEntity.LC_SEGMENT_64]:
                    segname = cmd['segname']
                    if not segname:
                        segname = "NO_NAME"
                    result = {
                        'segname':      segname,
                        'filesize':     cmd['filesize'],
                        'vmsize':       cmd['vmsize'],
                        'num_sections': len(cmd['sectlist'])
                    }
                    segment_list.append(result)
                    for sect in cmd['sectlist']:
                        result = {
                            'md5':          sect['md5'],
                            'addr':         sect['addr'],
                            'type':         sect['type'],
                            'size':         sect['size'],
                            'offset':       sect['offset'],
                            'flaglist':     ', '.join(sect['flaglist'])
                        }
                        self._add_result(e + ' section %i' % j, sect['sectname'], result)
                    j += 1
            for result in segment_list:
                self._add_result(e, '%s - %i' % (result['segname'], result['num_sections']), result)

            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_SYMTAB:
                    for sym in cmd['symbols']:
                        result = {
                            'Stab type': sym.get('stab_type', 'Not stab'),
                            'Limited Global Scope': sym.get('limited_global_scope', 'Not set'),
                            'Type': sym.get('n_type', 'Not set'),
                            'External': sym.get('External', 'Not set'),
                        }
                        self._add_result('Entity %i - %s' % (i, entity.cmd_name(cmd['cmd'])), sym.get('string', ''), result)

            i += 1
