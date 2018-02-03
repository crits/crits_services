# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# Copyright (c) 2016, Adam Polkosnik, Team Cymru.  All rights reserved.

# Source code distributed pursuant to license agreement.
# PEhash computing code is from Team Cymru.
# Wrapping into the CRITs module done by Adam Polkosnik.

from __future__ import division

import pefile
import bitstring
import string
import bz2
import binascii
import hashlib
import logging
import struct
from time import localtime, strftime

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL

from . import forms

logger = logging.getLogger(__name__)


class PEInfoService(Service):
    """
    Extract metadata about Windows PE/COFF files.

    Leverages a combination of pefile python module and some custom code
    to parse the structures of a PE/COFF binary and extract metadata about
    its sections, imports, exports, debug information and timestamps.
    """

    name = "peinfo"
    version = '1.1.5'
    supported_types = ['Sample']
    description = "Generate metadata about Windows PE/COFF files."
    added_files = []

    @staticmethod
    def valid_for(obj):
        # Only run on PE files
        if not obj.is_pe():
            raise ServiceConfigError("Not a PE.")

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'resource' not in config:
            config['resource'] = False
        return forms.PEInfoRunForm(config)

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        return render_to_string('services_run_form.html',
                                {'name': self.name,
                                 'form': forms.PEInfoRunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})

    @staticmethod
    def get_config(existing_config):
        # There are no config options for this service, blow away any existing
        # configs.
        return {}

    def _get_pehash(self, exe):
        #image characteristics
        img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
        #pad to 16 bits
        if len(img_chars) == 8:
            img_chars = bitstring.BitArray('0b00000000') + img_chars
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

        #start to build pehash
        pehash_bin = bitstring.BitArray(img_chars_xor)

        #subsystem -
        sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
        #pad to 16 bits
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
        pehash_bin.append(sub_chars_xor)

        #Stack Commit Size
        stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        #now xor the bits
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
        #pad to 8 bits
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        #Heap Commit Size
        hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        #now xor the bits
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
        #pad to 8 bits
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        #Section chars
        for section in exe.sections:
            #virutal address
            sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            pehash_bin.append(sect_va)

            #rawsize
            sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:31]
            pehash_bin.append(sect_rs_bits)

            #section chars
            sect_chars =  bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
            pehash_bin.append(sect_chars_xor)

            #entropy calulation
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.write()[address+size:]
            if size == 0:
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:7])
                continue
            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            #k = round(bz2_size / size, 5)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:7])

        m = hashlib.sha1()
        m.update(pehash_bin.tobytes())
        output = m.hexdigest()
        self._add_result('PEhash value', "%s" % output, {'Value': output})

    def run(self, obj, config):
        try:
            self._debug("Version: %s" % pefile.__version__ )
            pe = pefile.PE(data=obj.filedata.read())
        except pefile.PEFormatError as e:
            self._error("A PEFormatError occurred: %s" % e)
            return
        self._get_sections(pe)
        self._get_pehash(pe)

        user = self.current_task.user

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            self._dump_resource_data("ROOT",
                                     pe.DIRECTORY_ENTRY_RESOURCE,
                                     pe,
                                     config['resource'])
            if user.has_access_to(SampleACL.WRITE):
                for f in self.added_files:
                    handle_file(f[0], f[1], obj.source,
                                related_id=str(obj.id),
                                related_type=str(obj._meta['crits_type']),
                                campaign=obj.campaign,
                                source_method=self.name,
                                relationship=RelationshipTypes.CONTAINED_WITHIN,
                                user=user)
                    rsrc_md5 = hashlib.md5(f[1]).hexdigest()
                    self._add_result("file_added", f[0], {'md5': rsrc_md5})
        else:
            self._debug("No resources")

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            self._get_imports(pe)
        else:
            self._debug("No imports")

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            self._get_exports(pe)
        else:
            self._debug("No exports")

        if hasattr(pe, 'VS_VERSIONINFO'):
            self._get_version_info(pe)
        else:
            self._debug("No Version information")

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            self._get_debug_info(pe)
        else:
            self._debug("No debug info")

        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            self._get_tls_info(pe)
        else:
            self._debug("No TLS info")

        if callable(getattr(pe, 'get_imphash', None)):
            self._get_imphash(pe)
        else:
            self._debug("pefile does not support get_imphash, upgrade to 1.2.10-139")

        self._get_timestamp(pe)
        self._get_rich_header(pe)

    # http://www.ntcore.com/files/richsign.htm
    def _get_rich_header(self, pe):
        rich_hdr = pe.parse_rich_header()
        if not rich_hdr:
            return
        data = {"raw": str(rich_hdr['values'])}
        self._add_result('rich_header', hex(rich_hdr['checksum']), data)

        # Generate a signature of the block. Need to apply checksum
        # appropriately. The hash here is sha256 because others are using
        # that here.
        #
        # Most of this code was taken from pefile but modified to work
        # on the start and checksum blocks.
        try:
            rich_data = pe.get_data(0x80, 0x80)
            if len(rich_data) != 0x80:
                return None
            data = list(struct.unpack("<32I", rich_data))
        except pefile.PEFormatError as e:
            return None

        checksum = data[1]
        headervalues = []

        for i in xrange(len(data) // 2):
            if data[2 * i] == 0x68636952: # Rich
                if data[2 * i + 1] != checksum:
                    self._parse_error('Rich Header corrupted', Exception)
                break
            headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]

        sha_256 = hashlib.sha256()
        for hv in headervalues:
            sha_256.update(struct.pack('<I', hv))
        self._add_result('rich_header', sha_256.hexdigest(), None)

    def _get_imphash(self, pe):
        imphash = pe.get_imphash()
        self._add_result('imphash', imphash, {'import_hash': imphash})

    def _dump_resource_data(self, name, dir, pe, save):
        for i in dir.entries:
            try:
                if hasattr(i, 'data'):
                    x = i.data
                    rva = x.struct.OffsetToData
                    rname = "%s_%s_%s" % (name, i.name, x.struct.name)
                    size = x.struct.Size
                    data = pe.get_memory_mapped_image()[rva:rva + size]
                    if not data:
                        data = ""
                    if len(data) > 0:
                        if (save or data[:2] == 'MZ' or data[:4] == "%%PDF"):
                            self._debug("Adding new file from resource len %d - %s" % (len(data), rname))
                            self.added_files.append((rname, data))
                    results = {
                            "resource_type": x.struct.name.decode('UTF-8', errors='replace') ,
                            "resource_id": i.id,
                            "language": x.lang,
                            "sub_language": x.sublang,
                            "address": hex(x.struct.OffsetToData),
                            "size": len(data),
                            "md5": hashlib.md5(data).hexdigest(),
                    }
                    self._debug("Adding result for resource %s" % i.name)
                    self._add_result('pe_resource', x.struct.name, results)
                if hasattr(i, "directory"):
                    self._debug("Parsing next directory entry %s" % i.name)
                    self._dump_resource_data(name + "_%s" % i.name,
                                             i.directory, pe, save)
            except Exception as e:
                self._parse_error("Resource directory entry", e)

    def _get_sections(self, pe):
        for section in pe.sections:
            try:
                section_name = section.Name.decode('UTF-8', errors='replace')
                if section_name == "":
                    section_name = "NULL"
                data = {
                        "virt_address": hex(section.VirtualAddress),
                        "virt_size": section.Misc_VirtualSize,
                        "size": section.SizeOfRawData,
                        "md5": section.get_hash_md5(),
                        "entropy": section.get_entropy(),
                }
                self._add_result('pe_section', section_name, data)
            except Exception as e:
                self._parse_error("section info", e)
                continue

    def _get_imports(self, pe):
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name
                    else:
                        name = "%s#%s" % (entry.dll, imp.ordinal)
                    data = {
                            "dll": "%s" % entry.dll,
                            "ordinal": "%s" % imp.ordinal,
                    }
                    self._debug("import_data: '%s'" % data )
                    self._add_result('pe_import', name, data)
        except Exception as e:
            self._parse_error("imports", e)

    def _get_exports(self, pe):
        try:
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                data = {"rva_offset": hex(pe.OPTIONAL_HEADER.ImageBase
                                        + entry.address)}
                ename = 'NULL'
                if entry.name:
                    ename = entry.name
                self._add_result('pe_export', ename, data)
        except Exception as e:
            self._parse_error("exports", e)

    def _get_timestamp(self, pe):
        try:
            timestamp = pe.FILE_HEADER.TimeDateStamp
            time_string = strftime('%Y-%m-%d %H:%M:%S', localtime(timestamp))
            data = {"raw": timestamp}
            self._add_result('pe_timestamp', time_string, data)
        except Exception as e:
            self._parse_error("timestamp", e)

    def _get_debug_info(self, pe):
        # woe is pefile when it comes to debug entries
        # we're mostly interested in codeview stuctures, namely NB10 and RSDS
        try:
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                dbg_path = ""
                if hasattr(dbg.struct, "Type"):
                    result = {
                         'MajorVersion': dbg.struct.MajorVersion,
                         'MinorVersion': dbg.struct.MinorVersion,
                         'PointerToRawData': hex(dbg.struct.PointerToRawData),
                         'SizeOfData': dbg.struct.SizeOfData,
                         'TimeDateStamp': dbg.struct.TimeDateStamp,
                         'TimeDateString': strftime('%Y-%m-%d %H:%M:%S', localtime(dbg.struct.TimeDateStamp)),
                         'Type': dbg.struct.Type,
                         'subtype': 'pe_debug',
                    }
                    # type 0x2 is codeview, though not any specific version
                    # for other types we don't parse them yet
                    # but sounds like a great project for an enterprising CRITs coder...
                    if dbg.struct.Type == 0x2:
                        debug_offset = dbg.struct.PointerToRawData
                        debug_size = dbg.struct.SizeOfData
                        # ok, this probably isn't right, fix me
                        if debug_size < 0x200 and debug_size > 0:
                            # there might be a better way than __data__ in pefile to get the raw data
                            # i think that get_data uses RVA's, which this requires physical address
                            debug_data = pe.__data__[debug_offset:debug_offset + debug_size]
                            # now we need to check the codeview version,
                            # http://www.debuginfo.com/articles/debuginfomatch.html
                            # as far as I can tell the gold is in RSDS and NB10
                            if debug_data[:4] == "RSDS":
                                result.update({
                                    'DebugSig': debug_data[0x00:0x04],
                                    'DebugGUID': binascii.hexlify(debug_data[0x04:0x14]),
                                    'DebugAge': struct.unpack('I', debug_data[0x14:0x18])[0],
                                })
                                if dbg.struct.SizeOfData > 0x18:
                                    dbg_path = debug_data[0x18:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                    result.update({
                                        'DebugPath': "%s" % dbg_path,
                                        'result': "%s" % dbg_path,
                                    })
                            if debug_data[:4] == "NB10":
                                result.update({
                                    'DebugSig': debug_data[0x00:0x04],
                                    'DebugTime': struct.unpack('I', debug_data[0x08:0x0c])[0],
                                    'DebugAge': struct.unpack('I', debug_data[0x0c:0x10])[0],
                                })
                                if dbg.struct.SizeOfData > 0x10:
                                    dbg_path = debug_data[0x10:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                    result.update({
                                        'DebugPath': "%s" % dbg_path,
                                        'result': "%s" % dbg_path,
                                    })
                self._add_result('pe_debug', dbg_path, result)
        except Exception as e:
            self._parse_error("could not extract debug info", e)

    def _get_version_info(self, pe):
        if hasattr(pe, 'FileInfo'):
            try:
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                try:
                                    value = str_entry[1].encode('ascii')
                                    result = {
                                        'key':      str_entry[0],
                                        'value':    value,
                                    }
                                except:
                                    value = str_entry[1].encode('ascii', errors='ignore')
                                    raw = binascii.hexlify(str_entry[1].encode('utf-8'))
                                    result = {
                                        'key':      str_entry[0],
                                        'value':    value,
                                        'raw':      raw,
                                    }
                                result_name = str_entry[0] + ': ' + value[:255]
                                self._add_result('version_info', result_name, result)
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                for key in var_entry.entry.keys():
                                    try:
                                        value = var_entry.entry[key].encode('ascii')
                                        result = {
                                            'key':      key,
                                            'value':    value,
                                        }
                                    except:
                                        value = var_entry.entry[key].encode('ascii', errors='ignore')
                                        raw = binascii.hexlify(var_entry.entry[key])
                                        result = {
                                            'key':      key,
                                            'value':    value,
                                            'raw':      raw,
                                        }
                                    result_name = key + ': ' + value
                                    self._add_result('version_var', result_name, result)
            except Exception as e:
                self._parse_error("version info", e)

    def _get_tls_info(self, pe):
        self._info("TLS callback table listed at 0x%08x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

        # read the array of TLS callbacks until we hit a NULL ptr (end of array)
        idx = 0
        callback_functions = [ ]
        while pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0):
            callback_functions.append(pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0))
            idx += 1

        # if we start with a NULL ptr, then there are no callback functions
        if idx == 0:
            self._info("No TLS callback functions supported")
        else:
            for idx, va in enumerate(callback_functions):
                va_string = "0x%08x" % va
                self._info("TLS callback function at %s" % va_string)
                data = { 'Callback Function': idx }
                self._add_result('tls_callback', va_string, data)

    def _parse_error(self, item, e):
        self._error("Error parsing %s (%s): %s" % (item, e.__class__.__name__, e))
