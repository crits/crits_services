# These are useful to read and understand:
#
# http://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Mach-O_File_Format.pdf
#
# Various header files, especially:
#
# /usr/include/mach-o/loader.h
# /usr/include/mach-o/fat.h
# /usr/include/mach/machine.h

# XXX: There are a lot of comments indicating we should check we aren't
# parsing past the end of a slice. These should all be fixed. ;)

import struct
import binascii
from hashlib import md5
from datetime import datetime

class MachOParserError(Exception):
    pass

class MachOEntity(object):
    # Magic values
    FAT_MAGIC   = 0xCAFEBABE
    FAT_CIGAM   = 0xBEBAFECA
    MH_MAGIC    = 0xFEEDFACE
    MH_CIGAM    = 0xCEFAEDFE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE

    # CPU Types (not complete)
    CPU_ARCH_ABI64     = 0x01000000
    CPU_TYPE_POWERPC   = 0x00000012
    CPU_TYPE_X86       = 0x00000007
    CPU_TYPE_ARM       = 0x0000000C
    CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
    CPU_TYPE_X86_64    = CPU_TYPE_X86 | CPU_ARCH_ABI64

    # CPU Subtypes (not complete)
    CPU_SUBTYPE_MASK         = 0xFF000000
    CPU_SUBTYPE_POWERPC_ALL  = 0x00000000
    CPU_SUBTYPE_POWERPC_7400 = 0x0000000A
    CPU_SUBTYPE_POWERPC_7450 = 0x0000000B
    CPU_SUBTYPE_I386_ALL     = 0x00000003
    CPU_SUBTYPE_ARM_ALL      = 0x00000000
    CPU_SUBTYPE_ARM_V4T      = 0x00000005
    CPU_SUBTYPE_ARM_V6       = 0x00000006
    CPU_SUBTYPE_ARM_V5TEJ    = 0x00000007
    CPU_SUBTYPE_ARM_XSCALE   = 0x00000008
    CPU_SUBTYPE_ARM_V7       = 0x00000009
    CPU_SUBTYPE_ARM_V7F      = 0x0000000A
    CPU_SUBTYPE_ARM_V7K      = 0x0000000C

    # Filetype
    MH_OBJECT      = 0x00000001
    MH_EXECUTE     = 0x00000002
    MH_FVMLIB      = 0x00000003
    MH_CORE        = 0x00000004
    MH_PRELOAD     = 0x00000005
    MH_DYLIB       = 0x00000006
    MH_DYLINKER    = 0x00000007
    MH_BUNDLE      = 0x00000008
    MH_DYLIB_STUB  = 0x00000009
    MH_DSYM        = 0x0000000A
    MH_KEXT_BUNDLE = 0x0000000B

    # Flags
    MH_NOUNDEFS                = 0x00000001
    MH_INCRLINK                = 0x00000002
    MH_DYLDLINK                = 0x00000004
    MH_BINDATLOAD              = 0x00000008
    MH_PREBOUND                = 0x00000010
    MH_SPLIT_SEGS              = 0x00000020
    MH_LAZY_INIT               = 0x00000040
    MH_TWOLEVEL                = 0x00000080
    MH_FORCE_FLAT              = 0x00000100
    MH_NOMULTIDEFS             = 0x00000200
    MH_NOFIXPREBINDING         = 0x00000400
    MH_PREBINDABLE             = 0x00000800
    MH_ALLMODSBOUND            = 0x00001000
    MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
    MH_CANONICAL               = 0x00004000
    MH_WEAK_DEFINES            = 0x00008000
    MH_BINDS_TO_WEAK           = 0x00010000
    MH_ALLOW_STACK_EXECUTION   = 0x00020000
    MH_ROOT_SAFE               = 0x00040000
    MH_SETUID_SAFE             = 0x00080000
    MH_NO_REEXPORTED_DYLIBS    = 0x00100000
    MH_PIE                     = 0x00200000
    MH_DEAD_STRIPPABLE_DYLIB   = 0x00400000
    MH_HAS_TLV_DESCRIPTORS     = 0x00800000
    MH_NO_HEAP_EXECUTION       = 0x01000000

    # Commands
    LC_REQ_DYLD             = 0x80000000
    LC_SEGMENT              = 0x00000001
    LC_SYMTAB               = 0x00000002
    LC_SYMSEG               = 0x00000003
    LC_THREAD               = 0x00000004
    LC_UNIXTHREAD           = 0x00000005
    LC_LOADFVMLIB           = 0x00000006
    LC_IDFVMLIB             = 0x00000007
    LC_IDENT                = 0x00000008
    LC_FVMFILE              = 0x00000009
    LC_PREPAGE              = 0x0000000A
    LC_DYSYMTAB             = 0x0000000B
    LC_LOAD_DYLIB           = 0x0000000C
    LC_ID_DYLIB             = 0x0000000D
    LC_LOAD_DYLINKER        = 0x0000000E
    LC_ID_DYLINKER          = 0x0000000F
    LC_PREBOUND_DYLIB       = 0x00000010
    LC_ROUTINES             = 0x00000011
    LC_SUB_FRAMEWORK        = 0x00000012
    LC_SUB_UMBRELLA         = 0x00000013
    LC_SUB_CLIENT           = 0x00000014
    LC_SUB_LIBRARY          = 0x00000015
    LC_TWOLEVEL_HINTS       = 0x00000016
    LC_PREBIND_CKSUM        = 0x00000017
    LC_LOAD_WEAK_DYLIB      = 0x00000018 | LC_REQ_DYLD
    LC_SEGMENT_64           = 0x00000019
    LC_ROUTINES_64          = 0x0000001A
    LC_UUID                 = 0x0000001B
    LC_RPATH                = 0x0000001C | LC_REQ_DYLD
    LC_CODE_SIGNATURE       = 0x0000001D
    LC_SEGMENT_SPLIT_INFO   = 0x0000001E
    LC_REEXPORT_DYLIB       = 0x0000001F | LC_REQ_DYLD
    LC_LAZY_LOAD_DYLIB      = 0x00000020
    LC_ENCRYPTION_INFO      = 0x00000021
    LC_DYLD_INFO            = 0x00000022
    LC_DYLD_INFO_ONLY       = 0x00000022 | LC_REQ_DYLD
    LC_LOAD_UPWARD_DYLIB    = 0x00000023 | LC_REQ_DYLD
    LC_VERSION_MIN_MACOSX   = 0x00000024
    LC_VERSION_MIN_IPHONEOS = 0x00000025
    LC_FUNCTION_STARTS      = 0x00000026
    LC_DYLD_ENVIRONMENT     = 0x00000027
    LC_MAIN                 = 0x00000028 | LC_REQ_DYLD
    LC_DATA_IN_CODE         = 0x00000029
    LC_SOURCE_VERSION       = 0x0000002A
    LC_DYLIB_CODE_SIGN_DRS  = 0x0000002B

    # Section types and attributes
    # /usr/include/mach-o/loader.h
    S_REGULAR                             = 0x00
    S_ZEROFILL                            = 0x01
    S_CSTRING_LITERALS                    = 0x02
    S_4BYTE_LITERALS                      = 0x03
    S_8BYTE_LITERALS                      = 0x04
    S_LITERAL_POINTERS                    = 0x05
    S_NON_LAZY_SYMBOL_POINTERS            = 0x06
    S_LAZY_SYMBOL_POINTERS                = 0x07
    S_SYMBOL_STUBS                        = 0x08
    S_MOD_INIT_FUNC_POINTERS              = 0x09
    S_MOD_TERM_FUNC_POINTERS              = 0x0A
    S_COALESCED                           = 0x0B
    S_GB_ZEROFILL                         = 0x0C
    S_INTERPOSING                         = 0x0D
    S_16BYTE_LITERALS                     = 0x0E
    S_DTRACE_DOF                          = 0x0F
    S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10
    S_THREAD_LOCAL_REGULAR                = 0x11
    S_THREAD_LOCAL_ZEROFILL               = 0x12
    S_THREAD_LOCAL_VARIABLES              = 0x13
    S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14
    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

    # Apparently the high order byte is "USR" defined while the next 2
    # bytes are "SYS" defined. For more information see
    # SECTION_ATTRIBUTES_USR and SECTION_ATTRIBUTES_SYS.
    S_ATTR_PURE_INSTRUCTIONS   = 0x80000000
    S_ATTR_NO_TOC              = 0x40000000
    S_ATTR_STRIP_STATIC_SYMS   = 0x20000000
    S_ATTR_NO_DEAD_STRIP       = 0x10000000
    S_ATTR_LIVE_SUPPORT        = 0x08000000
    S_ATTR_SELF_MODIFYING_CODE = 0x04000000
    S_ATTR_DEBUG               = 0x02000000
    S_ATTR_SOME_INSTRUCTIONS   = 0x00000400
    S_ATTR_EXT_RELOC           = 0x00000200
    S_ATTR_LOC_RELOC           = 0x00000100

    # Signature magic
    # http://opensource.apple.com/source/Security/Security-55179.11/libsecurity_codesigning/lib/CSCommonPriv.h
    # CERT_BLOB is sometimes referred to as "blob wrapper" in other code.
    CODE_REQUIREMENT = 0xFADE0C00
    REQUIREMENT_SET  = 0xFADE0C01
    CODE_DIRECTORY   = 0xFADE0C02
    EMBEDDED_SIG     = 0xFADE0CC0
    DETACHED_SIG     = 0xFADE0CC1
    CERT_BLOB        = 0xFADE0B01
    ENTITLEMENT      = 0xFADE7171

    # Hash type definitions
    # http://opensource.apple.com/source/Security/Security-55179.11/libsecurity_codesigning/lib/CSCommonPriv.h
    CS_NOHASH = 0x00
    CS_SHA1   = 0x01
    CS_SHA256 = 0x02
    CS_SKEIN1 = 0x20
    CS_SKEIN2 = 0x21

    # nlist n_type masks
    # /usr/include/mach-o/nlist.h
    N_STAB = 0xE0 # Mask to get the stab information
    N_PEXT = 0x10
    N_TYPE = 0x0E # Mask to get the type bits
    N_EXT  = 0x01

    # stab masks. These are only used if nlist.n_type & N_STAB != 0
    # /usr/include/mach-o/stab.h
    N_GSYM    = 0x20
    N_FNAME   = 0x22
    N_FUN     = 0x24
    N_STSYM   = 0x26
    N_LCSYM   = 0x28
    N_BNSYM   = 0x2E
    N_OPT     = 0x3C
    N_RSYM    = 0x40
    N_SLINE   = 0x44
    N_ENSYM   = 0x4E
    N_SSYM    = 0x60
    N_SO      = 0x64
    N_OSO     = 0x66
    N_LSYM    = 0x80
    N_BINCL   = 0x82
    N_SOL     = 0x84
    N_PARAMS  = 0x86
    N_VERSION = 0x88
    N_OLEVEL  = 0x8A
    N_PSYM    = 0xA0
    N_EINCL   = 0xA2
    N_ENTRY   = 0xA4
    N_LBRAC   = 0xC0
    N_EXCL    = 0xC2
    N_RBRAC   = 0xE0
    N_BCOMM   = 0xE2
    N_ECOMM   = 0xE4
    N_ECOML   = 0xE8
    N_LENG    = 0xFE

    # nlist n_type values
    # Use these if n_type & N_TYPE is set.
    N_UNDF = 0x00
    N_ABS  = 0x02
    N_SECT = 0x0E
    N_PBUD = 0x0C
    N_INDR = 0x0A

    def __init__(self):
        self.magic       = 0
        self.nfat        = 0
        self.cpu_type    = 0
        self.cpu_subtype = 0
        self.filetype    = 0
        self.ncmds       = 0
        self.sizeofcmds  = 0
        self.flagval     = 0
        self.cmdlist     = []

        # Endianness to use when parsing. If the file is in big endian
        # this will be changed later.
        self.endian = '<'

        # Size of structures
        self.MACHO32_SZ  = 28
        self.MACHO64_SZ  = 32 # An extra 32 bit reserved field.
        self.LC_SZ       = 8

        # Map magic values to a string
        self.magics = {
                        self.FAT_MAGIC:   'Universal',
                        self.FAT_CIGAM:   'Universal',
                        self.MH_MAGIC:    '32-bit',
                        self.MH_CIGAM:    '32-bit',
                        self.MH_MAGIC_64: '64-bit',
                        self.MH_CIGAM_64: '64-bit'
                      }

        # CPU mapping
        self.cpu_types = {
                           self.CPU_TYPE_POWERPC:   'PPC',
                           self.CPU_TYPE_X86:       'Intel',
                           self.CPU_TYPE_POWERPC64: 'PPC64',
                           self.CPU_TYPE_X86_64:    'Intel (64-bit)',
                           self.CPU_TYPE_ARM:       'ARM'
                         }

        # CPU subtype mapping
        self.cpu_ppc_subtypes = {
                                  self.CPU_SUBTYPE_POWERPC_ALL: 'All',
                                  self.CPU_SUBTYPE_POWERPC_7400: '7400',
                                  self.CPU_SUBTYPE_POWERPC_7450: '7450'
                                }
        self.cpu_x86_subtypes = {
                                  self.CPU_SUBTYPE_I386_ALL: 'All'
                                }
        self.cpu_arm_subtypes = {
                                  self.CPU_SUBTYPE_ARM_ALL:    'All',
                                  self.CPU_SUBTYPE_ARM_V4T:    'V4T',
                                  self.CPU_SUBTYPE_ARM_V6:     'V6',
                                  self.CPU_SUBTYPE_ARM_V5TEJ:  'V5TEJ',
                                  self.CPU_SUBTYPE_ARM_XSCALE: 'XSCALE',
                                  self.CPU_SUBTYPE_ARM_V7:     'V7',
                                  self.CPU_SUBTYPE_ARM_V7F:    'V7F',
                                  self.CPU_SUBTYPE_ARM_V7K:    'V7K'
                                }

        # Filetype mapping
        self.filetypes = {
                           self.MH_OBJECT:      'Object',
                           self.MH_EXECUTE:     'Executable',
                           self.MH_FVMLIB:      'Fixed VM dynamic library',
                           self.MH_CORE:        'Core',
                           self.MH_PRELOAD:     'Preloaded executable',
                           self.MH_DYLIB:       'Dynamic library',
                           self.MH_DYLINKER:    'Dynamic link editor',
                           self.MH_BUNDLE:      'Bundle',
                           self.MH_DYLIB_STUB:  'Dynamic library stub',
                           self.MH_DSYM:        'Symbol information',
                           self.MH_KEXT_BUNDLE: '64 bit kernel extension'
                         }

        # Header flag mapping
        self.flags = {
                       self.MH_NOUNDEFS: 'No undefined references',
                       self.MH_INCRLINK: 'Incremental link',
                       self.MH_DYLDLINK: 'Dynamic link',
                       self.MH_BINDATLOAD: 'Bind undefined at load',
                       self.MH_PREBOUND: 'Undefined references prebound',
                       self.MH_SPLIT_SEGS: 'Split RW/RO segments',
                       self.MH_LAZY_INIT: 'Lazy init (obsolete)',
                       self.MH_TWOLEVEL: 'Two-level namespace bindings',
                       self.MH_FORCE_FLAT: 'Flat namespace bindings',
                       self.MH_NOMULTIDEFS: 'No multiple symbold definitions',
                       self.MH_NOFIXPREBINDING: 'Do not notify prebinding',
                       self.MH_PREBINDABLE: 'Can prebind',
                       self.MH_ALLMODSBOUND: 'Binds to two-level namespaces',
                       self.MH_SUBSECTIONS_VIA_SYMBOLS: 'Subdivide sections',
                       self.MH_CANONICAL: 'Canonicalized',
                       self.MH_WEAK_DEFINES: 'Contains external weak symbols',
                       self.MH_BINDS_TO_WEAK: 'Uses weak symbols',
                       self.MH_ALLOW_STACK_EXECUTION: 'Allow stack execution',
                       self.MH_ROOT_SAFE: 'Safe for uid zero',
                       self.MH_SETUID_SAFE: 'Safe for setuid',
                       self.MH_NO_REEXPORTED_DYLIBS: 'No re-exported dylibs',
                       self.MH_PIE: 'PIE',
                       self.MH_DEAD_STRIPPABLE_DYLIB: 'Dead strippable',
                       self.MH_HAS_TLV_DESCRIPTORS: 'Thread local variables',
                       self.MH_NO_HEAP_EXECUTION: 'No heap execution'
                     }

        # Command mapping
        self.commands = {
                          self.LC_SEGMENT: 'Segment',
                          self.LC_SYMTAB: 'Link-edit stab symbol table',
                          self.LC_SYMSEG: 'Link-edit gdb symbol table',
                          self.LC_THREAD: 'Thread',
                          self.LC_UNIXTHREAD: 'Unix thread',
                          self.LC_LOADFVMLIB: 'Load fixed VM shared library',
                          self.LC_IDFVMLIB: 'Fixed VM shared library ID',
                          self.LC_IDENT: 'Object ID information',
                          self.LC_FVMFILE: 'Fixed VM file inclusion',
                          self.LC_PREPAGE: 'Prepage command',
                          self.LC_DYSYMTAB: 'Dynamic Link-edit symbol table',
                          self.LC_LOAD_DYLIB: 'Load dynamically linked shared library',
                          self.LC_ID_DYLIB: 'Dynamically linked shared library identification',
                          self.LC_LOAD_DYLINKER: 'Load dynamic linker',
                          self.LC_ID_DYLINKER: 'Dynamic linker identification',
                          self.LC_PREBOUND_DYLIB: 'Modules prebound for a dynamically linked shared library',
                          self.LC_ROUTINES: 'Image routines',
                          self.LC_SUB_FRAMEWORK: 'Sub framework',
                          self.LC_SUB_UMBRELLA: 'Sub umbrella',
                          self.LC_SUB_CLIENT: 'Sub client',
                          self.LC_SUB_LIBRARY: 'Sub library',
                          self.LC_TWOLEVEL_HINTS: 'Two-level namespace hints',
                          self.LC_PREBIND_CKSUM: 'Prebind checksum',
                          self.LC_LOAD_WEAK_DYLIB: 'Load weak dynamic library',
                          self.LC_SEGMENT_64: '64 bit segment',
                          self.LC_ROUTINES_64: '64 bit image routines',
                          self.LC_UUID: 'UUID',
                          self.LC_RPATH: 'Runpath additions',
                          self.LC_CODE_SIGNATURE: 'Code signature',
                          self.LC_SEGMENT_SPLIT_INFO: 'Info to split segments',
                          self.LC_REEXPORT_DYLIB: 'Load and re-export dylib',
                          self.LC_LAZY_LOAD_DYLIB: 'Delay load of dylib',
                          self.LC_ENCRYPTION_INFO: 'Encrypted segment information',
                          self.LC_DYLD_INFO: 'Compressed dyld information',
                          self.LC_DYLD_INFO_ONLY: 'Compressed dyld information only',
                          self.LC_LOAD_UPWARD_DYLIB: 'Load upward dylib',
                          self.LC_VERSION_MIN_MACOSX: 'Minimum OS X version',
                          self.LC_VERSION_MIN_IPHONEOS: 'Minimum iOS version',
                          self.LC_FUNCTION_STARTS: 'Compressed table of function start addresses',
                          self.LC_DYLD_ENVIRONMENT: 'Dyld environment string',
                          self.LC_MAIN: 'Main load command',
                          self.LC_DATA_IN_CODE: 'Non-instructions',
                          self.LC_SOURCE_VERSION: 'Source version',
                          self.LC_DYLIB_CODE_SIGN_DRS: 'Code signing DRs copied from linked dylib'
                        }

        # Command parsers
        self.cmd_parsers = {
                             self.LC_SEGMENT: self.parse_lc_segment,
                             self.LC_SYMTAB: self.parse_lc_symtab,
                             self.LC_THREAD: self.parse_lc_thread,
                             # LC_UNIXTHREAD and LC_THREAD are the same
                             # structure, so use the same parser. LC_THREAD
                             # does not cause the kernel to allocate a stack.
                             self.LC_UNIXTHREAD: self.parse_lc_thread,
                             self.LC_DYSYMTAB: self.parse_lc_dysymtab,
                             self.LC_LOAD_DYLIB: self.parse_lc_load_dylib,
                             self.LC_ID_DYLIB: self.parse_lc_id_dylib,
                             self.LC_LOAD_DYLINKER: self.parse_lc_load_dylinker,
                             self.LC_ID_DYLINKER: self.parse_lc_id_dylinker,
                             self.LC_PREBOUND_DYLIB:  self.parse_lc_prebound_dylib,
                             self.LC_ROUTINES: self.parse_lc_routines,
                             self.LC_SUB_FRAMEWORK: self.parse_lc_sub_framework,
                             self.LC_SUB_UMBRELLA: self.parse_lc_sub_umbrella,
                             self.LC_SUB_CLIENT: self.parse_sub_client,
                             self.LC_SUB_LIBRARY: self.parse_sub_library,
                             self.LC_TWOLEVEL_HINTS: self.parse_twolevel_hints,
                             self.LC_SEGMENT_64: self.parse_lc_segment_64,
                             self.LC_ROUTINES_64: self.parse_lc_routines_64,
                             self.LC_UUID: self.parse_lc_uuid,
                             self.LC_CODE_SIGNATURE: self.parse_lc_code_signature,
                             # LC_VERSION_MIN_MACOSX and LC_VERSION_MIN_IPHONEOS
                             # are the same structure, so use the same parser.
                             self.LC_VERSION_MIN_MACOSX: self.parse_lc_version_min_macosx,
                             self.LC_VERSION_MIN_IPHONEOS: self.parse_lc_version_min_macosx,
                             self.LC_SOURCE_VERSION: self.parse_lc_source_version
                           }

        # Most commands are self contained. That is, all the data needed
        # is in the blob passed to the command parser. There are a couple
        # that require a sub-parser, where the first parser returns the
        # necessary amount of information to locate the next blob of data
        # for the sub parser.
        #
        # LC_SEGMENT and LC_SEGMENT_64 use the same sub parser.
        self.sub_cmd_parsers = {
                                 self.LC_SEGMENT: self.parse_lc_segment_sub,
                                 self.LC_SEGMENT_64: self.parse_lc_segment_sub,
                                 self.LC_CODE_SIGNATURE: self.parse_lc_code_signature_sub,
                                 self.LC_SYMTAB: self.parse_lc_symtab_sub
                               }

        # Section type mapping
        self.section_types = {
                               self.S_REGULAR: 'Regular',
                               self.S_ZEROFILL: 'Zero fill on demand',
                               self.S_CSTRING_LITERALS: 'Literal C strings',
                               self.S_4BYTE_LITERALS: '4 byte literals',
                               self.S_8BYTE_LITERALS: '8 byte literals',
                               self.S_LITERAL_POINTERS: 'Pointers to literals',
                               self.S_NON_LAZY_SYMBOL_POINTERS: 'Non-lazy symbol pointers',
                               self.S_LAZY_SYMBOL_POINTERS: 'Lazy symbol pointers',
                               self.S_SYMBOL_STUBS: 'Symbol stubs',
                               self.S_MOD_INIT_FUNC_POINTERS: 'Initialization function pointers',
                               self.S_MOD_TERM_FUNC_POINTERS: 'Termination function pointers',
                               self.S_COALESCED: 'Coalesced symbols',
                               self.S_GB_ZEROFILL: 'Zero fill on demand (GB)',
                               self.S_INTERPOSING: 'Pairs of function pointers for interposing',
                               self.S_16BYTE_LITERALS: '16 byte literals',
                               self.S_DTRACE_DOF: 'DTrace object format',
                               self.S_LAZY_DYLIB_SYMBOL_POINTERS: 'Lazy symbol pointers to lazy loaded dylibs',
                               self.S_THREAD_LOCAL_REGULAR: 'Initial TLV values',
                               self.S_THREAD_LOCAL_ZEROFILL: 'TLV zero fill',
                               self.S_THREAD_LOCAL_VARIABLES: 'TLV descriptors',
                               self.S_THREAD_LOCAL_VARIABLE_POINTERS: 'Pointers to TLV descriptors',
                               self.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: 'TLV initialization functions'
                             }

        # Section attribute mapping
        self.section_attrs = {
                               self.S_ATTR_PURE_INSTRUCTIONS: 'True machine instructions',
                               self.S_ATTR_NO_TOC: 'Coalesced symbols not in TOC',
                               self.S_ATTR_STRIP_STATIC_SYMS: 'Strip static symbols',
                               self.S_ATTR_NO_DEAD_STRIP: 'No dead stripping',
                               self.S_ATTR_LIVE_SUPPORT: 'Live blocks',
                               self.S_ATTR_SELF_MODIFYING_CODE: 'Self modifying code',
                               self.S_ATTR_DEBUG: 'Debug section',
                               self.S_ATTR_SOME_INSTRUCTIONS: 'Some machine instructions',
                               self.S_ATTR_EXT_RELOC: 'External relocation entries',
                               self.S_ATTR_LOC_RELOC: 'Local relocation entries'
                             }

        # Signature mapping
        self.signatures = {
                            self.CODE_REQUIREMENT: 'Code requirement',
                            self.REQUIREMENT_SET: 'Requirement set',
                            self.CODE_DIRECTORY: 'Code directory',
                            self.EMBEDDED_SIG: 'Embedded code signature',
                            self.DETACHED_SIG: 'Detached code signature',
                            self.CERT_BLOB: 'Certificate blob',
                            self.ENTITLEMENT: 'Entitlement blob'
                          }

        # Signature parsers
        self.signature_parsers = {
                                   self.CODE_REQUIREMENT: self.parse_code_requirement,
                                   self.REQUIREMENT_SET: self.parse_requirement_set,
                                   self.CODE_DIRECTORY: self.parse_code_directory,
                                   self.EMBEDDED_SIG: self.parse_embedded_sig,
                                   self.CERT_BLOB: self.parse_cert_blob
                                 }

        # Hash type mapping
        self.hashes = {
                        self.CS_NOHASH: 'None',
                        self.CS_SHA1: 'SHA1',
                        self.CS_SHA256: 'SHA256',
                        self.CS_SKEIN1: 'SKEIN 160x256',
                        self.CS_SKEIN2: 'SKEIN 256x512'
                      }

        # These should be the first 4 bytes of a PKCS7 blob.
        self.PKCS7 = [0x3080, 0x3081, 0x3082, 0x3083, 0x3084]

        # Map stab symbol information to a useful name.
        self.stabs = {
                       self.N_GSYM: 'Global symbol',
                       self.N_FNAME: 'Procedure name (f77 kludge)',
                       self.N_FUN: 'Procedure',
                       self.N_STSYM: 'Static symbol',
                       self.N_LCSYM: '.lcomm symbol',
                       self.N_BNSYM: 'Begin nsect symbol',
                       self.N_OPT: 'Emitted with gcc2_compiled and in gcc source',
                       self.N_RSYM: 'Register sym',
                       self.N_SLINE: 'Source line',
                       self.N_ENSYM: 'End nsect symbol',
                       self.N_SSYM: 'Structure elt',
                       self.N_SO: 'Source file name',
                       self.N_OSO: 'Object file name',
                       self.N_LSYM: 'Local symbol',
                       self.N_BINCL: 'Include file beginning',
                       self.N_SOL: '#included file name',
                       self.N_PARAMS: 'Compiler parameters',
                       self.N_VERSION: 'Compiler version',
                       self.N_OLEVEL: 'Compiler -O level',
                       self.N_PSYM: 'Parameter',
                       self.N_EINCL: 'Include file end',
                       self.N_ENTRY: 'Alternate entry',
                       self.N_LBRAC: 'Left bracket',
                       self.N_EXCL: 'Deleted include file',
                       self.N_RBRAC: 'Right bracket',
                       self.N_BCOMM: 'Begin common',
                       self.N_ECOMM: 'End common',
                       self.N_ECOML: 'End common (local name)',
                       self.N_LENG: 'Second stab entry with length information'
                     }

        self.ntypes = {
                        self.N_UNDF: 'Undefined',
                        self.N_ABS: 'Absolute',
                        self.N_SECT: 'Defined in another section',
                        self.N_PBUD: 'Prebound undefined',
                        self.N_INDR: 'Indirect'
                      }

    # Things we store internally as an their literal value but want
    # to eventually expose as a useful string are exposed as properties.
    # Things that don't have a useful string (eg: nfat) should be
    # accessed directly.
    #
    # Some things (eg: cpu_type) may not have a useful string representation.
    # This is likely because the dictionary that maps constants to their
    # string representation is not complete. This is fixed by expanding
    # the appropriate dictionary to contain the mapping. In these cases
    # return the value as a hex string so it can still be printed.
    @property
    def magic_str(self):
        return self.magics[self.magic]

    @property
    def cpu_type_str(self):
        return self.cpu_types.get(self.cpu_type, "0x%08x" % self.cpu_type)

    @property
    def cpu_subtype_str(self):
        # Don't look at the high order byte, it is used to denote
        # capabilities. The high order bit is used to denote a 64 bit CPU.
        # We have to choose the correct subtype dictionary based upon the
        # CPU_TYPE value. This is because some subtypes are the same value.
        if self.cpu_type in [self.CPU_TYPE_POWERPC, self.CPU_TYPE_POWERPC64]:
            return self.cpu_ppc_subtypes.get(self.cpu_subtype & ~self.CPU_SUBTYPE_MASK, "0x%08x" % self.cpu_subtype)
        elif self.cpu_type in [self.CPU_TYPE_X86, self.CPU_TYPE_X86_64]:
            return self.cpu_x86_subtypes.get(self.cpu_subtype & ~self.CPU_SUBTYPE_MASK, "0x%08x" % self.cpu_subtype)
        elif self.cpu_type in [self.CPU_TYPE_ARM]:
            return self.cpu_arm_subtypes.get(self.cpu_subtype & ~self.CPU_SUBTYPE_MASK, "0x%08x" % self.cpu_subtype)
        else:
            return "0x%08x" % self.cpu_subtype

    @property
    def filetype_str(self):
        return self.filetypes.get(self.filetype, "0x%08x" % self.filetype)

    @property
    def flaglist(self):
        # Given the internal 'flagval' from a header, return a list
        # of the corresponding flag names.
        flaglist = []
        for (k, v) in self.flags.iteritems():
            if self.flagval & k == k:
                flaglist.append(v)
        return flaglist

    # Given a command value (integer) return the command name or hex string
    # if it's not known. This isn't a property like the others because it
    # takes an argument.
    def cmd_name(self, cmd):
        return self.commands.get(cmd, "0x%08x" % cmd)

    # Given a signature value (integer) return the signature name or hex string
    # if it's not known. This isn't a property like the others because it
    # takes an argument.
    def sig_name(self, sig):
        return self.signatures.get(sig, "0x%08x" % sig)

    def unknown_cmd(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_segment(self, cmd_data):
        ret = {}
        # Segment name is a NULL terminated string, at most 16 bytes long.
        # Make sure there is a NULL somewhere in the first 16 bytes else
        # take the entire thing.
        null = cmd_data[:16].find('\x00')
        if null == -1:
            null = 16
        ret['segname'] = cmd_data[:null]
        (ret['vmsize'], ret['filesize'], ret['nsects'], ret['flags']) = struct.unpack(self.endian + 'IxxxxIxxxxxxxxII', cmd_data[20:48])

        # Sections come after the command.
        sect_ptr = cmd_data[48:]
        ret['sectlist'] = []
        for i in xrange(ret['nsects']):
            sect = {}
            # XXX: Ensure nsects * sizeof(struct section) is not off the end.
            null = sect_ptr[:16].find('\x00')
            if null == -1:
                null = 16
            sect['sectname'] = sect_ptr[:null]
            # Bytes 16 through 32 are the segment name in this section.
            # Skip it as we aren't using it.
            (addr, sect['size'], sect['offset'], flags) = struct.unpack(self.endian + 'IIIxxxxxxxxxxxxI', sect_ptr[32:60])
            sect['addr'] = "0x%08x" % addr
            # 24 bits are for attributes, 8 bits are for type.
            sect['type'] = self.section_types.get(flags & 0xFF, "0x%08x" % flags)
            sect['flaglist'] = []
            for (attr, desc) in self.section_attrs.items():
                if flags & attr == attr:
                    sect['flaglist'].append(desc)
            ret['sectlist'].append(sect)
            sect_ptr = sect_ptr[68:]
        return ret

    def parse_lc_symtab(self, cmd_data):
        ret = {}
        (ret['sym_off'], ret['nsyms'], ret['str_off'], ret['str_sz']) = struct.unpack(self.endian + 'IIII', cmd_data[:16])
        return ret

    def parse_lc_thread(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_dysymtab(self, cmd_data):
        ret = {}
        return ret

    # Parsing a struct dylib. This is used in a number of load commands.
    def parse_dylib_struct(self, cmd_data):
        ret = {}
        # The first 4 bytes are an offset to the start of the string.
        # We subtract 8 from this because we are not getting the first 8
        # bytes of the command (they are stripped before calling the command
        # parsers).
        (offset, ts, cv, cpv) = struct.unpack(self.endian + 'IIII', cmd_data[:16])
        offset -= 8
        ret['timestamp'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        ret['cv'] = "%i.%i.%i" % ((cv >> 16), (cv >> 8) & 0xFF, cv & 0xFF)
        ret['cpv'] = "%i.%i.%i" % ((cpv >> 16), (cpv >> 8) & 0xFF, cpv & 0xFF)
        # XXX: Ensure offset is not past the end...
        # Jump forward to the string and grab it.
        null = cmd_data[offset:].find('\x00')
        if null == -1:
            ret['dylib'] = 'Unknown'
        ret['dylib'] = cmd_data[offset:offset + null]
        return ret

    def parse_lc_load_dylib(self, cmd_data):
        return self.parse_dylib_struct(cmd_data)

    def parse_lc_id_dylib(self, cmd_data):
        return self.parse_dylib_struct(cmd_data)

    def parse_lc_load_dylinker(self, cmd_data):
        ret = {}
        # The first 4 bytes are an offset to the start of the string. It's
        # the only thing in this structure, so just skip the first 4 bytes
        # and grab the rest until the null.
        null = cmd_data[4:].find('\x00')
        if null == -1:
            ret['dylib'] = 'Unknown'
        ret['dylinker'] = cmd_data[4:4 + null]
        return ret

    def parse_lc_id_dylinker(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_prebound_dylib(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_routines(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_sub_framework(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_sub_umbrella(self, cmd_data):
        ret = {}
        return ret

    def parse_sub_client(self, cmd_data):
        ret = {}
        return ret

    def parse_sub_library(self, cmd_data):
        ret = {}
        return ret

    def parse_twolevel_hints(self, cmd_data):
        # Intentionally not parsing this...
        ret = {}
        return ret

    def parse_lc_segment_64(self, cmd_data):
        ret = {}
        # Segment name is a NULL terminated string, at most 16 bytes long.
        # Make sure there is a NULL somewhere in the first 16 bytes else
        # take the entire thing.
        null = cmd_data[:16].find('\x00')
        if null == -1:
            null = 16
        ret['segname'] = cmd_data[:null]
        (ret['vmsize'], ret['filesize'], ret['nsects'], ret['flags']) = struct.unpack(self.endian + 'QxxxxxxxxQxxxxxxxxII', cmd_data[24:64])

        # Sections come after the command.
        sect_ptr = cmd_data[64:]
        ret['sectlist'] = []
        for i in xrange(ret['nsects']):
            sect = {}
            # XXX: Ensure nsects * sizeof(struct section_64) is not off the end.
            null = sect_ptr[:16].find('\x00')
            if null == -1:
                null = 16
            sect['sectname'] = sect_ptr[:null]
            # Bytes 16 through 32 are the segment name in this section.
            # Skip it as we aren't using it.
            (addr, sect['size'], sect['offset'], flags) = struct.unpack(self.endian + 'QQIxxxxxxxxxxxxI', sect_ptr[32:68])
            sect['addr'] = "0x%08x" % addr
            # 24 bits are for attributes, 8 bits are for type.
            sect['type'] = self.section_types.get(flags & 0xFF, "0x%08x" % flags)
            sect['flaglist'] = []
            for (attr, desc) in self.section_attrs.items():
                if flags & attr == attr:
                    sect['flaglist'].append(desc)
            ret['sectlist'].append(sect)
            # XXX: Should be 76 but there are an extra 4 padding bytes (align?)
            sect_ptr = sect_ptr[80:]
        return ret

    def parse_lc_source_version(self, cmd_data):
        ret = {}
        (ver) = struct.unpack(self.endian + 'Q', cmd_data)[0]
        ret['ver'] = "%i.%i.%i.%i.%i" % ((ver >> 40), (ver >> 30) & 0x3FF, (ver >> 20) & 0x3FF, (ver >> 10) & 0x3FF, ver & 0x3FF)
        return ret

    def parse_lc_version_min_macosx(self, cmd_data):
        ret = {}
        (ver, sdk) = struct.unpack(self.endian + 'II', cmd_data[:8])
        ret['ver'] = "%i.%i.%i" % ((ver >> 16), (ver >> 8) & 0xFF, ver & 0xFF)
        ret['sdk'] = "%i.%i.%i" % ((sdk >> 16), (sdk >> 8) & 0xFF, sdk & 0xFF)
        return ret

    def parse_lc_routines_64(self, cmd_data):
        ret = {}
        return ret

    def parse_lc_uuid(self, cmd_data):
        return {'uuid': binascii.hexlify(cmd_data[:16])}

    def parse_lc_code_signature(self, cmd_data):
        ret = {}
        # Based upon the output of 'otool -l' looks like the first 4 bytes
        # are an offset and the next 4 are a size.
        ret['offset'], ret['size'] = struct.unpack(self.endian + 'II', cmd_data)
        return ret

    def unknown_sig(self, sig_data):
        ret = {}
        return ret

    def parse_cert_blob(self, sig_data):
        ret = {}
        # Skip the magic, grab the length and next 2 bytes. They should be
        # one of the PKCS7 values.
        (length, blob_hdr) = struct.unpack('>IH', sig_data[4:10])
        if blob_hdr in self.PKCS7:
            ret['pkcs7'] = sig_data[8:length]
        return ret

    def parse_embedded_sig(self, sig_data):
        # Length is the length of the entire signature. This is a different
        # value from the length in the LC_SIGNATURE block. That length is
        # aligned to something. This length is the size of the blob.
        #
        # Count is the number of sub-structures contained in this header.
        # The sub-structures are 4 bytes for a type and 4 bytes for an offset.
        (length, count) = struct.unpack('>II', sig_data[4:12])
        ptr = sig_data[12:]
        ret = [] # A list of dictionaries returned by sub-parsers.
        for i in xrange(count):
            (type_, offset) = struct.unpack('>II', ptr[:8])
            if (offset) > len(sig_data):
                raise MachOParserError("Embedded signature overflow.")
            sig = struct.unpack('>I', sig_data[offset:offset + 4])[0]
            sub_parser = self.signature_parsers.get(sig, self.unknown_sig)
            sub_ret = sub_parser(sig_data[offset:])
            sub_ret['type'] = sig
            ret.append(sub_ret)
            ptr = ptr[8:]
        return ret

    # Best definition of this structure I've been able to find:
    # http://opensource.apple.com/source/Security/Security-55179.11/libsecurity_codesigning/lib/cscdefs.h
    def parse_code_directory(self, sig_data):
        ret = {}
        # Only grabbing certain parts of this structure..
        (ver, ho, io, hs, ht) = struct.unpack('>' + 'x' * 8 + 'I' + 'x' * 4 + 'II' + 'x' * 12 + 'BB' + 'x' * 6, sig_data[:44])
        if (ho + hs) > len(sig_data):
            raise MachOParserError("Code directory too large.")
        ret['ver'] = "0x%08x" % ver
        ret['hashtype'] = self.hashes.get(ht, '0x%02x' % ht)
        ret['hash'] = binascii.hexlify(sig_data[ho:ho + hs])
        # Identifier is null terminated.
        null = sig_data[io:].find('\x00')
        if null == -1:
            ret['identifier'] = 'Unknown'
        else:
            ret['identifier'] = sig_data[io:io + null]
        return ret

    def parse_code_requirement(self, sig_data):
        ret = {}
        return ret

    # Requirement sets are like other blobs. Follow the offset to
    # the real block we care about.
    def parse_requirement_set(self, sig_data):
        ret = {}
        # Skipping the 4 byte magic, the next 4 bytes are the size and
        # the next 4 bytes are the number of requirements in this set.
        count = struct.unpack('>I', sig_data[8:12])[0]
        # Requirement sets are stored like super blobs.
        ptr = sig_data[12:]
        ret['requirements'] = []
        for i in xrange(count):
            # Skipping over the first 4 bytes, I don't know what they are.
            # I think they are a type?
            offset = struct.unpack('>I', ptr[4:8])[0]
            if offset > len(sig_data):
                raise MachOParserError("Requirement set too large.")
            magic = struct.unpack('>I', sig_data[offset:offset + 4])[0]
            new_parser = self.signature_parsers.get(magic, self.unknown_sig)
            req = new_parser(sig_data[offset:])
            req['type'] = magic
            ret['requirements'].append(req)
            ptr = ptr[8:]
        return ret

    def parse_lc_segment_sub(self, cmd_dict, data):
        for sect in cmd_dict['sectlist']:
            sect_offset = sect['offset']
            sect_size = sect['size']
            if not sect_offset or not sect_size:
                sect['md5'] = 'None'
            else:
                if (sect_offset + sect_size) > len(data):
                    raise MachOParserError("Segment too large.")
                hash_ = md5()
                hash_.update(data[sect_offset:sect_offset + sect_size])
                sect['md5'] = hash_.hexdigest()

    def parse_lc_code_signature_sub(self, cmd_dict, data):
        # If parsing a signature command, follow the offset.
        # No need to store offset and size in the results.
        # Use them locally and delete them.
        offset = cmd_dict['offset']
        size = cmd_dict['size']
        del cmd_dict['offset']
        del cmd_dict['size']
        if (offset + size) > len(data):
            raise MachOParserError("Signature data too large.")
        sig = struct.unpack('>I', data[offset:offset + 4])[0]
        cmd_dict['sig'] = sig
        sig_parser = self.signature_parsers.get(sig, self.unknown_sig)
        # Move pass the first 4 bytes we just parsed because internal
        # offsets are relative to that start.
        sig_dict = sig_parser(data[offset:offset + size])
        cmd_dict['signatures'] = sig_dict

    def parse_lc_symtab_sub(self, cmd_dict, data):
        symbols = []

        # Follow the symbol offset.
        sym_off = cmd_dict['sym_off']
        nsyms = cmd_dict['nsyms']
        str_off = cmd_dict['str_off']
        str_sz = cmd_dict['str_sz']

        # No need to keep these around anymore.
        del cmd_dict['sym_off']
        del cmd_dict['nsyms']

        # We need the string table for some symbols.
        str_tab = data[str_off:str_off + str_sz]

        # XXX: Ensure sym_off + sizeof(struct nlist) is valid
        ptr = data[sym_off:]
        for i in xrange(nsyms):
            sym = {}

            # n_desc is unsigned for 64-bit files and signed for 32-bit. Weird.
            if self.magic in [self.MH_MAGIC_64, self.MH_CIGAM_64]:
                fmt = 'IBBHQ'
                nlist_size = struct.calcsize(fmt)
            else:
                # The docs say n_strx is a signed value, mach-o/nlist.h says
                # otherwise. I'm trusting the header file. :)
                fmt = 'IBBhI'
                nlist_size = struct.calcsize(fmt)

            (n_strx, n_type, n_sect, n_desc, n_value) = struct.unpack(self.endian + fmt, ptr[:nlist_size])

            if n_strx > 0:
                # XXX: Ensure that str_off + n_strx is valid
                # n_strx is an offset into the string table starting at
                # str_off. The strings are null terminated.
                null = str_tab[n_strx:].find('\x00')
                if null == 0 or null == -1:
                    ptr = ptr[nlist_size:]
                    continue
                else:
                    sym['string'] = str_tab[n_strx:n_strx + null]
            else:
                ptr = ptr[nlist_size:]
                continue

            # If any of the stab bits are set, the entire byte is to be
            # interpreted as a stab byte. If they are not set then
            # use the other masks to check the values.
            # See also:
            # /usr/include/mach-o/nlist.h
            # /usr/include/mach-o/stab.h
            if n_type & self.N_STAB != 0:
                sym['is_stab'] = True
                sym['stab_type'] = self.stabs.get(n_type, "0x%08x" % n_type)
            else:
                sym['is_stab'] = False
                if n_type & self.N_PEXT == self.N_PEXT:
                    sym['limited_global_scope'] = True
                else:
                    sym['limited_global_scope'] = False

                type_val = n_type & self.N_TYPE
                if type_val != 0:
                    sym['n_type'] = self.ntypes.get(type_val, "0x%02x" % type_val)
                else:
                    sym['n_type'] = "0x%02x" % type_val

                if n_type & self.N_EXT == self.N_EXT:
                    sym['external'] = True
                else:
                    sym['external'] = False

            symbols.append(sym)
            ptr = ptr[nlist_size:]

        # Symbols go into the cmd_dict.
        cmd_dict['symbols'] = symbols

    def get_magic(self, ptr):
        self.magic = struct.unpack('@I', ptr[:4])[0]
        if self.magic not in self.magics:
            raise MachOParserError("Unknown magic.")

        # Set endianness to use.
        if self.magic in [self.FAT_CIGAM, self.MH_CIGAM, self.MH_CIGAM_64]:
            self.endian = '>'

        # If a universal binary, grab the nfat value.
        if self.is_universal():
            self.nfat = struct.unpack('>I', ptr[4:8])[0]

    def is_universal(self):
        return self.magic in [self.FAT_MAGIC, self.FAT_CIGAM]

    def is_32bit(self):
        return self.magic in [self.MH_MAGIC, self.MH_CIGAM]

    def is_64bit(self):
        return self.magic in [self.MH_MAGIC_64, self.MH_CIGAM_64]

    # Offset must point to the start of the header. This function
    # calculates where the commands are from there.
    def parse_cmds(self, data):
        if self.is_64bit():
            cmd_offset = self.MACHO64_SZ
        else:
            cmd_offset = self.MACHO32_SZ

        if (cmd_offset + (self.ncmds * self.LC_SZ)) > len(data):
            raise MachOParserError("Load commands too large.")
        # Loop through all the commands.
        for i in xrange(self.ncmds):
            (cmd, size) = struct.unpack(self.endian + 'II', data[cmd_offset:cmd_offset + self.LC_SZ])
            # The parsers don't want the 8 bytes we just parsed.
            cmd_data = data[cmd_offset + self.LC_SZ:cmd_offset + size]
            cmd_parser = self.cmd_parsers.get(cmd, self.unknown_cmd)
            cmd_dict = cmd_parser(cmd_data)
            cmd_dict['cmd'] = cmd
            # Call a sub parser for any commands that need it.
            sub_cmd_parser = self.sub_cmd_parsers.get(cmd_dict['cmd'], None)
            if sub_cmd_parser:
                # cmd_dict is modified by sub parsers.
                sub_cmd_parser(cmd_dict, data)
            self.cmdlist.append(cmd_dict)
            cmd_offset += size

    def parse_header(self, data):
        (cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds, flagval) = struct.unpack(self.endian + 'IIIIII', data[4:]) # Skipping magic...
        self.cpu_type = cpu_type
        self.cpu_subtype = cpu_subtype
        if filetype not in self.filetypes:
            raise MachOParserError("Unknown filetype (0x%08x)" % filetype)
        self.filetype = filetype
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.flagval = flagval

    def parse(self, data):
        self.parse_header(data[:self.MACHO32_SZ])
        self.parse_cmds(data)

class MachOParser(object):
    def __init__(self, data):
        self.data = data
        if len(data) < 8:
            raise MachOParserError("Not enough data.")

        # A list of parsed "entities" which are MachOEntity objects.
        # For a fat file there will be N items in this list. For single
        # arch files there will be only one.
        self.entities = []

        # Sizes of structures.
        self.FAT_SZ      = 8
        self.FAT_ARCH_SZ = 20
        self.MACHO32_SZ  = 28
        self.MACHO64_SZ  = 32 # An extra 32bit reserved field.

    def parse(self):
        # XXX: Get total header length and make sure we have enough data
        entity = MachOEntity()
        # The magic is 4 bytes, but we pass 8 here because if it is
        # a universal binary get_magic() will also parse the nfat value.
        entity.get_magic(self.data[:8])

        if entity.is_universal():
            self.entities.append(entity)
            ptr = self.data[self.FAT_SZ:]
            for i in xrange(entity.nfat):
                # Grab the offset and size from each fat_arch.
                (offset, size) = struct.unpack(entity.endian + 'II', ptr[8:16])
                if (offset + size) > len(self.data):
                    raise MachOParserError("nfat %i too big.")
                new_entity = MachOEntity()
                new_entity.get_magic(self.data[offset:offset + 8])
                if new_entity.is_universal():
                    raise MachOParserError("Universal inception.")
                new_entity.parse(self.data[offset:offset + size])
                self.entities.append(new_entity)
                ptr = ptr[self.FAT_ARCH_SZ:]
        elif entity.is_32bit() or entity.is_64bit():
            entity.parse(self.data)
            self.entities.append(entity)
