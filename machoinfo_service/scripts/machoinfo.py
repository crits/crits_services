from optparse import OptionParser

from django.core.mail import send_mail
from crits.core.mongo_tools import get_file
from crits.core.basescript import CRITsBaseScript
from machoinfo_service.machoinfo import MachOEntity, MachOParser
from machoinfo_service.machoinfo import MachOParserError

class CRITsScript(CRITsBaseScript):
    def __init__(self, username=None):
        self.username = username

    def run(self, argv):
        parser = OptionParser()
        parser.add_option("-m", "--md5", action="store", dest="md5",
                type="string", help="MD5 of file to retrieve")
        parser.add_option("-f", "--file", action="store", dest="file",
                type="string", help="File to analyze")
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                default=False, help="Be verbose")
        (opts, args) = parser.parse_args(argv)

        if opts.md5:
            if opts.verbose:
                print "[+] attempting to call get_file on %s" % opts.md5
            data = get_file(opts.md5)
        elif opts.file:
            try:
                fin = open(opts.file, 'rb')
            except IOError, e:
                print str(e)
                return
            data = fin.read()
            fin.close()

        if not data:
            print "[+] no data"
            return

        if opts.verbose:
            print "[+] parsing %d bytes" % len(data)

        mop = MachOParser(data)
        try:
            mop.parse()
        except MachOParserError, e:
            print "ERROR: %s" % e

        i = 0
        for entity in mop.entities:
            print "[+] Entity %i" % i
            print "  [-] File format: %s" % entity.magic_str
            if entity.is_universal():
                print "  [-] Containing: %i" % entity.nfat
            else:
                print "  [-] CPU Type: %s" % entity.cpu_type_str
                print "  [-] CPU Subtype: %s" % entity.cpu_subtype_str
                print "  [-] Filetype: %s" % entity.filetype_str
                print "  [+] Flaglist (%i)" % len(entity.flaglist)
                for flag in entity.flaglist:
                    print "    [-] %s" % flag
                print "  [+] Commands (%i)" % len(entity.cmdlist)
                for cmd in entity.cmdlist:
                    cmd_name = entity.cmd_name(cmd['cmd'])
                    print "    [-] %s" % entity.cmd_name(cmd['cmd'])
                    if cmd['cmd'] == MachOEntity.LC_LOAD_DYLINKER:
                        print "      [-] Linker: %s" % cmd['dylinker']
                    elif cmd['cmd'] in [MachOEntity.LC_SEGMENT, MachOEntity.LC_SEGMENT_64]:
                        print "      [-] Name: %s" % cmd['segname']
                        print "      [-] Size: %s" % cmd['filesize']
                        print "      [-] VM Size: %s" % cmd['vmsize']
                        print "      [+] Sections (%i)" % len(cmd['sectlist'])
                        for sect in cmd['sectlist']:
                            print "        [-] Name: %s" % sect['sectname']
                            print "          [-] MD5: %s" % sect['md5']
                            print "          [-] VM address: %s" % sect['addr']
                            print "          [-] Offset: %s" % sect['offset']
                            print "          [-] Size: %s" % sect['size']
                            print "          [-] Type: %s" % sect['type']
                            print "          [+] Flag list (%i)" % len(sect['flaglist'])
                            for flag in sect['flaglist']:
                                print "            [-] %s" % flag
                    elif cmd['cmd'] in [MachOEntity.LC_LOAD_DYLIB, MachOEntity.LC_ID_DYLIB]:
                        print "      [-] Library: %s" % cmd['dylib']
                        print "      [-] Timestamp: %s" % cmd['timestamp']
                        print "      [-] Current version: %s" % cmd['cv']
                        print "      [-] Compatability version: %s" % cmd['cpv']
                    elif cmd['cmd'] == MachOEntity.LC_CODE_SIGNATURE:
                        for sig in cmd.get('signatures', []):
                            print "      [+] %s" % entity.sig_name(sig['type'])
                            if sig['type'] == MachOEntity.CODE_DIRECTORY:
                                print "        [-] Version: %s" % sig['ver']
                                print "        [-] Identifier: %s" % sig['identifier']
                                print "        [-] Hash type: %s" % sig['hashtype']
                                print "        [-] Hash: %s" % sig['hash']
                            if sig['type'] == MachOEntity.REQUIREMENT_SET:
                                #print "        [-] Requirements: %s" % sig['requirements']
                                pass
                            if sig['type'] == MachOEntity.CERT_BLOB:
                                print "        [-] PKCS7: %i" % len(sig['pkcs7'])
                    elif cmd['cmd'] == MachOEntity.LC_UUID:
                        print "      [-] UUID: %s" % cmd['uuid']
                    elif cmd['cmd'] in [MachOEntity.LC_VERSION_MIN_MACOSX, MachOEntity.LC_VERSION_MIN_IPHONEOS]:
                        print "      [-] Version: %s" % cmd['ver']
                        print "      [-] SDK: %s" % cmd['sdk']
                    elif cmd['cmd'] == MachOEntity.LC_SOURCE_VERSION:
                        print "      [-] Version: %s" % cmd['ver']
                    elif cmd['cmd'] == MachOEntity.LC_SYMTAB:
                        for sym in cmd['symbols']:
                            print "      [+] Symbol: %s" % sym.get('string', '')
                            if sym['is_stab']:
                                print "        [-] Stab type: %s" % sym['stab_type']
                            else:
                                print "        [-] Limited global scope: %s" % sym['limited_global_scope']
                                print "        [-] Type: %s" % sym['n_type']
                                print "        [-] External: %s" % sym['external']
            i += 1
