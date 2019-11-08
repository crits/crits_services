from crits.services.core import Service

from . import pylnker

class LnkService(Service):
    name = "LnkService"
    version = "0.1"
    supported_types  = ['Sample']
    description = "Parses features from an LNK file"

    def run(self, obj, config):
        fname = obj.filename
        fh = obj.filedata
        fh.seek(0)
        try:
            lnk_info = pylnker.parse_lnk(fname, fh)
            self._add_result("Target Location", lnk_info['target_location'])
            if lnk_info['target_location'] == 'local volume':
                self._add_result("Base Path", lnk_info['base_path'])
            elif lnk_info['target_location'] == 'network share':
                self._add_result("Network Share Name", lnk_info['net_share_name'])
            
            if 'command_line' in lnk_info:
                self._add_result("Command Line", lnk_info['command_line'])
            if 'icon_filename' in lnk_info:
                self._add_result("Icon filename", lnk_info['icon_filename'])
            
        except Exception as E:
            import traceback
            tb = traceback.format_exc()
            self._error("Cannot parse file: %s" % str(tb))
            return
