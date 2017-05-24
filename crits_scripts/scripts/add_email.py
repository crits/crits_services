from optparse import OptionParser

# Crits imports
from crits.emails.handlers import handle_eml, handle_json, handle_yaml
from crits.core.basescript import CRITsBaseScript
from crits.vocabulary.acls import EmailACL

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        oparse = OptionParser()
        oparse.add_option("-e","--emlfile", action="store", dest="eml",
                type="string", help="EML file to import")
        oparse.add_option("-j", "--json", action="store", dest="json",
                default=False, help="JSON file to import")
        oparse.add_option("-y", "--yaml", action="store", dest="yaml",
                default=False, help="YAML file to import")
        oparse.add_option("-s","--source", action="store", dest="source",
                type="string", help="source")
        oparse.add_option("-m","--method", action="store", dest="method",
                type="string", default="", help="source method")
        oparse.add_option("-r","--reference", action="store", dest="reference",
                type="string", default="", help="source reference")
        oparse.add_option("-t", "--tlp", action="store", dest="tlp",
                type="string", default="red", help="TLP of data")
        (opts, args) = oparse.parse_args(argv)

        if not opts.eml and not opts.json and not opts.yaml:
            print "Need a filename."
            return

        if not opts.source:
            print "[-] Need a source."
            return

        if not user.has_access_to(EmailACL.WRITE):
            print "[-] User does not have permission to add email"
            return

        if opts.eml:
            filename = opts.eml
            handler = handle_eml
            method = "Command Line EML Upload"
        elif opts.json:
            filename = opts.json
            handler = handle_json
            method = "Command Line JSON Upload"
        elif opts.yaml:
            filename = opts.yaml
            handler = handle_yaml
            method = "Command Line YAML Upload"

        if opts.method:
            method = method + " - " + opts.method

        if not opts.tlp or opts.tlp not in ['red', 'amber', 'green', 'white']:
            opts.tlp = 'red'


        try:
            fh = open(filename, 'rb')
            data = fh.read()
            fh.close()
        except IOError:
            print "[-] Cannot open %s for reading!" % filename
            return
        except:
            print "[-] Cannot open file."
            return

        obj = handler(data, opts.source, opts.reference, method, opts.tlp,
                      self.user)
        if obj['status']:
            try:
                obj['object'].save()
            except Exception, e:
                message = "Failed to save object: %s " % str(e)
                print message

            print "[-] Success: %s" % obj['object'].id
            for (f, v) in obj.get('attachments', {}).items():
                print "\t[-] Attachment: %s" % v['filename']
        else:
            print "[!] Failure: %s" % obj['reason']
