import tempfile
import os
import hashlib
from lxml import etree

from django.conf import settings
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from subprocess import Popen, STDOUT, PIPE

from crits.pcaps.pcap import PCAP
from crits.pcaps.handlers import handle_pcap_file
from crits.core.mongo_tools import get_file_gridfs, put_file_gridfs
from crits.core.user_tools import get_user_organization
from crits.services.handlers import get_config

from crits.vocabulary.objects import ObjectTypes


def pcap_tcpdump(pcap_md5, form, analyst):
    flag_list = []
    cleaned_data = form.cleaned_data

    # Make sure we can find tcpdump
    sc = get_config('MetaCap')
    tcpdump_bin = str(sc['tcpdump'])
    if not os.path.exists(tcpdump_bin):
        tcpdump_output = "Could not find tcpdump!"
        return tcpdump_output

    # Make sure we have a PCAP to work with
    pcap = PCAP.objects(md5=pcap_md5).first()
    if not pcap:
        return "No PCAP found"
    pcap_data = pcap.filedata.read()
    if not pcap_data:
        return "Could not get PCAP from GridFS: %s" %  pcap_md5

    # Use the filename if it's there, otherwise the md5.
    # This is used for the description of the carved sample.
    if pcap.filename:
        pcap_filename = pcap.filename
    else:
        pcap_filename = pcap_md5

    # Setup tcpdump arguments
    if cleaned_data['sequence']:
        flag_list.append("-S")
    if cleaned_data['timestamp']:
        flag_list.append("%s" % cleaned_data['timestamp'])
    if cleaned_data['verbose']:
        flag_list.append("%s" % cleaned_data['verbose'])
    if cleaned_data['data']:
        flag_list.append("%s" % cleaned_data['data'])
    # force -nN
    flag_list.append("-nN")
    # if we need to carve
    if cleaned_data['carve']:
        if not cleaned_data['bpf']:
            return "Must supply a BPF filter to carve."
        new_pcap = tempfile.NamedTemporaryFile(delete=False)
        flag_list.append("-w")
        flag_list.append(new_pcap.name)

    if cleaned_data['bpf']:
        flag_list.append('%s' % str(cleaned_data['bpf'].replace('"', '')))

    # write PCAP to disk
    # temp_out collects stdout and stderr
    # temp_pcap is the pcap to read
    # new_pcap is the pcap being written if carving
    temp_out = tempfile.NamedTemporaryFile(delete=False)
    temp_pcap = tempfile.NamedTemporaryFile(delete=False)
    pcap_name = temp_pcap.name
    temp_pcap.write(pcap_data)
    temp_pcap.close()
    args = [tcpdump_bin, '-r', temp_pcap.name] + flag_list
    tcpdump = Popen(args, stdout=temp_out, stderr=STDOUT)
    tcpdump.communicate()
    out_name = temp_out.name
    temp_out.seek(0)
    tcpdump_output = ''
    for line in iter(temp_out):
        tcpdump_output += "%s" % line
    temp_out.close()

    #delete temp files
    os.unlink(pcap_name)
    os.unlink(out_name)

    if cleaned_data['carve']:
        new_pcap_data = new_pcap.read()
        if len(new_pcap_data) > 24: # pcap-ng will change this.
            m = hashlib.md5()
            m.update(new_pcap_data)
            md5 = m.hexdigest()
            org = get_user_organization(analyst)
            result = handle_pcap_file("%s.pcap" % md5,
                                      new_pcap_data,
                                      org,
                                      user=analyst,
                                      description="%s of %s" % (cleaned_data['bpf'], pcap_filename),
                                      parent_id=pcap.id,
                                      parent_type="PCAP",
                                      method="MetaCap Tcpdumper")
            if result['success']:
                tcpdump_output = "<a href=\"%s\">View new pcap.</a>" % reverse('crits-pcaps-views-pcap_details', args=[result['md5']])
            else:
                tcpdump_output = result['message']
        else:
            tcpdump_output = "No packets matched the filter."

        os.unlink(new_pcap.name)

    return tcpdump_output

def pcap_pdml_html(pcap_md5, analyst):
    # check to see if there is a File object with the source reference of
    # 'tshark_pdml.html'. If there is, return it.
    # If not, generate it, save it, and return it.
    pcap = PCAP.objects(md5=pcap_md5).first()
    if not pcap:
        return "No PCAP found"
    else:
        coll = settings.COL_OBJECTS
        pdml_obj = None
        pdml_html = None
        for obj in pcap.obj:
            for source in obj.source:
                for instance in source.instances:
                    if instance.reference == 'tshark_pdml.html':
                        pdml_obj = obj
        if not pdml_obj:
            sc = get_config('MetaCap')
            tshark_bin = str(sc['tshark'])
            if not os.path.exists(tshark_bin):
                pdml_html = "Could not find tshark!"
                return {'html': pdml_html}

            pcap_data = pcap.filedata.read()
            if not pcap_data:
                pdml_html =  "Could not get PCAP from GridFS: %s" %  pcap_md5
                return {'html': pdml_html}

            # write PCAP to disk
            temp_pcap = tempfile.NamedTemporaryFile(delete=False)
            pcap_name = temp_pcap.name
            temp_pcap.write(pcap_data)
            temp_pcap.close()

            # use tshark to generate a pdml file
            temp_pdml = tempfile.NamedTemporaryFile(delete=False)
            args = [tshark_bin, "-n", "-r", pcap_name, "-T", "pdml"]
            tshark = Popen(args, stdout=temp_pdml, stderr=PIPE)
            tshark_out, tshark_err = tshark.communicate()
            if tshark.returncode != 0:
                return {'html': "%s, %s" % (tshark_out,tshark_err)}
            pdml_name = temp_pdml.name
            temp_pdml.seek(0)

            # transform PDML into HTML
            xsl_file = None
            for d in settings.SERVICE_DIRS:
                try:
                    file_dir = "%s/metacap_service" % d
                    xsl_file = open('%s/pdml2html.xsl' % file_dir, 'r')
                except IOError:
                    pass
            if not xsl_file:
                return {'html': 'Could not find XSL.'}

            parser = etree.XMLParser()
            parser.resolvers.add(FileResolver())
            save_pdml = False
            try:
                xml_input = etree.parse(temp_pdml, parser)
                xslt_root = etree.parse(xsl_file, parser)
                transform = etree.XSLT(xslt_root)
                pdml_html = str(transform(xml_input))
                save_pdml = True
            except Exception:
                temp_pdml.close()
                # delete PDML file
                os.unlink(pdml_name)
                os.unlink(pcap_name)
                return {'html': 'Could not parse/transform PDML output!'}

            temp_pdml.close()

            # delete PDML file
            os.unlink(pdml_name)
            os.unlink(pcap_name)

            #  save pdml_html as an object for this PCAP
            if save_pdml:
                fn = put_file_gridfs('tshark_pdml.html', pdml_html, collection=coll)
                if fn:
                    m = hashlib.md5()
                    m.update(pdml_html)
                    md5 = m.hexdigest()
                    pcap.add_object(ObjectTypes.FILE_UPLOAD,
                                    md5,
                                    get_user_organization(analyst),
                                    "MetaCap",
                                    'tshark_pdml.html',
                                    analyst)
                    pcap.save()
        else:
            # get file from gridfs and return it
            obj_md5 = pdml_obj.value
            pdml_html = get_file_gridfs(obj_md5, collection=coll)
            if not pdml_html:
                return {'html': 'No file found in GridFS'}
        if not pdml_obj:
            pcap_objects = pcap.sort_objects()
            return {'html': pdml_html, 'objects': pcap_objects, 'id': pcap.id}
        else:
            return {'html': pdml_html}

class FileResolver(etree.Resolver):
        def resolve(self, url, pubid, context):
                    return self.resolve_filename(url, context)
