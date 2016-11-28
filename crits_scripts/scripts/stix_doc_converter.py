# (c) 2013, Bloomberg Finance L.P.  All rights reserved.
# Source code distributed pursuant to license agreement.
import os
import datetime
import argparse
from io import BytesIO

from lxml import etree
from crits.core.basescript import CRITsBaseScript
from stix.core import STIXPackage

class CRITsScript(CRITsBaseScript):
    """This script converts certain kinds of non-standard STIX documents to
    something which is reasonably more standard.

    This script may not convert completely correctly, caveat emptor.
    """

    XML_NS_PREFIX_XSI = "xsi"
    XML_NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

    XML_NS_PREFIX_STIX = "stix"
    XML_NS_STIX = "http://stix.mitre.org/stix-1"

    XML_NS_PREFIX_STIX_COMMON = "stixCommon"
    XML_NS_STIX_COMMON = "http://stix.mitre.org/common-1"

    XML_NS_PREFIX_CISCP = "ciscp"
    XML_NS_CISCP = "http://www.us-cert.gov/ciscp"

    XML_NS_PREFIX_CYBOX = "cybox"
    XML_NS_CYBOX = "http://cybox.mitre.org/cybox-2"

    XML_NS_PREFIX_OBJ_DOMAIN = "DomainObj"
    XML_NS_OBJ_DOMAIN = "http://cybox.mitre.org/objects#DomainObject-1"

    XML_NS_PREFIX_OBJ_URI = "URIObj"
    XML_NS_OBJ_URI = "http://cybox.mitre.org/objects#URIObject-2"

    XML_NS_DICT = {XML_NS_PREFIX_XSI : XML_NS_XSI,
                   XML_NS_PREFIX_STIX : XML_NS_STIX,
                   XML_NS_PREFIX_STIX_COMMON : XML_NS_STIX_COMMON,
                   XML_NS_PREFIX_CISCP : XML_NS_CISCP,
                   XML_NS_PREFIX_CYBOX : XML_NS_CYBOX,
                   XML_NS_PREFIX_OBJ_DOMAIN : XML_NS_OBJ_DOMAIN,
                   XML_NS_PREFIX_OBJ_URI : XML_NS_OBJ_URI}

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

        etree.register_namespace(self.XML_NS_PREFIX_STIX, self.XML_NS_STIX)
        etree.register_namespace(self.XML_NS_PREFIX_STIX_COMMON, self.XML_NS_STIX_COMMON)
        etree.register_namespace(self.XML_NS_PREFIX_CISCP, self.XML_NS_CISCP)
        etree.register_namespace(self.XML_NS_PREFIX_CYBOX, self.XML_NS_CYBOX)
        etree.register_namespace(self.XML_NS_PREFIX_OBJ_DOMAIN, self.XML_NS_OBJ_DOMAIN)
        etree.register_namespace(self.XML_NS_PREFIX_OBJ_URI, self.XML_NS_OBJ_URI)

    def _add_namespaces(self, root):
        """Adds the URI namespace declaration to the root object if it is not present.
        This method is necessary because you cannot modify the nsmap attribute
        of an etree Element object.

        Keyword arguments:
        root -- the root etree Element object
        """
        uri_prefix = self._get_prefix_for_namespace(self.XML_NS_OBJ_URI, root.nsmap)

        if not uri_prefix:
            nsmap = root.nsmap
            nsmap[self.XML_NS_PREFIX_OBJ_URI] = self.XML_NS_OBJ_URI
            new_root = etree.Element(root.tag, nsmap=nsmap)
            new_root[:] = root[:]
            return new_root

        return root

    def _get_etree_root(self, xml):
        """Returns an etree object for the given CISCP input. Etree has namespaces
        added to it that are necessary to the processing of the CISCP document.

        Keyword arguments:
        xml -- filename or file-like object containing xml
        """

        tree = etree.parse(xml)
        root = self._add_namespaces(tree.getroot())
        return root

    def _get_prefix_for_namespace(self, ns, nsmap):
        """Returns a namespace prefix for a given nsmap. This is used because lxml Element nsmap
        dictionaries are formatted as '{prefix:namespace}'

        Keyword arguments:
        ns -- the namespace we are attempting to find a prefix for
        nsmap -- a dictionary containing prefix-to-namespace mappings
        """
        for k,v in nsmap.iteritems():
            if v == ns:
                return k

        return None

    def _get_stix_package_list(self, e_root):
        """Returns a list of etree elements containing STIX_Package elements

        Keyword arguments:
        e_root -- a root etree Element object
        """
        tag_package = "{%s}STIX_Package" % (self.XML_NS_STIX)

        if e_root.tag == tag_package:
            packages = [e_root] # if the root element is a STIX_Package, return a list with it as the only item
        else:
            packages = e_root.findall(tag_package)

        return packages

    def _fix_domain_obj(self, xmlobj):
        """Changes CISCP Domain Objects into CybOX URI Objects

        Keyword arguments
        xmlobj -- an etree Element object
        """
        tag_xsi_type = "{%s}type" % (self.XML_NS_XSI)
        tag_uri_value = "{%s}Value" % (self.XML_NS_OBJ_URI)

        xpath_domain_obj = ".//%s:Properties[@%s:type='%s:DomainObjectType' and @type='FQDN']" % (self.XML_NS_PREFIX_CYBOX, self.XML_NS_PREFIX_XSI, self.XML_NS_PREFIX_OBJ_DOMAIN)
        domain_objs = xmlobj.xpath(xpath_domain_obj, namespaces=self.XML_NS_DICT)

        if domain_objs is not None and len(domain_objs) > 0:
            uri_obj_prefix = self._get_prefix_for_namespace(self.XML_NS_OBJ_URI, xmlobj.nsmap) # this should always return a value

            for domain_obj in domain_objs:
                domain_obj.attrib[tag_xsi_type] = "%s:URIObjectType" % (uri_obj_prefix)
                domain_obj.attrib['type'] = 'Domain Name'
                value = domain_obj.find('{%s}Value' % (self.XML_NS_OBJ_DOMAIN))
                if value is not None: value.tag = tag_uri_value

    def _fix_information_source(self, e_package, source=None):
        """Adds an Information_Source to the STIX Header if not present.
        If Information_Source is not present, it is added with an Identity
        child element.

        Key argument:
        e_package -- STIX_Package etree Element object
        """
        tag_stix_header = "{%s}STIX_Header" % (self.XML_NS_STIX)
        tag_information_source = "{%s}Information_Source" % (self.XML_NS_STIX)
        tag_identity = "{%s}Identity" % (self.XML_NS_STIX_COMMON)
        tag_name = "{%s}Name" % (self.XML_NS_STIX_COMMON)

        stix_header = e_package.find(tag_stix_header)
        if stix_header is None:
            stix_header = etree.Element(tag_stix_header)
            e_package.insert(0, stix_header)

        information_source = stix_header.find(tag_information_source)
        if information_source is None:
            information_source = etree.Element(tag_information_source)
            stix_header.append(information_source)

        identity = information_source.find(tag_identity)
        if identity is None:
            identity = etree.Element(tag_identity)
            information_source.insert(0, identity)

        name = identity.find(tag_name)
        if name is None:
            name = etree.Element(tag_name)
            identity.insert(0, name)

            if source:
                name.text = source

    def convert_ciscp(self, ciscp_content, source=None):
        """Returns a list of STIX_Package etree Element objects
        that have been broken out from a CISCP STIX_Packages container.

        Each STIX Package has had the following operations performed on it:
        + Domain Object of type "FQDN" converted to URI Object of type "Domain Name"

        Keyword arguments:
        ciscp_content -- a filename or filelike object containing the CISCP STIX_Packages element
        """
        root = self._get_etree_root(ciscp_content)
        packages = self._get_stix_package_list(root)

        for package in packages:
            self._fix_domain_obj(root)
            self._fix_information_source(package, source)

        return packages

    def get_api_packages(self, packages):
        """Returns a list of python-stix api STIXPackage objects.

        Keyword arguments:
        packages -- a list of STIX_Package etree Element objects
        """
        api_packages = []
        for package in packages:
            xml = etree.tostring(package)
            bytesio = BytesIO(xml)
            stix_package = STIXPackage.from_xml(bytesio)
            api_packages.append(stix_package[0])

        return api_packages


    def write_packages(self, packages, dir=None):
        """Writes a file for each package in supplied list of packages.

        Keyword arguments:
        packages -- list of STIX_Package etree Element objects
        """
        count = 1
        day = datetime.date.today().strftime("%Y%m%d")

        for package in packages:
            fn = 'ciscp-'+ day +'-' + str(count) + ".xml"

            if dir:
                path_output = os.path.join(dir, fn)
            else:
                path_output = fn

            et = etree.ElementTree(package)
            et.write(path_output, pretty_print=True)
            count = count + 1

    def run(self, argv):
        argparser = argparse.ArgumentParser(description="CISCP Package Converter")
        argparser.add_argument("-o", "--outdir", action="store", dest="dir", default=None, help="Directory to write to.")
        argparser.add_argument("-i", "--infile", action="store", dest="infile", required=True, help="File to read.")
        argparser.add_argument("-s", "--source", action="store", dest="source", default=None, help="Identity source name.")

        args = argparser.parse_args()
        try:
            fn = args.infile
            f = open(fn, 'r')
        except IOError:
            print("[!] Cannot open %s for reading!" % (fn))
            return
        except:
            print("[!] Cannot open file")
            return

        packages = self.convert_ciscp(f, args.source)
        self.write_packages(packages, args.dir)

        # The code below converts these into python-stix api objects
        # and prints them out to stdout
        #api_packages = get_api_packages(packages)

        #for api_package in api_packages:
        #    print api_package.to_xml()
