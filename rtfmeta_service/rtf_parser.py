'''
Copyright 2004-present Facebook. All Rights Reserved.
'''

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import binascii
import hashlib
import optparse
import re
import struct
import sys

class RtfParser(object):
    """An RTF document parser. It is used to parse useful information from
    a RTF document. The information includes hashes and values found in the
    document that can be used to correlate malicious documents."""
    
    objmeta = {
        'width': re.compile(r'.*\\objw(\d+)'),
        'height': re.compile(r'.*\\objh(\d+)'),
        'class': re.compile(r'.+\\*\\objclass (\S+?)\}'),
        'clsid': re.compile(r'.+\\*\\oleclsid (\S+?)\}'),
    }
    
    info_tags = {
        'author': 'author',
        'operator': 'operator',
        'creatim': 'create_time',
        'revtim': 'revise_time',
        'printim': 'print_time',
        'version': 'version',
        'edmins': 'edit_mins',
        'nofwords': 'no_words',
        'nofchars': 'no_chars',
        'vern': 'internal_version',
        'nofpages': 'no_pages',
        'version': 'version',
    }

    code_page_map = {
        708: 'Arabic',
        852: 'Eastern European',
        862: 'Hebrew',
        932: 'Japanese',        
        936: 'Simplified Chinese',
        949: 'Korean',
        950: 'Traditional Chinese',
        1250: 'Eastern European',
        1251: 'Cyrillic',
        1252: 'Western European',
        1253: 'Greek',
        1254: 'Turkish',
    
    }
    
    datablobs = [
        {
            'regex': r'{\\\*\\colorschememapping',
            'name': 'colorschememapping',
            'offset': 22,
            'type': 'hash',
        },
        {
            'regex': r'{\\\*\\themedata',
            'name': 'themedata',
            'offset': 12,
            'type': 'hash',
        },
        {
            'regex': r'{\\\*\\blipuid',
            'name': 'blipuid',
            'offset': 11,
            'type': 'value',
        },
    ]

    time_regex = re.compile(r'.*\\yr(\d+)\\mo(\d+)\\dy(\d+)\\hr(\d+)\\min(\d+).*')

    binascii_range = range(0x30, 0x7a)
    whitespace_range = (0x20, 0x0a, 0x0d, 0x07)
    number_range = range(0x30, 0x39)

    def __init__(self, data, debug=False):
        if type(data) == str:
            self.data = bytearray(data)
        else:
            self.data = data
        self.debug = debug
        self.objects = []
        self.features = {
            'data_len': len(data),
            'file_md5': hashlib.md5(data).hexdigest(),
            'file_sha1': hashlib.sha1(data).hexdigest(),
            'file_sha256': hashlib.sha256(data).hexdigest(),
        }
        
    def parse(self):
        if (self.features.get('data_len') <= 0) or self.is_valid() == False:
            self.features['valid_rtf'] = 0
            return
        self.features['valid_rtf'] = 1
        self.binary_percent()
        self.parse_header()
        self.parse_generator()
        self.parse_code_page()
        self.parse_deflang()
        self.parse_info()
        self.parse_data_object()
        self.parse_datastore_object()
        self.hash_data_blob()
        self.parse_rsid()
        self.parse_bliptag()

    def is_valid(self):
        return self.data.startswith(b'{\\rt')
        
    def unique_list(self, input_list):
        """Return unique values from input_list"""
        output_list = []
        [output_list.append(i) for i in input_list if i not in output_list]
        return output_list

    def binary_percent(self):
        """Calculates the percentage of bytes that are binary vs ascii"""
        ascii_bytes = 0
        binary_bytes = 0
        for i in range(0,self.features.get('data_len')):
            if self.data[i] > 7 and self.data[i] < 127:
                ascii_bytes += 1
            else:
                binary_bytes += 1
        self.features['binary_bytes'] = binary_bytes
        self.features['ascii_bytes'] = ascii_bytes
        data_len = self.features.get('data_len')
        self.features['binary_ratio'] = (ascii_bytes * 1.0) / data_len
            
    def parse_header(self):
        self.features['rtf_header_version'] = 0
        header = re.match(r'^\{\\rtf(\d+)', self.data[:10])
        if header:
            header_val = header.group(1)
            try:
                val = int(header_val[:1])
                self.features['rtf_header_version'] = val
            except Exception:
                pass
    
    def parse_generator(self):
        """Parse RTF generator field"""
        self.features['rtf_generator'] = ''
        gen_match = re.compile(
            r'{\\*\\.+generator[\x20\x07\x0d\x0a]{1,}(.+?);.*}',
            re.M | re.S
        )
        gen = gen_match.match(self.data)
        if gen:
            self.features['rtf_generator'] = gen.group(1).decode('utf-8') 
            
    def parse_code_page(self):
        """Parse RTF code page"""
        self.features['ansi_code_page'] = 0
        self.features['ansi_code_page_name'] = u'unknown'
        page = re.compile(r'.*\\ansicpg(\d+)', re.M | re.S)
        match = page.match(self.data)
        if match:
            try:
                value = int(match.group(1))
                self.features['ansi_code_page'] = value
                self.features['ansi_code_page_name'] = \
                    self.code_page_map.get(value, 'unknown')
            except Exception:
                if self.debug:
                    print('Could not convert ansi code page to int')
                
    def parse_deflang(self):
        """Parse RTF default language setting"""
        self.features['deflang'] = 0
        page = re.compile(r'.*\\deflang(\d+)', re.M | re.S)
        match = page.match(self.data)
        if match:
            try:
                self.features['deflang'] = int(match.group(1))
            except Exception:
                if self.debug:
                    print('Could not convert deflang to int')
                    
    def hash_data_blob(self):
        """Hashes various data blobs as defined in datablobs regex.
        Each datablob can be of type 'hash', meaning to hash the contents
        inside the object, or type 'value', which means to read the value after
        the tag"""
        for collector in self.datablobs:
            hashes = []
            data_offset = collector.get('offset', 0)
            name = collector.get('name', 'N/A')
            hash_re = re.compile(collector.get('regex'), re.M | re.S)
            m = hash_re.finditer(self.data)
            for n in m:
                try:
                    start = n.span()[0]
                    o = self.balanced_braces(self.data[start:])
                    if collector.get('type') == 'hash':
                        n = self.normalize_data_stream(o[data_offset:])
                        d = binascii.unhexlify(n)
                        hashes.append(hashlib.md5(d).hexdigest())
                    elif collector.get('type') == 'value':
                        result = bytes(o[data_offset:]).decode('utf-8')
                        hashes.append(result)
                except Exception as e:
                    if self.debug:
                        print("%s - %s" % (self.features.get('file_md5'), e))
            self.features[name] = self.unique_list(hashes)
        
    def balanced_braces(self, arg, strip=True):
        """Returns the contents inside a pair of balanced {} braces. This
        is required when parsing various RTF artifacts as the braces delimit
        content associated with a specific tag."""
        if b'{' not in arg:
            return
        chars = []
        n = 0
        for c in arg:
            if c == 0x7b:
                if n > 0:
                    chars.append(c)
                n += 1
            elif c == 0x7d:
                n -= 1
                if n > 0:
                    chars.append(c)
                elif n == 0:
                    if strip:
                        return bytearray(chars).strip()
                    else:
                        return bytearray(chars)
                    chars = []
            elif n > 0:
                chars.append(c)

    def parse_time(self, data):
        match = self.time_regex.match(data)
        if match:
            mins = int(match.group(5))
            hours = int(match.group(4))
            month = int(match.group(2))
            day = int(match.group(3))
            year = match.group(1).decode('utf-8')
            return u'%s-%02d-%02d %02d:%02d:00' % \
                (year, month, day, hours, mins)

    def parse_part(self, data):
        key_name = re.compile(
            r'[\\\*]{1,3}([a-zA-Z]+)[\x20\x07\x0a\x0d]{0,}(.*)')
        match = key_name.match(data)
        if match:
            key = match.group(1)
            data = match.group(2)
            if key.endswith(b'tim'):
                data = self.parse_time(data)
            if type(key) in (bytearray, bytes):
                key = key.decode('utf-8')
            if type(data) in (bytearray, bytes):
                data = data.decode('utf-8')
            if key in self.info_tags:
                key = self.info_tags[key]
            return {key: data}
        return {}

    def parse_info(self):
        info = {}
        data = self.balanced_braces(self.data[self.data.find(b'{\\info'):])
        if data is None:
            return info
        info_data = re.sub(r'[\x0d\x0a\x07]', b'', data)
        x = 5
        while x < len(info_data):
            part = self.balanced_braces(info_data[x:], False)
            if part:
                result = self.parse_part(part.strip().rstrip())
                info.update(result)
                x += len(part) + 2
            else:
                break
        self.features.update({'info': info})

    def normalize_data_stream(self, data):
        x = 0
        out = bytearray()
        while x < len(data):
            if data[x] in self.whitespace_range:
                 x += 1
                 continue
            if data[x] == 0:
                x += 1
                continue
            if data[x] == ord('\\'):
                if data[x+1] in (ord('{'), ord('}')):
                    x += 2
                    continue
                if data[x + 1: x + 4] == b'dde':
                    x += 4
                    y = 0
                    while y < 250 and data[x:x+2] == b'00':
                        x += 2
                        y += 2
                    continue
                if data[x + 1: x + 2] == b'li':
                    while data[x + 3] in self.number_range:
                        x += 1
                    x += 3
                    continue
                if data[x+1] == ord('x'):
                    x + 1
                    # do not continue here, process as binascii
                if data[x + 1] in self.binascii_range:
                    if data[x + 2] in self.binascii_range:
                        out_byte = \
                            binascii.unhexlify(data[x + 1:x + 3])
                        if ord(out_byte) not in self.whitespace_range:
                            out += bytearray(out_byte)
                        x += 3
                    continue
            elif data[x] == ord('{'):
                while data[x] != ord('}'):
                    x += 1
                x += 1
            else:
                out += data[x:x + 1]
                x += 1
        return out

    def read_length_prefixed_string(self, data):
        if len(data) < 4:
            return None, 0
        str_len = struct.unpack(u'I', data[:4])[0]
        if len(data) < (4 + str_len):
            return None, 4
        string = data[4:4 + str_len].replace(b'\x00', b'')
        return string, str_len + 4
        
            
    def parse_embedded(self, data):
        # structure documented here
        # https://msdn.microsoft.com/en-us/library/dd942076.aspx
        if len(data) < 13:
            return {}, len(data)
        props = {
            'ole_version': struct.unpack('I', data[:4])[0],
            'format_id': struct.unpack('I', data[4:8])[0],
        }
        offset = 8
        for item in ['classname', 'topicname', 'itemname']:
            value, size = self.read_length_prefixed_string(data[offset:])
            props[item] = value.decode('utf-8')
            offset += size
        data_len = struct.unpack('I', data[offset:offset + 4])[0]
        offset += 4
        props['data_size'] = data_len
        return props, offset
        
    def parse_data_object(self):
        objects = []
        obj = re.compile(r'{\\object', re.M | re.S)
        m = obj.finditer(self.data)
        for n in m:
            try:
                obj = {}
                start = n.span()[0]
                data = self.data[start:]
                data = data.replace(b'\x00', b'')
                data = re.sub(r'\\([\{\}])', b'', data)
                data = self.balanced_braces(data)
                for name, rex in self.objmeta.items():
                    m = rex.match(data)
                    if m:
                        obj[name] = m.group(1).decode('utf-8')
                data = data.replace(b'\r', b'').replace(b'\n', b'').replace(b'\t', b'').lower()
                marker = b'{\\*\\objdata'
                marker_len = len(marker)
                obj_offset = data.find(marker)
                if obj_offset < 0:
                    continue
                obj['offset'] = start
                obj['data_offset'] = start + obj_offset + marker_len + 1
                objdata = self.balanced_braces(data[obj_offset:])
                obj['raw_md5'] = hashlib.md5(objdata).hexdigest()
                obj['raw_sha1'] = hashlib.sha1(objdata).hexdigest()
                obj['raw_sha256'] = hashlib.sha256(objdata).hexdigest()
                try:
                    result = self.normalize_data_stream(objdata[11:])
                    d = binascii.unhexlify(result)
                    obj['md5'] = hashlib.md5(d).hexdigest()
                    obj['sha1'] = hashlib.sha1(d).hexdigest()
                    obj['sha256'] = hashlib.sha256(d).hexdigest()
                    obj['raw_size'] = len(d)
                    props, prop_len = self.parse_embedded(d)
                    obj.update(props)
                    if len(d[prop_len:props.get('data_size', 0)]) > 0:
                        final_obj_data = d[prop_len:props.get('data_size', 0)]
                        obj['content_md5'] = hashlib.md5(final_obj_data).hexdigest()
                        self.objects.append(final_obj_data)
                    obj['parsed'] = 1
                except Exception as e:
                    obj['parsed'] = 0
                    if self.debug:
                        print("%s - bad obj - %s" % (self.features.get('file_md5'), e))
                objects.append(obj)
            except Exception as e:
                if self.debug:
                    print("object parsing barf at %08x - %s" % (start, e))
        self.features.update({'objects': objects})
        
    def parse_datastore_object(self):
        datastore_objects = []
        ds = re.compile(r'{\\\*\\datastore', re.M | re.S)
        m = ds.finditer(self.data)
        for n in m:
            try:
                obj = {}
                start = n.span()[0]
                o = self.balanced_braces(self.data[start:])
                o = o.replace(b'\r', b'').replace(b'\n', b'').lower()
                obj['offset'] = start
                obj['data_offset'] = start + 14
                objdata = o[13:]
                obj['raw_md5'] = hashlib.md5(objdata).hexdigest()
                obj['raw_sha1'] = hashlib.sha1(objdata).hexdigest()
                obj['raw_sha256'] = hashlib.sha256(objdata).hexdigest()
                d = binascii.unhexlify(self.normalize_data_stream(objdata))
                obj['md5'] = hashlib.md5(d).hexdigest()
                obj['sha1'] = hashlib.sha1(d).hexdigest()
                obj['sha256'] = hashlib.sha256(d).hexdigest()
                obj['raw_size'] = len(d)
                props, prop_len = self.parse_embedded(d)
                obj.update(props)
                final_obj_data = d[prop_len:props.get('data_size', 0)]
                obj['content_md5'] = hashlib.md5(final_obj_data).hexdigest()
                self.objects.append(final_obj_data)
                datastore_objects.append(obj)
            except Exception as e:
                if self.debug:
                    print("%s barf - %s" % (self.features.get('file_md5'), e))
        self.features.update({'datastores': datastore_objects})

    def parse_rsid(self):
        rsids = []
        rsid_offset = self.data.find(b'{\\*\\rsidtbl')
        data = self.balanced_braces(self.data[rsid_offset:])
        if data:
            rsids = re.findall(r'\\(rsid[\d]+)', data)
        rsids = self.unique_list(rsids)
        rsids = [x.decode('utf-8') for x in rsids]
        self.features.update({'rsid': rsids})

    def parse_bliptag(self):
        bliptags = re.findall(r'\\(bliptag[\d]+)', self.data)
        bliptags = self.unique_list(bliptags)
        bliptags = [x.decode('utf-8') for x in bliptags]
        self.features.update({'bliptag': bliptags})
    
    def output(self):
        print("File MD5: %s" % self.features.get('file_md5'))
        print("File size: %s" % self.features.get('data_len'))
        if self.features.get('valid_rtf') != 1:
            print("** Not a valid RTF **")
            return
        print("Binary Ratio: %.02f" % self.features.get('binary_ratio'))
        print("Binary Bytes: %d" % self.features.get('binary_bytes'))
        print("Rtf Version: %d" % self.features.get('rtf_header_version'))
        print("Rtf Generator: %s" % self.features.get('rtf_generator'))
        print("Rtf Code Page: %d" % self.features.get('ansi_code_page'))
        print("Rtf Code Page Name: %s" % self.features.get('ansi_code_page_name'))
        print("Rtf Default lang: %d" % self.features.get('deflang'))
        print("Rtf Colorschemes:")
        for scheme in self.features.get('colorschememapping', []):
            print("%40s" % scheme)
        print("Rtf Themedata:")
        for scheme in self.features.get('themedata', []):
            print("%40s" % scheme)
        print("Rtf Blipuid:")
        for scheme in self.features.get('blipuid', []):
            print("%40s" % scheme)
        print("Rtf RSIDs:")
        for rsid in self.features.get('rsid', []):
            print("%40s" % rsid)
        print("Rtf BlipTags:")
        for blip in self.features.get('bliptag', []):
            print("%40s" % blip)
        print("Rtf Meta Info:")
        for (k, v) in self.features.get('info', {}).items():
            print("%20s: %s" % (k,v))
        print("Rtf Object Info:")
        for obj in self.features.get('objects', []):
            print("Object:")
            for (k,v) in obj.items():
                val = hex(v) if type(v) == int else v
                print("%20s: %s" % (k,val))
        print("Rtf Datastore Object Info:")
        for obj in self.features.get('datastores', []):
            print("Object:")
            for (k,v) in obj.items():
                val = hex(v) if type(v) == int else v
                print("%20s: %s" % (k,val))
        for i in range(len(self.objects)):
            filename = "%s.%d.%s" % (self.features.get('file_md5'), i, 'out')
            print("Saving %d bytes from object to %s" % (len(self.objects[i]), filename))
            with open(filename, 'wb') as f:
                f.write(self.objects[i])
        
def main():
    opts = optparse.OptionParser()
    opts.add_option("-f", dest="filename", type="str", help="File to process")
#    opts.add_option('-d', dest="dump", type="boolean", default=False, help="Dump objects")
    (options, args) = opts.parse_args()
    if options.filename:
        with open(options.filename, 'rb') as f:
            data = f.read()
        r = RtfParser(data, debug=True)
        r.parse()
        r.output()

if __name__ == '__main__':
    main()