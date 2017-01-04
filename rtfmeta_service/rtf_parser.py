import sys
import time
import array
import hashlib
import binascii
import struct
import re
import optparse

class RtfParser(object):

    objmeta = {
        'width': re.compile('.*\\\\objw(\d+)'),
        'height': re.compile('.*\\\\objh(\d+)'),
        'class': re.compile('.+\\\\*\\\\objclass (\S+?)\}'),
        'clsid': re.compile('.+\\\\*\\\\oleclsid (\S+?)\}'),
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
            'regex': '{\\\\\*\\\\colorschememapping',
            'name': 'colorschememapping',
            'offset': 22,
            'type': 'hash',
        },
        {
            'regex': '{\\\\\*\\\\themedata',
            'name': 'themedata',
            'offset': 12,
            'type': 'hash',
        },
        {
            'regex': '{\\\\\*\\\\blipuid',
            'name': 'blipuid',
            'offset': 11,
            'type': 'value',
        },
    ]

    time_regex = re.compile('.*\\\\yr(\d+)\\\\mo(\d+)\\\\dy(\d+)\\\\hr(\d+)\\\\min(\d+).*')


    def __init__(self, data, debug=False):
        self.debug = debug
        self.data = data
        self.objects = []
        self.features = {
            'data_len': len(data),
            'file_md5': hashlib.md5(data).hexdigest(),
            'file_sha1': hashlib.sha1(data).hexdigest(),
            'file_sha256': hashlib.sha256(data).hexdigest(),
        }
        
    def parse(self):
        if (self.features.get('data_len') <= 0) and self.is_valid() == False:
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

    def is_valid(self):
        return self.data.startswith('{\\rt')

    def binary_percent(self):
        ascii_bytes = 0
        binary_bytes = 0
        for i in range(0,self.features.get('data_len')):
            if ord(self.data[i]) > 7 and ord(self.data[i]) < 127:
                ascii_bytes += 1
            else:
                binary_bytes += 1
        self.features['binary_bytes'] = binary_bytes
        self.features['ascii_bytes'] = ascii_bytes
        self.features['binary_ratio'] = (ascii_bytes * 1.0) / self.features.get('data_len')
            
    def parse_header(self):
        self.features['rtf_header_version'] = 0
        header = re.match('^\{\\\\rtf(\d+)', self.data[:10])
        if header:
            header_val = header.group(1)
            try:
                val = int(header_val[:1])
                self.features['rtf_header_version'] = val
            except:
                pass
    
    def parse_generator(self):
        self.features['rtf_generator'] = ''
        gen_match = re.compile('{\\\\*\\\\.+generator[\x20\x07\x0d\x0a]{1,}(.+?);.*}', re.M|re.S)
        gen = gen_match.match(self.data)
        if gen:
            self.features['rtf_generator'] = gen.group(1)  
            
    def parse_code_page(self):
        self.features['ansi_code_page'] = 0
        self.features['ansi_code_page_name'] = 'unknown'
        page = re.compile('.*\\\\ansicpg(\d+)', re.M|re.S)
        match = page.match(self.data)
        if match:
            try:
                value = int(match.group(1))
                self.features['ansi_code_page'] = value
                self.features['ansi_code_page_name'] = self.code_page_map.get(value, 'unknown')
            except:
                if self.debug:
                    print "bad data"
                
    def parse_deflang(self):
        self.features['deflang'] = 0
        page = re.compile('.*\\\\deflang(\d+)', re.M|re.S)
        match = page.match(self.data)
        if match:
            try:
                self.features['deflang'] = int(match.group(1))
            except:
                if self.debug:
                    print "bad data"
                    
    def hash_data_blob(self):
        for collector in self.datablobs:
            hashes = []
            data_offset = collector.get('offset', 0)
            name = collector.get('name', 'N/A')
            hash_re = re.compile(collector.get('regex'), re.M|re.S)
            m = hash_re.finditer(self.data)
            for n in m:
                try:
                    start = n.span()[0]
                    o = self.balanced_braces(self.data[start:])
                    d = binascii.unhexlify(self.normalize_data_stream(o[data_offset:]))
                    if collector.get('type') == 'hash':
                        hashes.append(hashlib.md5(d).hexdigest())
                    elif collector.get('type') == 'value':
                        hashes.append(o[data_offset:])
                except Exception as e:
                    if self.debug:
                        print "%s barf - %s" % (self.features.get('file_md5'), e)
            self.features[name] = hashes
        
    def balanced_braces(self, arg, strip=True):
        if '{' not in arg:
            return
        chars = []
        n = 0
        for c in arg:
            if c == '{':
                if n > 0:
                    chars.append(c)
                n += 1
            elif c == '}':
                n -= 1
                if n > 0:
                    chars.append(c)
                elif n == 0:
                    if strip:
                        return ''.join(chars).lstrip().rstrip()
                    else:
                        return ''.join(chars)
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
            return "%s-%02d-%02d %02d:%02d:00" % (match.group(1), month, day, hours, mins)
            
    def parse_part(self, data):
        key_name = re.compile('[\\\\\*]{1,3}([a-zA-Z]+)[\x20\x07\x0a\x0d]{0,}(.*)')
        match = key_name.match(data)
        if match:
            key = match.group(1)
            data = match.group(2)
            if key.endswith('tim'):
                data = self.parse_time(data)
            if key in self.info_tags:
                key = self.info_tags[key]
            return {key:data}
        return {}
            
    def parse_info(self):
        info = {}
        data = self.balanced_braces(self.data[self.data.find('{\\info'):])
        if data == None:
            return info
        info_data = re.sub('[\x0d\x0a\x07]', '', data)
        x = 5
        while x < len(info_data):
            part = self.balanced_braces(info_data[x:], False)
            if part:
                info.update(self.parse_part(part.strip().rstrip()))
                x += len(part) + 2
            else:
                break
        self.features.update({'info': info})

    def binhex_convert(self, match):
        return binascii.unhexlify(match.group(1))
        
    def escape_char(self, match):
        return match.group(1)

    def normalize_data_stream(self, data):
        return re.sub('\W', '', re.sub('\{.+?\}', '', re.sub('\\\\([\d]{2})', self.binhex_convert, data)))
            
            
    def read_length_prefixed_string(self, data):
        if len(data) < 4:
            return None, 0
        str_len = struct.unpack('I', data[:4])[0]
        if len(data) < (4 + str_len):
            return None, 4
        string = data[4:4+str_len].replace('\x00', '')
        return string, str_len + 4
        
            
    def parse_embedded(self, data):
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
            props[item] = value
            offset += size
        data_len = struct.unpack('I', data[offset:offset+4])[0]
        offset += 4
        props['data_size'] = data_len
        return props, offset
        
    def parse_data_object(self):
        objects = []
        obj = re.compile('{\\\\object', re.M|re.S)
        m = obj.finditer(self.data)
        for n in m:
            try:
                obj = {}
                start = n.span()[0]
                data = self.data[start:]
                data = re.sub('\\\\([\{\}])', '', data)
                data = self.balanced_braces(data)
                for name, rex in self.objmeta.iteritems():
                    m = rex.match(data)
                    if m:
                        obj[name] = m.group(1)
                data = data.replace('\r', '').replace('\n', '').lower()
                obj_offset = data.find('{\\*\\objdata')
                if obj_offset < 0:
                    continue
                obj['offset'] = start
                obj['data_offset'] = start + obj_offset + 12
                objdata = self.balanced_braces(data[obj_offset:])
                obj['raw_md5'] = hashlib.md5(objdata).hexdigest()
                obj['raw_sha1'] = hashlib.sha1(objdata).hexdigest()
                obj['raw_sha256'] = hashlib.sha256(objdata).hexdigest()
                try:
                    d = binascii.unhexlify(self.normalize_data_stream(objdata[11:]))
                    obj['md5'] = hashlib.md5(d).hexdigest()
                    obj['sha1'] = hashlib.sha1(d).hexdigest()
                    obj['sha256'] = hashlib.sha256(d).hexdigest()
                    obj['raw_size'] = len(d)
                    props, prop_len = self.parse_embedded(d)
                    obj.update(props)
                    if d[prop_len:props.get('data_size', 0)] > 0:
                        self.objects.append(d[prop_len:props.get('data_size', 0)])
                    obj['parsed'] = 1
                except Exception as e:
                    obj['parsed'] = 0
                    if self.debug:
                        print "%s - bad obj - %s" % (self.features.get('file_md5'), e)
                objects.append(obj)
            except Exception as e:
                if self.debug:
                    print "object parsing barf at %08x - %s" % (start, e)
        self.features.update({'objects': objects})
        
    def parse_datastore_object(self):
        datastore_objects = []
        ds = re.compile('{\\\\\*\\\\datastore', re.M|re.S)
        m = ds.finditer(self.data)
        for n in m:
            try:
                obj = {}
                start = n.span()[0]
                o = self.balanced_braces(self.data[start:])
                o = o.replace('\r', '').replace('\n', '').lower()
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
                self.objects.append(d[prop_len:props.get('data_size', 0)])
                datastore_objects.append(obj)
            except Exception as e:
                if self.debug:
                    print "%s barf - %s" % (self.features.get('file_md5'), e)
        self.features.update({'datastores': datastore_objects})
    
    def output(self):
        print "File MD5: %s" % self.features.get('file_md5')
        print "File size: %s" % self.features.get('data_len')
        if self.features.get('valid_rtf') != 1:
            print "** Not a valid RTF **"
            return
        print "Binary Ratio: %.02f" % self.features.get('binary_ratio')
        print "Binary Bytes: %d" % self.features.get('binary_bytes')
        print "Rtf Version: %d" % self.features.get('rtf_header_version')
        print "Rtf Generator: %s" % self.features.get('rtf_generator')
        print "Rtf Code Page: %d" % self.features.get('ansi_code_page')
        print "Rtf Code Page Name: %s" % self.features.get('ansi_code_page_name')
        print "Rtf Default lang: %d" % self.features.get('deflang')
        print "Rtf Colorschemes:"
        for scheme in self.features.get('colorschememapping', []):
            print "%40s" % scheme
        print "Rtf Themedata:"
        for scheme in self.features.get('themedata', []):
            print "%40s" % scheme
        print "Rtf Blipuid:"
        for scheme in self.features.get('blipuid', []):
            print "%40s" % scheme
        print "Rtf Meta Info:"
        for (k, v) in self.features.get('info', {}).items():
            print "%20s: %s" % (k,v)
        print "Rtf Object Info:"
        for obj in self.features.get('objects', []):
            print "Object:"
            for (k,v) in obj.items():
                val = hex(v) if type(v) == int else v
                print "%20s: %s" % (k,val)
        print "Rtf Datastore Object Info:"
        for obj in self.features.get('datastores', []):
            print "Object:"
            for (k,v) in obj.items():
                val = hex(v) if type(v) == int else v
                print "%20s: %s" % (k,val)
        for i in range(len(self.objects)):
            filename = "%s.%d.%s" % (self.features.get('file_md5'), i, 'out')
            print "Saving %d bytes from object to %s" % (len(self.objects[i]), filename)
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