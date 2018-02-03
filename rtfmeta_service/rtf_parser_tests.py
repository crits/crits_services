'''
Copyright 2004-present Facebook. All Rights Reserved.
'''

import unittest

from rtf_parser import RtfParser
import re
import binascii

class RtfParserTests(unittest.TestCase):
    
    def testBinaryRatio(self):
        data = [
            (bytearray(b'{\\rtf}\xff\xff\xff\xff\xff\xff'), 0.5, 6),
            (bytearray(b'{\\rtf}'), 1.0, 0),
        ]
        for d in data:
            r = RtfParser(d[0])
            r.binary_percent()
            self.assertEqual(r.features.get('binary_ratio'), d[1])
            self.assertEqual(r.features.get('binary_bytes'), d[2])
        
    def testHashes(self):
        tests = [
            ('file_md5', '8274425de767b30b2fff1124ab54abb5'),
            ('file_sha1', '2201589aa3ed709b3665e4ff979e10c6ad5137fc'),
            ('file_sha256', '0d6afb7e939f0936f40afdc759b5a354ea5427ec250a47e7b904ab1ea800a01d'),
        ]
        data = bytearray(b'{\\rtf1}')
        r = RtfParser(data)
        for t in tests:
            self.failUnless(r.features.get(t[0]) == t[1])
        
    def testLen(self):
        data = bytearray(b'{\\rtf1}')
        r = RtfParser(data)
        self.failUnless(r.features.get('data_len') == len(data))
        
    def test_HeaderVersion(self):
        versions = [
            (bytearray(b'{\\rtf1}'), 1),
            (bytearray(b'{\\rtf2}'), 2),
            (bytearray(b'{\\rt}'), 0),
            (bytearray(b'{\\rtf123412342142143124321423412431341412413}'), 1),
            (bytearray(b'1x2389r7n209t8qcproiqprtf2134poiaf'), 0),
        ]
        for version in versions:
            r = RtfParser(version[0])
            r.parse_header()
            self.assertEqual(r.features.get('rtf_header_version'), version[1])

            
    def test_Generator(self):
        data = [
            (bytearray(b'{\\rtf1{\\\\*\\\\generator Msftedit 5.41.21.2510;}}'),
                'Msftedit 5.41.21.2510'),
            (bytearray(b'{\\rtf1}'), ''),
            (bytearray(
                b'{\\rtf1{\\\\*\\\\generator\r\n Msftedit 5.41.21.2510;}}'),
                'Msftedit 5.41.21.2510'),
        ]
        for d in data:
            r = RtfParser(d[0])
            r.parse_generator()
            self.assertEqual(r.features.get('rtf_generator'), d[1])
            
    def test_CodePage(self):
        data = [
            (bytearray(
                b'{\\rtf1\\deflang936\\ansi\\ansicpg1252\\uc1\\adeff0\\deff0}'),
             1252,
             'Western European'),
            (bytearray(b'{\\rtf1}'), 0, 'unknown'),
            (bytearray(
                b'{\\rtflANsi\\ansicpg1251\\deff0\\deflang1049{\\fonttbl{\\f0' +
                b'\\fswiss\\fcharset0Arial;}{\\f1\\fswiss\\fcharset204{\\*\\' +
                b'fname Arial;}Arial CYR;}}'),
             1251,
             'Cyrillic'),
        ]
        for d in data:
            r = RtfParser(d[0])
            r.parse_code_page()
            self.assertEqual(r.features.get('ansi_code_page'), d[1])
            self.assertEqual(r.features.get('ansi_code_page_name'), d[2])

    def test_Deflang(self):
        data = [
            (bytearray(
                b'{\\rtf1\\deflang1\\ansi\\ansicpg1252\\uc1\\adeff0\\deff0}'),
             1),
            (bytearray(b'{\\rtf1}'), 0),
            (bytearray(
                b'{\\rtflANsi\\ansicpg1251\\deff0\\deflang1049{\\fonttbl{\\' +
                b'f0\\fswiss\\fcharset0Arial;}{\\f1\\fswiss\\fcharset204{\\*' +
                b'\\fname Arial;}Arial CYR;}}'),
             1049),
        ]
        for d in data:
            r = RtfParser(d[0])
            r.parse_deflang()
            self.assertEqual(r.features.get('deflang'), d[1])

    def test_NormalizeData(self):
        data = [
            (bytearray(b'the quick fox'), b'thequickfox'),
            (bytearray(b'the quick\\20fox'), b'thequickfox'),
            (bytearray(b'the \\71uick fox'), b'thequickfox'),
            (bytearray(b'010500000200000018000000\r\n4d73786d6c322e534158584d4c5265616465722e352e300'),
                b'0105000002000000180000004d73786d6c322e534158584d4c5265616465722e352e300'),
            (bytearray(b'aabb{\\*\\asfasfasdfsaffdasff}ccdd'), b'aabbccdd'),
            (bytearray(b' 000102'), b'000102'),
        ]
        for d in data:
            r = RtfParser('{\\rtf1}')
            out = r.normalize_data_stream(d[0])
            self.assertEqual(out, d[1])

    def test_InfoParse(self):
        data = bytearray(
            b'asdfasfsadfsadfdsaf{\\info{\\author ivan  }\n{\\operator ivan}' +
            b'{\\creatim\\yr2015\\mo2\\dy5\\hr11\\min7}{\\revtim\\yr2015\\mo2' +
            b'\\dy5\\hr11\\min14}{\\version8}{\\edmins0}{\\nofpages1}' +
            b'{\\nofwords9}{\\nofchars57}{\\nofcharsws65}{\\vern32774}' +
            b'{\\blargh72}{\*\company Grizli777}}asfsafasdfsa')
        info_dict = {
            'author': 'ivan',
            'operator': 'ivan',
            'version': '8',
            'no_pages': '1',
            'no_words': '9',
            'create_time': '2015-02-05 11:07:00',
            'blargh': '72',
            'company': 'Grizli777',
        }
        r = RtfParser(data)
        r.parse_info()
        for k in info_dict.keys():
            self.assertEqual(r.features.get('info', {}).get(k), info_dict[k])

    def test_BalancedBraces(self):
        tests = [
            (bytearray(b'{{a}{b}{c}}'), b'{a}{b}{c}'),
            (bytearray(b'{a}'), b'a'),
            (bytearray(b'{\n\t\r{a}\r}'), b'{a}'),
            (bytearray(b'{{{{{{{a{}}}'), None),
            (bytearray(b'\x0a\x0d\x0a\x0d'), None)
        ]
        r = RtfParser(bytearray(b'{\\rtf1}'))
        for t in tests:
            self.assertEqual(r.balanced_braces(t[0]), t[1])

    def test_ObjectParse(self):
        data = bytearray(
            b'{\\object\\objocx\\f1\\objsetsize\\objw71\\objh71' +
            b'{\\*\\objclass None}{\\*\\oleclsid \\\'7bD27CDB6E-AE6D-11cf-' +
            b'96B8-444553540000\\\'7d}{\\*\\objdata 010500000200000021000000}}')
        obj_dict = {
            'height': '71',
            'width': '71',
            'class': 'none',
            'clsid': r"\'7bD27CDB6E-AE6D-11cf-96B8-444553540000\'7d".lower(),
        }
        r = RtfParser(data)
        r.parse_data_object()
        for k in obj_dict.keys():
            self.assertEqual(r.features.get('objects', [])[0].get(k).lower(), obj_dict[k])

    
    def test_TwoOjbect(self):
        data = bytearray(
            b'{\\object\\objocx{\\*\\objdata 010500000200000021000000}}{\\' +
            b'object\\objemb{\\*\\objclass Word}{\\*\\objdata 01050000020000' +
            b'0011000000576f72642e446f63756d656e742e3132000000000000000000000' +
            b'00000}}')
        r = RtfParser(data)
        r.parse_data_object()
        self.assertEqual(len(r.features.get('objects', [])), 2)

    
    def testObjectObfs(self):
        data = r"""
        {\object\*\}objemb{\*\objclass Word.Document.12}\objw9355\objh1018{\*\objdata 
        01050000
        0200{blahblah}0000
        11000000
        576f72642e446f63756d656e742e313200
        00000000
        00000000
        003a0000}}
        """
        obj_dict = {
            'class': 'Word.Document.12',
        }
        r = RtfParser(data)
        r.parse_data_object()
        self.assertEqual(len(r.features.get('objects', [])), 1)
        for k in obj_dict.keys():
            self.assertEqual(r.features.get('objects', [])[0].get(k), obj_dict[k])

    def testObjectOfs2(self):
        data = """
        {\\object\\\x00\\}objemb{\\\x00\\objclass Word.Document.12}\\objw9355\\objh1018{\x00\\*\\\x00objdata 
        01050000
        02000000
        11000000
        576f72642e446f63756d656e742e313200}}"""
        obj_dict = {
            'class': 'Word.Document.12',
        }
        r = RtfParser(data)
        r.parse_data_object()
        self.assertEqual(len(r.features.get('objects', [])), 1)
        for k in obj_dict.keys():
            self.assertEqual(r.features.get('objects', [])[0].get(k), obj_dict[k])
            
    def testObjectWithDDE(self):
        data = '{\\object\\objocx{\\*\\objclass Word.Document.12}{\\*\\objdata \r\n' + \
               '\\dde' + ('0' * 250) + \
               '01050000020000001b0000000000000000000000000000000000000000000000000000000000000000000000000000000e0000' + \
               'd0cf11e0a1b11ae1}}'
        obj_dict = {
            'class': 'Word.Document.12',
            'sha256': '4b7174a7827d6b5bd4c339d3a5fbf2081382268fb2b92020825b287ebfd70eaa',
        }
        r = RtfParser(data)
        r.parse_data_object()
        self.assertEqual(len(r.features.get('objects', [])), 1)
        for k in obj_dict.keys():
            self.assertEqual(r.features.get('objects', [])[0].get(k), obj_dict[k])

    def testObjectParseData(self):
        data = 'asfdsaf{\\object{\\*\\objdata 68656c6c6f\r\n20776f726c64}}'
        obj_dict = {
            'raw_size': 11,
            'md5': '5eb63bbbe01eeed093cb22bb8f5acdc3',
            'sha1': '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
            'sha256': 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
            'raw_md5': '64dd2d98eb991df53bd25719cf37964e',
            'offset': 7,
            'data_offset': 26,
        }
        r = RtfParser(data)
        r.parse_data_object()
        self.assertEqual(len(r.features.get('objects', [])), 1)
        for k in obj_dict.keys():
            self.assertEqual(r.features.get('objects', [])[0].get(k), obj_dict[k])
            
    def testNoValidObject(self):
        tests = [
            '{\\notarealobject{\\*\\objdata 68656c6c6f\r\n20776f726c64}}}}}}}}}}}}}',
            '{\\object{\\*\\obafadsfjdata 0124124214213432412342134}}',
            'afasfasfsdafasfsfsafasfas',
        ]
        for t in tests:
            r = RtfParser(t)
            r.parse_data_object()
            self.assertEqual(len(r.features.get('objects', [])), 0)
        
    def testLengthPrefixedString(self):
        tests = [
            ('\x08\x00\x00\x00hellos!\x00', 'hellos!'),
            ('\x0e\x00\x00\x00\x46\x6f\x72\x6d\x73\x2e\x49\x6d\x61\x67\x65\x2e\x31\x00', 'Forms.Image.1'),
            ('\xff\xff\x00\x00\xff\xff\xff', None),
            ('\x00', None),
        ]
        r = RtfParser('{\\rtf1}')
        for t in tests:
            val, strlen = r.read_length_prefixed_string(t[0])
            if val:
                self.assertEqual(val, t[1])
                
    def testParseEmbedded(self):
        tests = [
            (
                '01050000020000000e000000466f726d732e496d6167652e3100000000000000000006000000aabbccddeeff', 
                {'classname': 'Forms.Image.1', 'format_id': 2, 'ole_version': 1281, 'data_size': 6}
            ),
            (
                '0105000000000000000000',
                {},
            ),
            (
                '0105000002000000180000004d73786d6c322e534158584d4c5265616465722e362e3000000000000000000000060000',
                {'classname': 'Msxml2.SAXXMLReader.6.0', 'format_id': 2, 'ole_version': 1281, 'data_size': 1536},
            ),
        ]
        r = RtfParser('{\\rtf1}')
        for t in tests:
            props, offset = r.parse_embedded(binascii.unhexlify(t[0]))
            for k, v in t[1].items():
                self.assertEqual(v, props[k]) 
                
    def test_ParseDataStore(self):
        tests = [
            (bytearray(
                b'{\\rtf1{\\*\\datastore 0105000002000000180000004d73786d6c32' +
                b'2e534158584d4c5265616465722e362e300000000000000000000000000' +
                b'0}}'),
                {'classname': 'Msxml2.SAXXMLReader.6.0',
                 'format_id': 2,
                 'ole_version': 1281,
                 'data_size': 0}
             ),
            (bytearray(b'{\\rtf1}'), {}),
            (bytearray(b'{\\rtf1{\\*\\datastore 01050}}'), {})
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.parse_datastore_object()
            for k in t[1].keys():
                self.assertEqual(r.features.get('datastores', [])[0].get(k), t[1][k])

    def test_ColorScheme(self):
        tests = [
            (
                """{\*\colorschememapping 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c613a
636c724d617020786d6c6e733a613d22687474703a2f2f736368656d61732e6f70656e786d6c666f726d6174732e6f72672f64726177696e676d6c2f323030362f6d6169
6e22206267313d226c743122207478313d22646b3122206267323d226c743222207478323d22646b322220616363656e74313d22616363656e74312220616363
656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d22616363656e7435222061636
3656e74363d22616363656e74362220686c696e6b3d22686c696e6b2220666f6c486c696e6b3d22666f6c486c696e6b222f3e}""",
                '6b7a472a22fbdbff4b2b08ddb4f43735',
            ),
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.hash_data_blob()
            self.assertEqual(r.features.get('colorschememapping', []), [t[1]])

    def test_ThemeData(self):
        tests = [
            (
                '{\\*\\themedata 504b030414000600080000002100e9de0fbfff0000001c020000130000005b436f6e74656e745f54797065735d2e786d6cac91cb4ec3301045f748fc83e52d4a}',
                '273b51fccd19fea163f1179043c667d0',
            ),
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.hash_data_blob()
            self.assertEqual(r.features.get('themedata', []), [t[1]])

    def test_BlipUID(self):
        tests = [
            ('{\\rtf1{\\*\\blipuid 1a7354d2647ee40ec69876e0af6edc4a}}',
             '1a7354d2647ee40ec69876e0af6edc4a')
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.hash_data_blob()
            self.assertIn(t[1], r.features.get('blipuid', []))

    def test_RSID(self):
        tests = [
            ('{\\rtf1{\*\\rsidtbl \\rsid221283\\rsid944553\\rsid2187550\\rsid2887680\\rsid9381173}}',
             ['rsid221283', 'rsid944553', 'rsid9381173'])
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.parse_rsid()
            for item in t[1]:
                self.assertIn(item, r.features.get('rsid', []))

    def testBlipTag(self):
        tests = [
            ('{\\rtf1{\\picscalex65\\picscaley65\\jpegblip\\bliptag1833808814}}', ['bliptag1833808814'])
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.parse_bliptag()
            for item in t[1]:
                self.assertIn(item, r.features.get('bliptag', []))

        
    def testIsValid(self):
        tests = [
            ('{\\rtf1}', True),
            ('aaaaaa', False),
            ('{\\rtadfasfasdfasdfadsfsadfdasfas}', True),
            ('\x00\x00', False),
            ('{\\rtf{}}\xff\x8c\xf0', True),
        ]
        for t in tests:
            r = RtfParser(t[0])
            self.assertEqual(r.is_valid(), t[1])

    def testParse(self):
        tests = [
            ('{\\rtf1}', 1),
            ('aaaaaa', 0),
            ('{\\rtadfasfasdfasdfadsfsadfdasfas}', 1),
            ('\x00\x00', 0),
        ]
        for t in tests:
            r = RtfParser(t[0])
            r.parse()
            self.assertEqual(r.features.get('valid_rtf'), t[1])
            
    def testUniqueList(self):
        tests = [
            ([1,2,2,3,4], [1,2,3,4]),
            (['a', 'a', 'a', 'a'], ['a'])
        ]
        for t in tests:
            r = RtfParser('{\\rtf1}')
            self.assertEqual(r.unique_list(t[0]), t[1])
        
def main():
    unittest.main()
    
if __name__ == '__main__':
    main()