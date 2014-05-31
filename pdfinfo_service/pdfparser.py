#!/usr/bin/python

__description__ = 'pdf-parser, use it to parse a PDF document'
__author__ = 'Didier Stevens'
__version__ = '0.3.7'
__date__ = '2010/01/09'
__minimum_python_version__ = (2, 5, 1)
__maximum_python_version__ = (2, 6, 2)

import re
import optparse
import zlib
import binascii
import hashlib
import sys
import cStringIO
import simplejson as json
import math
import traceback
from numpy import zeros

CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result

def Obj2Str(content):
    return ''.join(map(lambda x: repr(x[1])[1:-1], CopyWithoutWhiteSpace(content)))

class cPDFDocument:
    def __init__(self, file):
        import StringIO
        self.file = file
        self.infile = StringIO.StringIO(file)
        self.ungetted = []
        self.position = -1

    def byte(self):
        if len(self.ungetted) != 0:
            self.position += 1
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte:
            self.infile.close()
            return None
        self.position += 1
        return ord(inbyte)

    def unget(self, byte):
        self.position -= 1
        self.ungetted.append(byte)

def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if byte == 0x28 or byte == 0x29 or byte == 0x3C or byte == 0x3E or byte == 0x5B or byte == 0x5D or byte == 0x7B or byte == 0x7D or byte == 0x2F or byte == 0x25:
        return CHAR_DELIMITER
    return CHAR_REGULAR

def IsNumeric(str):
    return re.match('^[0-9]+', str)

class cPDFTokenizer:
    def __init__(self, file):
        self.oPDF = cPDFDocument(file)
        self.ungetted = []

    def Token(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        if self.oPDF == None:
            return None
        self.byte = self.oPDF.byte()
        if self.byte == None:
            self.oPDF = None
            return None
        elif CharacterClass(self.byte) == CHAR_WHITESPACE:
            self.token = ''
            while self.byte != None and CharacterClass(self.byte) == CHAR_WHITESPACE:
                self.token = self.token + chr(self.byte)
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            return (CHAR_WHITESPACE, self.token)
        elif CharacterClass(self.byte) == CHAR_REGULAR:
            self.token = ''
            while self.byte != None and CharacterClass(self.byte) == CHAR_REGULAR:
                self.token = self.token + chr(self.byte)
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            return (CHAR_REGULAR, self.token)
        else:
            if self.byte == 0x3C:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3C:
                    return (CHAR_DELIMITER, '<<')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '<')
            elif self.byte == 0x3E:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3E:
                    return (CHAR_DELIMITER, '>>')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '>')
            elif self.byte == 0x25:
                self.token = ''
                while self.byte != None:
                    self.token = self.token + chr(self.byte)
                    if self.byte == 10 or self.byte == 13:
                        self.byte = self.oPDF.byte()
                        break
                    self.byte = self.oPDF.byte()
                if self.byte != None:
                    if self.byte == 10:
                        self.token = self.token + chr(self.byte)
                    else:
                        self.oPDF.unget(self.byte)
                else:
                    self.oPDF = None
                return (CHAR_DELIMITER, self.token)
            return (CHAR_DELIMITER, chr(self.byte))

    def TokenIgnoreWhiteSpace(self):
        token = self.Token()
        while token != None and token[0] == CHAR_WHITESPACE:
            token = self.Token()
        return token

    def unget(self, byte):
        self.ungetted.append(byte)

class cPDFParser:
    def __init__(self, file, verbose=False, extract=None):
        self.context = CONTEXT_NONE
        self.content = []
        self.oPDFTokenizer = cPDFTokenizer(file)
        self.verbose = verbose
        self.extract = extract

    def GetObject(self):
        while True:
            if self.context == CONTEXT_OBJ:
                self.token = self.oPDFTokenizer.Token()
            else:
                self.token = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
            if self.token:
                if self.token[0] == CHAR_DELIMITER:
                    if self.token[1][0] == '%':
                        if self.context == CONTEXT_OBJ:
                            self.content.append(self.token)
                        else:
                            return cPDFElementComment(self.token[1])
                    elif self.token[1] == '/':
                        self.token2 = self.oPDFTokenizer.Token()
                        if self.token2[0] == CHAR_REGULAR:
                            if self.context != CONTEXT_NONE:
                                self.content.append((CHAR_DELIMITER, self.token[1] + self.token2[1]))
                            elif self.verbose:
                                print 'todo 1: %s' % (self.token[1] + self.token2[1])
                        else:
                            self.oPDFTokenizer.unget(self.token2)
                            if self.context != CONTEXT_NONE:
                                self.content.append(self.token)
                            elif self.verbose:
                                print 'todo 2: %d %s' % (self.token[0], repr(self.token[1]))
                    elif self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print 'todo 3: %d %s' % (self.token[0], repr(self.token[1]))
                elif self.token[0] == CHAR_WHITESPACE:
                    if self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print 'todo 4: %d %s' % (self.token[0], repr(self.token[1]))
                else:
                    if self.context == CONTEXT_OBJ:
                        if self.token[1] == 'endobj':
                            self.oPDFElementIndirectObject = cPDFElementIndirectObject(self.objectId, self.objectVersion, self.content)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementIndirectObject
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_TRAILER:
                        if self.token[1] == 'startxref' or self.token[1] == 'xref':
                            self.oPDFElementTrailer = cPDFElementTrailer(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementTrailer
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_XREF:
                        if self.token[1] == 'trailer' or self.token[1] == 'xref':
                            self.oPDFElementXref = cPDFElementXref(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementXref
                        else:
                            self.content.append(self.token)
                    else:
                        if IsNumeric(self.token[1]):
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            try:
                                if IsNumeric(self.token2[1]):
                                    self.token3 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                                    if self.token3[1] == 'obj':
                                        self.objectId = eval(self.token[1])
                                        self.objectVersion = eval(self.token2[1])
                                        self.context = CONTEXT_OBJ
                                    else:
                                        self.oPDFTokenizer.unget(self.token3)
                                        self.oPDFTokenizer.unget(self.token2)
                                        if self.verbose:
                                            print 'todo 6: %d %s' % (self.token[0], repr(self.token[1]))
                                else:
                                    self.oPDFTokenizer.unget(self.token2)
                                    if self.verbose:
                                        print 'todo 7: %d %s' % (self.token[0], repr(self.token[1]))
                            except:
                                blank = None

                        elif self.token[1] == 'trailer':
                            self.context = CONTEXT_TRAILER
                            self.content = [self.token]
                        elif self.token[1] == 'xref':
                            self.context = CONTEXT_XREF
                            self.content = [self.token]
                        elif self.token[1] == 'startxref':
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if self.token2 and IsNumeric(self.token2[1]):
                                return cPDFElementStartxref(eval(self.token2[1]))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print 'todo 9: %d %s' % (self.token[0], repr(self.token[1]))
                        elif self.extract:
                            self.bytes = ''
                            while self.token:
                                self.bytes += self.token[1]
                                self.token = self.oPDFTokenizer.Token()
                            return cPDFElementMalformed(self.bytes)
                        elif self.verbose:
                            print 'todo 10: %d %s' % (self.token[0], repr(self.token[1]))
            else:
                break

class cPDFElementComment:
    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment
#                        if re.match('^%PDF-[0-9]\.[0-9]', self.token[1]):
#                            print repr(self.token[1])
#                        elif re.match('^%%EOF', self.token[1]):
#                            print repr(self.token[1])

class cPDFElementXref:
    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content

class cPDFElementTrailer:
    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

class cPDFElementIndirectObject:
    def __init__(self, id, version, content):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = id
        self.version = version
        self.content = content

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '<<':
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '>>':
                dictionary -= 1
            if dictionary == 1 and content[i][0] == CHAR_DELIMITER and EqualCanonical(content[i][1], '/Type') and i < len(content) - 1:
                return content[i+1][1]
        return ''

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if i > 1 and content[i][0] == CHAR_REGULAR and content[i][1] == 'R' and content[i-2][0] == CHAR_REGULAR and IsNumeric(content[i-2][1]) and content[i-1][0] == CHAR_REGULAR and IsNumeric(content[i-1][1]):
                references.append((content[i-2][1], content[i-1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def Stream(self, filter=True):
        state = 'start'
        countDirectories = 0
        data = ''
        filters = []
        for i in range(0, len(self.content)):
            if state == 'start':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '<<':
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '>>':
                    countDirectories -= 1
                if countDirectories == 1 and self.content[i][0] == CHAR_DELIMITER and EqualCanonical(self.content[i][1], '/Filter'):
                    state = 'filter'
            elif state == 'filter':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters = [self.content[i][1]]
                    state = 'search-stream'
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '[':
                    state = 'filter-list'
            elif state == 'filter-list':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ']':
                    state = 'search-stream'
            elif state == 'search-stream':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'stream-whitespace':
                if self.content[i][0] != CHAR_WHITESPACE:
                    data += self.content[i][1]
                state = 'stream-concat'
            elif state == 'stream-concat':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'endstream':
                    if filter:
                        return self.Decompress(data, filters)
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return 'Unexpected filter state'
        return filters

    def Decompress(self, data, filters):
        for filter in filters:
            if EqualCanonical(filter, '/FlateDecode') or EqualCanonical(filter, '/Fl'):
                try:
                    data = FlateDecode(data)
                except:
                    return 'FlateDecode decompress failed'
            elif EqualCanonical(filter, '/ASCIIHexDecode') or EqualCanonical(filter, '/AHx'):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return 'ASCIIHexDecode decompress failed'
            elif EqualCanonical(filter, '/ASCII85Decode') or EqualCanonical(filter, '/A85'):
                try:
                    data = ASCII85Decode(data.rstrip('>'))
                except:
                    return 'ASCII85Decode decompress failed'
            elif EqualCanonical(filter, '/LZWDecode') or EqualCanonical(filter, '/LZW'):
                try:
                    data = LZWDecode(data)
                except:
                    return 'LZWDecode decompress failed'
            elif EqualCanonical(filter, '/RunLengthDecode') or EqualCanonical(filter, '/R'):
                try:
                    data = RunLengthDecode(data)
                except:
                    return 'RunLengthDecode decompress failed'
#            elif i.startswith('/CC')                        # CCITTFaxDecode
#            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return 'Unsupported filter: %s' % repr(filters)
        if len(filters) == 0:
            return 'No filters'
        else:
            return data

class cPDFElementStartxref:
    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index

class cPDFElementMalformed:
    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content

def TrimLWhiteSpace(data):
    while data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data

def TrimRWhiteSpace(data):
    while data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data

class cPDFParseDictionary:
    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if self.isOpenDictionary(dataTrimmed[0]) and self.isCloseDictionary(dataTrimmed[-1]):
            self.parsed = self.ParseDictionary(dataTrimmed)
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '<<'

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '>>'

    def ParseDictionary(self, tokens):
        state = 0 # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value != [] and tokens[0][1][0] == '/':
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
                else:
                    value.append(ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput))
            tokens = tokens[1:]

    def retrieve(self):
        return self.parsed

    def PrettyPrint(self, prefix):
        if self.parsed != None:
            print '%s<<' % prefix
            for e in self.parsed:
                print '%s  %s %s' % (prefix, e[0], ''.join(e[1]))
            print '%s>>' % prefix

def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return ''.join(map(lambda x: x[1], data))
        else:
            return data
    else:
        return repr(data)

def PrintObject(object, options):
    print 'obj %d %d' % (object.id, object.version)
    print ' Type: %s' % ConditionalCanonicalize(object.GetType(), options.nocanonicalizedoutput)
    print ' Referencing: %s' % ', '.join(map(lambda x: '%s %s %s' % x, object.GetReferences()))
    stream = object.ContainsStream()
    oPDFParseDictionary = None
    if stream:
        print ' Contains stream'
        print ' %s' % FormatOutput(stream, options.raw)
        oPDFParseDictionary = cPDFParseDictionary(stream, options.nocanonicalizedoutput)
    else:
        print ' %s' % FormatOutput(object.content, options.raw)
        oPDFParseDictionary = cPDFParseDictionary(object.content, options.nocanonicalizedoutput)
    print
    oPDFParseDictionary.PrettyPrint(' ')
    print
    if options.filter and not options.dump:
        filtered = object.Stream()
        if filtered == []:
            print ' %s' % FormatOutput(object.content, options.raw)
        else:
            print ' %s' % FormatOutput(filtered, options.raw)
    if options.dump:
        print 'Start dump:'
        print object.Stream(False)
        print 'End dump'
    print
    return

def Canonicalize(sIn):
    if sIn == "":
        return sIn
    elif sIn[0] != '/':
        return sIn
    elif sIn.find('#') == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ''
        while i < iLen:
            if sIn[i] == '#' and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i+1:i+3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical

def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2

def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)

# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py
def ASCII85Decode(data):
    import struct
    n = b = 0
    out = ''
    for c in data:
        if '!' <= c and c <= 'u':
            n += 1
            b = b*85+(ord(c)-33)
            if n == 5:
                out += struct.pack('>L',b)
                n = b = 0
        elif c == 'z':
            assert n == 0
            out += '\0\0\0\0'
        elif c == '~':
            if n:
                for _ in range(5-n):
                    b = b*85+84
                out += struct.pack('>L',b)[:n-1]
            break
    return out

def ASCIIHexDecode(data):
    return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))

def FlateDecode(data):
    return zlib.decompress(data)

def RunLengthDecode(data):
    f = cStringIO.StringIO(data)
    decompressed = ''
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
#    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed

#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in xrange(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return

####

def LZWDecode(data):
    return ''.join(LZWDecoder(cStringIO.StringIO(data)).run())

#9bplus

def hash2JSON(obj):

    id = obj.id
    version = obj.version
    raw_content = FormatOutput(obj.content, True)
    length = len(raw_content)
    md5 = hashlib.md5(raw_content).hexdigest()

    jobject = { 'id':id, 'version':version, 'length':length, 'md5': md5 }
    return jobject

def content2JSON(obj):
    entropy = []
    id = obj.id
    filtered = obj.Stream()
    encoded = FormatOutput(obj.content, True)
    try:
        entropy = get_entropy(encoded)
    except:
        traceback.print_exc()
        v = "fail"
    encoded = unicode(FormatOutput(obj.content, True),errors='replace')

    if filtered == []:
        decoded = 'Object contained no stream or decoding failed'
    else:
        decoded = FormatOutput(filtered, True)
        try:
            entropy = []
            entropy = get_entropy(decoded)
        except:
            traceback.print_exc()
            v = "fail"
        decoded = unicode(FormatOutput(filtered, True),errors='replace')

    version = obj.version
    raw_content = FormatOutput(obj.content, True)
    length = len(raw_content)
    md5 = hashlib.md5(raw_content).hexdigest()
    hex = ByteToHex(raw_content)
    type = obj.GetType()
    if type == "":
        type = "Unknown"
    suspicious = []
    suspicious = check_raw_content(raw_content, suspicious)
    suspicious = check_raw_content(encoded, suspicious)
    suspicious = f5(check_raw_content(decoded, suspicious))
    sus = ",".join(suspicious)
    if sus != "":
        sus += " potentially detected"

    jobject = { 'id':id, 'version': version, 'length': length, 'md5': md5, 'encoded':encoded, 'decoded':decoded, 'hex': hex, 'suspicious': sus, 'type':type, 'entropy':out_entropy }
    return jobject

def get_entropy(data):
    out = []
    for i in range(0,len(data)):
        key = (i+1)*32
        if key > len(data) + 32:
            break
        chunk = data[i*32:key]
        entropy = float(H(chunk))
        out.append(entropy)
    return out

def H(data):
    if not data:
        return 0

    entropy = 0
    len_data = len(data)
    data_counts = zeros(256)
    lord = ord

    for d in data:
        data_counts[lord(d)] += 1

    for x in range(0, 256):
        p_x = float(data_counts[x])/len_data

        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)

    return entropy

def ByteToHex( byteStr ):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def HexToByte( hexStr ):
    bytes = []
    hexStr = ''.join( hexStr.split(" ") )
    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )
    return ''.join( bytes )

def f5(seq, idfun=None):
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result

def check_raw_content(content,suspicious):
    generic_flash = ['flash', 'swf']
    generic_adobe = ['app.','/js','/javascript','/JavaScript','/openAction','viewerVersion']
    generic_js = ['.this','function', 'eval', 'unescape', '.replace','.substring']
    utilprintf = ['util.','util','printf']
    geticon = ['getIcon']
    customdict = ['spell.', 'customDictionaryOpen','DictionaryOpen']
    getannots = ['getAnnots','nnots\(']
    libtiff = ['image/tif', 'tif"']
    newplayer = ['media','.newPlayer']
    collectemail = ['collectEmailInfo']
    jbig2decode = ['2Decode']

    for a in generic_flash:
        if re.search(a,content):
            obj = 'flash/swf'
            suspicious.append(obj)
            break
    for a in generic_adobe:
        if re.search(a,content):
            obj = 'adobe calls'
            suspicious.append(obj)
            break
    for a in generic_js:
        if re.search(a,content):
            obj = 'javascript'
            suspicious.append(obj)
            break
    for a in utilprintf:
        if re.search(a,content):
            obj = 'util.printf exploit'
            suspicious.append(obj)
            break
    for a in geticon:
        if re.search(a,content):
            obj = 'getIcon exploit'
            suspicious.append(obj)
            break
    for a in customdict:
        if re.search(a,content):
            obj = 'customdict exploit'
            suspicious.append(obj)
            break
    for a in getannots:
        if re.search(a,content):
            obj = 'getAnnots exploit'
            suspicious.append(obj)
            break
    for a in libtiff:
        if re.search(a,content):
            obj = 'libtiff exploit'
            suspicious.append(obj)
            break
    for a in newplayer:
        if re.search(a,content):
            obj = 'newplayer exploit'
            suspicious.append(obj)
            break
    for a in collectemail:
        if re.search(a,content):
            obj = 'collectEmail exploit'
            suspicious.append(obj)
            break
    for a in jbig2decode:
        if re.search(a,content):
            obj = 'JBIG2Decode exploit'
            suspicious.append(obj)
            break
    return suspicious

def Main():
    """pdf-parser, use it to parse a PDF document
    """

    oParser = optparse.OptionParser(usage='usage: %prog [options] pdf-file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-s', '--search', help='string to search in indirect objects (except streams)')
    oParser.add_option('-f', '--filter', action='store_true', default=False, help='pass stream object through filters (FlateDecode, ASCIIHexDecode and ASCII85Decode only)')
    oParser.add_option('-o', '--object', help='id of indirect object to select (version independent)')
    oParser.add_option('-r', '--reference', help='id of indirect object being referenced (version independent)')
    oParser.add_option('-e', '--elements', help='type of elements to select (cxtsi)')
    oParser.add_option('-w', '--raw', action='store_true', default=False, help='raw output for data and filters')
    oParser.add_option('-a', '--stats', action='store_true', default=False, help='display stats for pdf document')
    oParser.add_option('-t', '--type', help='type of indirect object to select')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='display malformed PDF elements')
    oParser.add_option('-x', '--extract', help='filename to extract to')
    oParser.add_option('-H', '--hash', action='store_true', default=False, help='display hash of objects')
    oParser.add_option('-n', '--nocanonicalizedoutput', action='store_true', default=False, help='do not canonicalize the output')
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='dump unfiltered content of a stream')
    oParser.add_option('-j', '--json', action='store_true', default=False, help='jsonify certain outputs')
    (options, args) = oParser.parse_args()

    if len(args) != 1:
        oParser.print_help()
        print ''
        print '  %s' % __description__
        print '  Source code put in the public domain by Didier Stevens, no Copyright'
        print '  Use at your own risk'
        print '  https://DidierStevens.com'

    else:
        oPDFParser = cPDFParser(args[0], options.verbose, options.extract)
        cntComment = 0
        cntXref = 0
        cntTrailer = 0
        cntStartXref = 0
        cntIndirectObject = 0
        dicObjectTypes = {}

        selectComment = False
        selectXref = False
        selectTrailer = False
        selectStartXref = False
        selectIndirectObject = False
        if options.elements:
            for c in options.elements:
                if c == 'c':
                    selectComment = True
                elif c == 'x':
                    selectXref = True
                elif c == 't':
                    selectTrailer = True
                elif c == 's':
                    selectStartXref = True
                elif c == 'i':
                    selectIndirectObject = True
                else:
                    print 'Error: unknown --elements value %s' % c
                    return
        else:
            selectIndirectObject = True
            if not options.search and not options.object and not options.reference and not options.type:
                selectComment = True
                selectXref = True
                selectTrailer = True
                selectStartXref = True

        if options.type == '-':
            optionsType = ''
        else:
            optionsType = options.type

        while True:
            object = oPDFParser.GetObject()
            if object != None:
                if options.stats:
                    if object.type == PDF_ELEMENT_COMMENT:
                        cntComment += 1
                    elif object.type == PDF_ELEMENT_XREF:
                        cntXref += 1
                    elif object.type == PDF_ELEMENT_TRAILER:
                        cntTrailer += 1
                    elif object.type == PDF_ELEMENT_STARTXREF:
                        cntStartXref += 1
                    elif object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                        cntIndirectObject += 1
                        type = object.GetType()
                        if not type in dicObjectTypes:
                            dicObjectTypes[type] = [object.id]
                        else:
                            dicObjectTypes[type].append(object.id)
                else:
                    if object.type == PDF_ELEMENT_COMMENT and selectComment:
                        print 'PDF Comment %s' % FormatOutput(object.comment, options.raw)
                        print
                    elif object.type == PDF_ELEMENT_XREF and selectXref:
                        print 'xref %s' % FormatOutput(object.content, options.raw)
                        print
                    elif object.type == PDF_ELEMENT_TRAILER and selectTrailer:
                        oPDFParseDictionary = cPDFParseDictionary(object.content[1:], options.nocanonicalizedoutput)
                        if oPDFParseDictionary == None:
                            print 'trailer %s' % FormatOutput(object.content, options.raw)
                        else:
                            print 'trailer'
                            oPDFParseDictionary.PrettyPrint(' ')
                        print
                    elif object.type == PDF_ELEMENT_STARTXREF and selectStartXref:
                        print 'startxref %d' % object.index
                        print
                    elif object.type == PDF_ELEMENT_INDIRECT_OBJECT and selectIndirectObject:
                        if options.search:
                            if object.Contains(options.search):
                                PrintObject(object, options)
                        elif options.object: #OBJECT
                            if object.id == eval(options.object):
                                PrintObject(object, options)
                        elif options.reference:
                            if object.References(options.reference):
                                PrintObject(object, options)
                        elif options.type:
                            if EqualCanonical(object.GetType(), optionsType):
                                PrintObject(object, options)
                        elif options.hash:
                            print 'obj %d %d' % (object.id, object.version)
                            rawContent = FormatOutput(object.content, True)
                            print ' len: %d md5: %s' % (len(rawContent), hashlib.md5(rawContent).hexdigest())
                            print
                        else:
                            PrintObject(object, options)
                    elif object.type == PDF_ELEMENT_MALFORMED:
                        try:
                            fExtract = open(options.extract, 'wb')
                            try:
                                fExtract.write(object.content)
                            except:
                                print 'Error writing file %s' % options.extract
                            fExtract.close()
                        except:
                            print 'Error writing file %s' % options.extract
            else:
                break

        if options.stats:
            print 'Comment: %s' % cntComment
            print 'XREF: %s' % cntXref
            print 'Trailer: %s' % cntTrailer
            print 'StartXref: %s' % cntStartXref
            print 'Indirect object: %s' % cntIndirectObject
            names = dicObjectTypes.keys()
            names.sort()
            for key in names:
                print ' %s %d: %s' % (key, len(dicObjectTypes[key]), ', '.join(map(lambda x: '%d' % x, dicObjectTypes[key])))

def TestPythonVersion(enforceMaximumVersion=False, enforceMinimumVersion=False):
    if sys.version_info[0:3] > __maximum_python_version__:
        if enforceMaximumVersion:
            print 'This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3]
            print 'Please use Python version %d.%d.%d' % __maximum_python_version__
            sys.exit()
        else:
            print 'This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3]
            print 'Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__
    if sys.version_info[0:3] < __minimum_python_version__:
        if enforceMinimumVersion:
            print 'This program does not work with this version of Python (%d.%d.%d)' % sys.version_info[0:3]
            print 'Please use Python version %d.%d.%d' % __maximum_python_version__
            sys.exit()
        else:
            print 'This program has not been tested with this version of Python (%d.%d.%d)' % sys.version_info[0:3]
            print 'Should you encounter problems, please use Python version %d.%d.%d' % __maximum_python_version__

if __name__ == '__main__':
    TestPythonVersion(enforceMaximumVersion=False)
    Main()
