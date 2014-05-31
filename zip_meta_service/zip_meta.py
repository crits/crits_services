import struct
import binascii
from datetime import datetime
from pprint import pprint
import extra_field_parse

#Parse Zip Central Directory
class ZipParser():

    zipLDMagic = "\x50\x4b\x03\x04" #Local Directory
    zipCDMagic = "\x50\x4b\x01\x02" #Central Directory

    def getFileComment(self):
        if self.getCommentLength() == 0:
            return None
        startPosition = (46 + self.getFileNameLength() + self.getExtraFieldCDLength())
        return self.centralDirectory[startPosition:(startPosition + self.getCommentLength())]

    def getCommentLength(self):
        return struct.unpack("<H",self.centralDirectory[32:34])[0]

    def parseExtraField(self,extraField):
        parsedExtraField = []
        efParser = extra_field_parse.HeaderIdMapping()
        efMappings = efParser.HeaderIds()
        while extraField:
            blockMagic = extraField[0:2]
            blockSize = struct.unpack("<H", extraField[2:4])[0]
            efBlock = extraField[:4+blockSize]
            if blockMagic in efMappings.keys():
                #Mapping Header Is known (may or may not have been parsed)
                parser = efMappings[blockMagic]["parseField"]()
                parsedExtraField.append(parser.parse(efBlock,self.zip64Flag))
            else:
                #No Header Hits
                parser = efMappings["Unknown"]["parseField"]()
                parsedExtraField.append(parser.parse(efBlock, self.zip64Flag))
            extraField = extraField[4+blockSize:]
        return parsedExtraField

    def getExtraField(self):
        if self.getExtraFieldLDLength() == 0:
            return None
        #Handler for case where offset cannot be found in central Directory
        if self.zip64Flag["offsetZip64"]:
            #If Offset flag present use central directory to find offset in extrafield
            startPosition = (46 + self.getFileNameLength())
            extraField = self.centralDirectory[startPosition:(startPosition + self.getExtraFieldCDLength())]

            efParser = extra_field_parse.HeaderIdMapping()
            efMappings = efParser.HeaderIds()

            start = extraField.find("\x01\x00")
            blockMagic = extraField[start:start + 2]
            blockSize = struct.unpack("<H", extraField[start + 2:start + 4])[0]
            parser = efMappings[blockMagic]["parseField"]()
            zip64 = parser.parse(efBlock,self.zip64Flag)
            offset = zip64["RelativeOffset"]

            startPosition = (offset + 30 + self.getFileNameLength())
            extraField = self.localDirectory[startPosition:(startPosition + self.getExtraFieldLDLength())]
        else:
            startPosition = (self.getRelativeOffset() + 30 + self.getFileNameLength())
            extraField = self.localDirectory[startPosition:(startPosition + self.getExtraFieldLDLength())]
        return self.parseExtraField(extraField)

    def getExtraFieldCDLength(self): #Central Directory
        length = struct.unpack("<H", self.centralDirectory[30:32])[0]
        return length

    def getExtraFieldLDLength(self): #Local Directory
        length = struct.unpack("<H", self.localDirectory[self.getRelativeOffset()
                                +28:self.getRelativeOffset()+30])[0]
        return length

    def getModifyDate(self):
        #MS-DOS Epoch
        if struct.unpack("<I",self.centralDirectory[12:16])[0] == 0:
            return None
        else:
            dateTime = struct.unpack("<I",self.centralDirectory[12:16])[0]
        secs  = (dateTime & 0x1F) * 2
        mins  = (dateTime & 0x7E0) >> 5
        hours = (dateTime & 0xF800) >> 11
        day   = (dateTime & 0x1F0000) >> 16
        month = (dateTime & 0x1E00000) >> 21
        year  = ((dateTime & 0xFE000000) >> 25) + 1980
        return datetime(year, month, day, hours, mins, secs).strftime("%B %d, %Y %H:%M:%S.%f")

    def getFileName(self):
        if self.getFileNameLength() == 0:
            return None
        return self.centralDirectory[46:(46 + self.getFileNameLength())]

    def getFileNameLength(self):
        return struct.unpack("<H",self.centralDirectory[28:30])[0]

    def getRelativeOffset(self):
        if struct.unpack("<I",self.centralDirectory[42:46])[0] == 0xFFFFFFFF:
            self.zip64Flag["offsetZip64"] = True
            return "Zip 64. See Extra Field For Relative Offset"
        return struct.unpack("<I",self.centralDirectory[42:46])[0]

    def getFileExternalAttributes(self):
        return struct.unpack("<I",self.centralDirectory[38:42])[0]

    def getInternalAttributeNames(self,bit):
        internalNames = {
        0:    "ASCII/text file",
        1:    "reserved",                                       #pkware reserved
        2:    "control field records precede logical records",  #pkware reserved
        3:    "unused"
        }
        if bit in xrange(3,16):
            return internalNames[3]
        elif bit in internalNames:
            return internalNames[bit]
        else:
            return "{} Is An Unknown Internal Attribute".format(bit)

    def getInternalAttributes(self):
        internalAttributes = struct.unpack("<H",self.centralDirectory[36:38])[0]
        setAttributes = []
        for bit in xrange(0,16):
            if internalAttributes & (2**bit) > 0:
                setAttributes.append(self.getInternalAttributeNames(bit))
        if not setAttributes:
            return None
        return setAttributes

    def getFileStartDisk(self):
        if struct.unpack("<H",self.centralDirectory[34:36])[0] == 0xFFFF:
            self.zip64Flag["diskZip64"] = True
            return "Zip 64. See Extra Field For File Start Disk"
        return struct.unpack("<H",self.centralDirectory[34:36])[0]

    def getCompressedSize(self):
        if struct.unpack("<I",self.centralDirectory[20:24])[0] == 0xFFFFFFFF:
             self.zip64Flag["cZip64"] = True
             return "Zip 64. See Extra Field For Compressed Size"
        return struct.unpack("<I",self.centralDirectory[20:24])[0]

    def getUncompressedSize(self):
        if struct.unpack("<I",self.centralDirectory[24:28])[0] == 0xFFFFFFFF:
            self.zip64Flag["ucZip64"] = True
            return "Zip 64. See Extra Field For Uncompressed Size"
        return struct.unpack("<I",self.centralDirectory[24:28])[0]

    def compressionMethodName(self):
        method = struct.unpack("<H",self.centralDirectory[10:12])[0]
        compMethods = {
        0:      "No Compression/Stored",
        1:      "Shrunk",
        2:      "Reduced With Compression Factor 1",
        3:      "Reduced With Compression Factor 2",
        4:      "Reduced With Compression Factor 3",
        5:      "Reduced With Compression Factor 4",
        6:      "Imploded",
        7:      "Reserved",
        8:      "Deflated",
        9:      "Enhanced Deflated",
        10:     "PKware Dcl Imploded",
        11:     "Reserved",
        12:     "Compressed Using Bzip2",
        13:     "Reserved",
        14:     "LZMA",
        15:     "Reserved",
        16:     "Reserved",
        17:     "Reserved",
        18:     "Compressed Using IBM Terse",
        19:     "IBM LZ77 Z",
        98:     "PPMD Version I, Revision 1"
        }
        if method in compMethods:
            return compMethods[method]
        else:
            return "{} Is An Unknown Compression Method".format(method)

    def getCRC(self):
        return binascii.hexlify(self.centralDirectory[16:20])

    def getFlagNames(self,flag):
        flagNames = {
        0:  "Encrypted File",
        1:  "Compression Option",
        2:  "Compression Option",
        3:  "Data Descriptor",
        4:  "Enhanced Deflation",
        5:  "Compressed Patched Data",
        6:  "Strong Encryption",
        7:  "Unused",
        8:  "Unused",
        9:  "Unused",
        10: "Unused",
        11: "Language Encoding",
        12: "Reserved",
        13: "Mask Header Values",
        14: "Reserved",
        15: "Reserved"
        }
        if flag in flagNames:
            return flagNames[flag]
        else:
            return "{} Is An Unknown Flag Name".format(flag)

    def getFlags(self):
        flags = struct.unpack("<H",self.centralDirectory[8:10])[0]
        setFlags = []
        for i in xrange(0,16):
        	if (flags & (2**i)):
        		setFlags.append(self.getFlagNames(i))
        if not setFlags:
            return None
        return setFlags

    def getRequiredVersion(self):
        return (struct.unpack("<H",self.centralDirectory[6:8])[0] * .1)

    def getVersionMadeByName(self,highByte):
        versionNameDict = {
        0   :"MS:DOS and OS/2 (FAT / VFAT / FAT32 file systems)",
        1   :"Amiga",
        2   :"OpenVMS",
        3   :"UNIX",
        4   :"VM/CMS",
        5   :"Atari ST",
        6   :"OS/2 H.P.F.S.",
        7   :"Macintosh",
        8   :"Z:System",
        9   :"CP/M",
        10  :"Windows NTFS",
        11  :"MVS (OS/390 : Z/OS)",
        12  :"VSE",
        13  :"Acorn Risc",
        14  :"VFAT",
        15  :"alternate MVS",
        16  :"BeOS",
        17  :"Tandem",
        18  :"OS/400",
        19  :"OS/X (Darwin)",
        20  :"unused",
        }
        if highByte in xrange(20,256):
            return versionNameDict[20]
        elif highByte in versionNameDict:
            return versionNameDict[highByte]
        else:
            return "{} Is An Unknown Version Name".format(highByte)

    def getVersionMadeBy(self):#MOD THIS FOR MINOR
        versionBytes = (struct.unpack("<BB",self.centralDirectory[4:6]))
        return self.getVersionMadeByName(versionBytes[1]), (float(versionBytes[0]) * .1)

    def parseCentralDirectory(self):
        centralDirectory = {
        "VersionMadeBy"             :self.getVersionMadeBy(),
        "ZipRequiredVersion"        :self.getRequiredVersion(),      #to extract
        "ZipBitFlag"                :self.getFlags(),
        "ZipCRC"                    :self.getCRC(),
        "ZipCompression"            :self.compressionMethodName(),       #method
        "ZipUncompressedSize"       :self.getUncompressedSize(),
        "ZipCompressedSize"         :self.getCompressedSize(),
        "FileStartDisk"             :self.getFileStartDisk(),
        "InternalAttributes"        :self.getInternalAttributes(),
        "ExternalAttributes"        :self.getFileExternalAttributes(),
        "RelativeOffset"            :self.getRelativeOffset(),
        "ZipFileName"               :self.getFileName(),
        "ZipModifyDate"             :self.getModifyDate(),
        "ZipExtraField"             :self.getExtraField(),
        "ZipComments"               :self.getFileComment()
        }

        return centralDirectory

    def parseZipFile(self):
        #Because a central directory is an extended version of a local
        #directory and thus, contains more data, we parse it rather than
        #the local directory.
        if not self.centralDirectory.startswith(self.zipCDMagic):
            return None
        start = 1
        parsedFiles = []
        while start > 0:
            parsedFiles.append(self.parseCentralDirectory())
            start = self.centralDirectory[1:].find(self.zipCDMagic) +1
            self.centralDirectory = self.centralDirectory[start:]
        return parsedFiles

#***************************END**DIRECTORY**PARSING*****************************

    def getHeaderSignature(self):
        return self.data[0:4]

    def getCDComment(self):
        if self.endDirectory[22:(22 + self.getCDCommentLength())] == 0:
            return None
        else:
            return self.endDirectory[22:(22 + self.getCDCommentLength())]

    def getCDCommentLength(self):
        return struct.unpack("<H",self.endDirectory[20:22])[0]

    def getCDStartOffset(self):
        return struct.unpack("<I",self.endDirectory[16:20])[0]

    def getSizeOfCD(self):
        return struct.unpack("<I",self.endDirectory[12:16])[0]

    def getTotalNumberOfCDs(self):
        return struct.unpack("<H",self.endDirectory[10:12])[0]

    def getNumberOfCDs(self): #On Disk
        return struct.unpack("<H",self.endDirectory[8:10])[0]

    def getStartOfCDDisk(self):
        return struct.unpack("<H",self.endDirectory[6:8])[0]

    def getNumberOfDisk(self):
        return struct.unpack("<H",self.endDirectory[4:6])[0]

    def parseEndDirectory(self):
        start = self.data.find("\x50\x4b\x05\x06")
        self.endDirectory = self.data[start:]
        endDirectoryDict = {
        "NumberOfDisk"              :self.getNumberOfDisk(),
        "StartOfCDDisk"             :self.getStartOfCDDisk(),
        "NumberOfCDs"               :self.getNumberOfCDs(),
        "TotalNumberofCDs"          :self.getTotalNumberOfCDs(),
        "CDSize"                    :self.getSizeOfCD(),
        "CDStartOffset"             :self.getCDStartOffset(),
        "Comment"                   :self.getCDComment()
        }
        return endDirectoryDict

#***********************END**DIRECTORY**PARSING**ENDS***************************

    def __init__(self,data):
        self.data = data
        cdStart = self.parseEndDirectory()["CDStartOffset"]
        cdEnd = cdStart + self.parseEndDirectory()["CDSize"]
        self.localDirectory = data[:cdStart]
        self.centralDirectory = data[cdStart:cdEnd]
        # Flags needed to denote a zip64 file type
        self.zip64Flag = {"ucZip64"     : False,
                          "cZip64"      : False,
                          "offsetZip64" : False,
                          "diskZip64"   : False
                          }
