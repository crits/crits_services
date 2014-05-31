import struct
from datetime import datetime,timedelta
import binascii

class HeaderIdMapping():
    #More classes can be created if needed and if available. Note that some
    #extra field breakdowns were unable to be found.
    def HeaderIds(self):

        headers = {
        "\x01\x00":    { "name": "ZIP64 extended information extra field",
                         "parseField": Zip64Extended},
        "\x07\x00":    { "name": "AV Info",
                         "parseField": UnknownExtraField},
        "\x09\x00":    { "name": "OS/2",
                         "parseField": OS2},
        "\x0a\x00":    { "name": "NTFS",
                         "parseField": NTFS},
        "\x0c\x00":    { "name": "OpenVMS",
                         "parseField": UnknownExtraField},
        "\x0d\x00":    { "name": "Unix",
                         "parseField": Unix},
        "\x0f\x00":    { "name": "Patch Descriptor",
                         "parseField": UnknownExtraField},
        "\x14\x00":    { "name": "PKCS#7 Store for X.509 Certificates",
                         "parseField": UnknownExtraField},
        "\x15\x00":    { "name": "X.509 Certificate ID and Signature for individual file",
                         "parseField": UnknownExtraField},
##        "\x16\x00":    { "name": "X.509 Certificate ID for Central Directory",
##                         "parseField": x_509},
        "\x65\x00":    { "name": "IBM S/390 attributes ? uncompressed",
                         "parseField": UnknownExtraField},
        "\x66\x00":    { "name": "IBM S/390 attributes ? compressed",
                         "parseField": UnknownExtraField},
        "\xc8\x07":    { "name": "Macintosh",
                         "parseField": UnknownExtraField},
        "\x05\x26":    { "name": "ZipIt Macintosh",
                         "parseField": UnknownExtraField},
        "\x05\x27":    { "name": "ZIpIt Macintosh 1.3.5+",
                         "parseField": UnknownExtraField},
        "\x4d\x33":    { "name": "Info-ZIP Macintosh",
                         "parseField": UnknownExtraField},
        "\x41\x43":    { "name": "Acorn/SparkFS",
                         "parseField": UnknownExtraField},
        "\x53\x44":    { "name": "Windows NT security descriptor (binary ACL)",
                         "parseField": WindowsNTSecurityDescriptor},
        "\x04\x47":    { "name": "VM/CMS",
                         "parseField": UnknownExtraField},
        "\x0f\x47":    { "name": "MVS",
                         "parseField": UnknownExtraField},
        "\x54\x48":    { "name": "FWKCS MD5 (see below)",
                         "parseField": UnknownExtraField},
        "\x41\x4c":    { "name": "OS/2 access control list (text ACL)",
                         "parseField": OS2ACL},
        "\x49\x4d":    { "name": "Info-ZIP OpenVMS",
                         "parseField": UnknownExtraField},
        "\x4c\x4f":    { "name": "Xceed original location extra field",
                         "parseField": UnknownExtraField},
        "\x56\x53":    { "name": "AOS/VS (ACL)",
                         "parseField": UnknownExtraField},
        "\x55\x54":    { "name": "extended timestamp",
                         "parseField": ExtendedTimeStamp},
        "\x55\x58":    { "name": "Info-ZIP Unix (original,}, also OS/2,}, NT,}, etc)",
                         "parseField": InfoZipUnixOld},
        "\x55\x4e":    { "name": "Xceed unicode extra field",
                         "parseField": UnknownExtraField},
        "\x42\x65":    { "name": "BeOS(BeBox, PowerMac, etc.)",
                         "parseField": UnknownExtraField},
        "\x6e\x75":    { "name": "ASi Unix",
                         "parseField": ASiUnix},
        "\x55\x78":    { "name": "Info-ZIP Unix (previous new)",
                         "parseField": Unix2},
        "\x75\x78":    { "name": "Info-ZIP Unix (new)",
                         "parseField": InfoZipUnixNew},
        "\x4a\xfb":    { "name": "SMS/QDOS",
                         "parseField": UnknownExtraField},
        "Unknown":    {  "name": "UnknownHeader",
                         "parseField": UnknownExtraField}

        }
        return headers

    def __init__(self):
        self.HeaderIds()

class TimeAdjust():

    def convertTime(self,time):
        #days between Unix epoch and NTFS epoch are 134,774
        # 134,774 days = 1.16444736e+19 nanoseconds
        nsFromUnix = (time*100) - (1.16444736e+19) #nanoseconds from Unix Epoch
        seconds = nsFromUnix * (1e-09)
        timestamp = datetime.fromtimestamp(seconds)
        return timestamp.strftime("%B %d, %Y %H:%M:%S.%f")

    def __init__(self):
        pass

class NTFS():  #Same For Local Directory
    #probably a better way to write this function...
    def parse(self,extraField, _zip64Flag):
        timeAjduster = TimeAdjust()
        parsedBlock = {
        "Name"      :"NTFS",
        "BlockTag"  :binascii.hexlify(extraField[0:2]),
        "TSize"     :struct.unpack("<H",extraField[2:4])[0],
        "Reserved"  :struct.unpack("<I",extraField[4:8])[0],
        }
        #At time of writing, there is only one tag possibility
        #Because of this TSize is expected to be 32 bytes
        #And the MTime,CTime, and ATime, all will be present
        if "\x01\x00" in extraField:
            attributeTag  = struct.unpack("<H",extraField[8:10])[0]
            attributeSize = struct.unpack("<H",extraField[10 + 12])[0]
            #No Attributes to Parse and No more Data in NTFS Block
            MTime = timeAjduster.convertTime(struct.unpack("<Q", extraField[12:20])[0])
            ATime = timeAjduster.convertTime(struct.unpack("<Q", extraField[20:28])[0])
            CTime = timeAjduster.convertTime(struct.unpack("<Q", extraField[28:36])[0])

        parsedBlock["tag" + str(attributeTag)] = {"attributeTag" :attributeTag,
                                                  "attributeSize": attributeSize,
                                                  "MTime" : MTime,
                                                  "ATime" : ATime,
                                                  "CTime" : CTime}
        return parsedBlock

    def __init__(self):
        pass

class Unix():

    def parse(self,extraField,_zip64Flag):
        timeAdjuster = TimeAdjust()
        parsedBlock = {
        "Name"      :"Unix",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"     :struct.unpack("<H", extraField[2:4])[0],
        "ATime"     :datetime.fromtimestamp(struct.unpack("<I", extraField[4:8])[0])\
                    .strftime("%B %d, %Y %H:%M:%S.%f"),
        "MTime"     :datetime.fromtimestamp(struct.unpack("I", extraField[8:12])[0])\
                    .strftime("%B %d, %Y %H:%M:%S.%f"),
        "Userid"    :struct.unpack("H", extraField[12:14])[0],
        "Groupid"   :struct.unpack("H", extraField[14:16])[0],
        "DataField" :binascii.hexlify(extraField[16:(16+(struct.unpack("<H", extraField[2:4]))[0])])
        }
        return parsedBlock

    def __init__(self):
        pass

class Unix2():

    def parse(self,extraField,_zip64Flags):
        parsedBlock = {
        "Name"       :"Info-ZIP Unix Extra Field (type 2)",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "UID"      :struct.unpack("<H", extraField[4:6])[0],
        "GID"      :struct.unpack("<H", extraField[6:8])[0]
        }
        return parsedBlock

class InfoZipUnixOld():

    def parse(self,extraField,_zip64Flag):
        timeAdjuster = TimeAdjust()
        parsedBlock = {
        "Name"      :"Unix",
        "BlockTag"  :binascii.hexlify(extraField[0:2]), #Unix1
        "TSize"     :struct.unpack("<H", extraField[2:4])[0],
        "ATime"     :datetime.fromtimestamp(struct.unpack("<I", extraField[4:8])[0])\
                    .strftime("%B %d, %Y %H:%M:%S.%f"),
        "MTime"     :datetime.fromtimestamp(struct.unpack("I", extraField[8:12])[0])\
                    .strftime("%B %d, %Y %H:%M:%S.%f"),
        "Userid"    :struct.unpack("H", extraField[12:14])[0],
        "Groupid"   :struct.unpack("H", extraField[14:16])[0]
        }
        return parsedBlock

    def __init__(self):
        pass

class InfoZipUnixNew():

    def parse(self,extraField,_zip64Flags):
        parsedBlock = {
        "Name"       :"Info-ZIP Unix Extra Field (type 1)",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "Version"    :struct.unpack("<B",extraField[4:5])[0],
        "UIDSize"    :struct.unpack("<B",extraField[5:6])[0],
        }
        UIDEnd = 6 + parsedBlock["UIDSize"]
        parsedBlock["UID"] = binascii.hexlify(extraField[6:UIDEnd])
        parsedBlock["GIDSize"] = struct.unpack("<B", extraField[UIDEnd:UIDEnd + 1])
        GIDEnd = UIDEnd + 1 + parsedBlock["GIDSize"][0]
        parsedBlock["GID"] = binascii.hexlify(extraField[UIDEnd + 1:GIDEnd])
        position = 4 + parsedBlock["TSize"]

        return parsedBlock

    def __init__(self):
        pass

class ExtendedTimeStamp():

    def parse(self, extraField, _zip64Flag):
        setBits = []
        parsedBlock = {
        "Name"       :"Extended Time Stamp", #UT
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "Flags"      :struct.unpack("<B",extraField[4:5])[0]
        }
        for i in xrange (0,8):
            if parsedBlock["Flags"] & (2**i) > 0:
                if i == 0:
                    MTime = True
                else:
                    MTime = False
                if i == 1:
                    ATime = True
                else:
                    ATime = False
                if i == 2:
                    CTime = True
                else:
                    CTime = False
                if i > 2:
                    setBits.append(i)
        if setBits: #Reserved Bits For Future Timestamps
            parsedBlock["FlagInfo"] = setBits

        start = 5
        if MTime:
            parsedBlock["MTime"] = datetime.fromtimestamp \
            (struct.unpack("I", extraField[start:start + 4])[0]).strftime("%B %d, %Y %H:%M:%S.%f")
            start += 4
        if ATime:
            parsedBlock["ATime"] = datetime.fromtimestamp \
            (struct.unpack("I", extraField[start:start + 4])[0]).strftime("%B %d, %Y %H:%M:%S.%f")
            start += 4
        if CTime:
            parsedBlock["CTime"] = datetime.fromtimestamp \
            (struct.unpack("I", extraField[start:start + 4])[0]).strftime("%B %d, %Y %H:%M:%S.%f")
            start += 4

        return parsedBlock

    def __init__(self):
        pass

class WindowsNTSecurityDescriptor():

    def parse(self, extraField, _zip64Flag):
        parsedBlock = {
        "Name"       :"Windows NT Security Descriptor",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "BSize"      :struct.unpack("<I",extraField[4:8])[0],
        "Version"    :struct.unpack("<B",extraField[8:9])[0],
        "CType"      :struct.unpack("<H",extraField[9:11])[0],
        "EACRC"      :struct.unpack("<I",extraField[11:15])[0],
        }
        #What do I do with this in CRITs?
        parsedBlock["SDData"] = extraField[15:(parsedBlock["TSize"] - 11)]
        return parsedBlock

    def __init__(self):
        pass

class Zip64Extended():

    def parse(self, extraField, zip64Flags):
    #Zip64 Flags are true if data could not fit in Central Directory Bytes
        parsedBlock = {
        "Name"               :"Zip64Extended",
        "BlockTag"           :binascii.hexlify(extraField[0:2]),
        "Size"               :struct.unpack("<H", extraField[2:4])[0],
        }
        #Order is Fixed
        start = 4
        if zip64Flags["ucZip64"]:
            parsedBlock["OriginalSize"] = struct.unpack("<Q", extraField[start:start + 8])[0],
            start += 8
        if zip64Flags["cZip64"]:
            parsedBlock["CompressedSize"] = struct.unpack("<Q", extlraField[start:start + 8])[0],
            start += 8
        if zip64Flags["offsetZip64"]:
            parsedBlock["RelativeOffset"] = struct.unpack("<Q", extraField[start:start + 8])[0],
            start += 8
        if zip64Flags["diskZip64"]:
            parsedBlock["StartDisk"] = struct.unpack("<I", extraField[start:start + 4])[0],
            start += 4

        return parsedBlock

    def __init__(self):
        pass

class OS2():

    def parse(self, extraField, _zip64Flag):
        parsedBlock = {
        "Name"       :"OS/2 Extended Attributes Extra Field",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "BSize"      :struct.unpack("<I", extraField[4:8])[0],
        "CType"      :struct.unpack("<H", extraField[8:10])[0],
        "EACRC"      :struct.unpack("<I", extraField[10:14])[0],
        }
        parsedBlock["EAData"] = extraField[14:(parsedBlock["TSize"] - 10)]
        return parsedBlock

    def __init__(self):
        pass

class OS2ACL():

    def parse(self,extraField,_zip64Flags):
        parsedBlock = {
        "Name"       :"OS/2 Extended Attributes Extra Field",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H", extraField[2:4])[0],
        "BSize"      :struct.unpack("<I", extraField[4:8])[0],
        "CType"      :struct.unpack("<H", extraField[8:10])[0],
        "EACRC"      :struct.unpack("<I", extraField[10:14])[0],
        }
        parsedBlock["EAData"] = extraField[14:(parsedBlock["TSize"] - 10)]
        return parsedBlock

    def __init__(self):
        pass


    def __init__(self):
            pass

    def __init__(self):
            pass

class ASiUnix():

    def parse(self,extraField,_zip64Flags):
        parsedBlock = {
        "Name"       :"ASi Unix Extra Field",
        "BlockTag"   :binascii.hexlify(extraField[0:2]),
        "TSize"      :struct.unpack("<H",extraField[2:4])[0],
        "CRC"        :struct.unpack("<Q",extraField[4:12])[0],
        "Mode"       :struct.unpack("<H",extraField[12:14])[0],
        "SizeDev"    :struct.unpack("<H",extraField[14:22])[0],
        "UID"        :struct.unpack("<H",extraField[22:24])[0],
        "GID"        :struct.unpack("<H",extraField[24:26])[0],
        }
        end = (26 + (parsedBlock["TSize"] - 22))
        parsedBlock["FileName"] = extraField[26:end]
        return parsedBlock

    def __init__(self):
        pass

class UnknownExtraField ():

    def parse(self, extraField, _zip64Flag):
        parsedBlock = {
        "Name"          :"UnknownHeader",
        "BlockTag"      :binascii.hexlify(extraField[0:2]),
        "CSize"         :struct.unpack("<H", extraField[2:4])[0],
        "Data"          :binascii.hexlify(extraField[4:])
        }
        return parsedBlock

    def __init__(self):
            pass
