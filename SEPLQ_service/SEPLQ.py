#!/usr/bin/python
__description__ = '%prog - extracts payload and metadata from a Symantec Local Quarantine files'
__author__ = 'Adam Polkosnik <adam.polkosnik@ny.frb.org> <apolkosnik@gmail.com>'
__date__ = '2015-04-08'
__version__ = '0.3 ('+ __date__ + ')'
__license__ = "MIT"

from struct import unpack
#from collections import defaultdict
import os, sys, io, platform, datetime, binascii, hashlib, re


""""
TODO: 
 - add code to handle VBN files with more than 1 file (but then again, the one that I have has two identical payloads)
 - get better meta 
 
 History:
 - 0.01 - 2014/05/20 - Reversing the file format, and initial version
 - 0.02 - 2015/01/20 - more reliable de-chunking
 - 0.03 - 2015/04/08 - fixes and turned it into a module for CRITs
"""
def ExtractPayloads(data):

    xorkeya5 = 0xa5
    xorkey5a = 0x5a
    xorkeyff = 0xff
 
    def ExtractFromLocal(data):
        data5a = bytearray(len(data))
        #dataff = bytearray(len(data))
        dechunked = bytearray() 
        shortone = False
        if data[0:4] == b'\x90\x12\x00\x00':
            xor1_start = unpack('<L',data[0:4])[0]
            for k in range(len(data)):
                #data5a[k] ^= xorkey5a
                f = data[k]
                f ^= xorkey5a
                data5a[k] = f
            #print (binascii.hexlify(data5a[0x1316:0x1316+4]))
            file_count = unpack('<L',data5a[0x1316: 0x1316 + 4])[0]
            payload_size = unpack('<L',data5a[0x12b0: 0x12b0+ 4])[0]
            hash_start = len(data) - payload_size
            #print("len_data: %x, payload_size: %x, hash_start: %x" % (len(data), payload_size, hash_start))
            #md5_start_test = re.finditer("\x03\x03\x00\x00\x00\x0a\x01\x08", str(data5a))
            hash_pattern = re.compile(b'\x0a\x01\x08\x52')
            hash_headers5a = [md.start() for md in hash_pattern.finditer(data5a)]
            #for h in hash_headers5a:
            #    #print("hash_header 5a: 0x%x" % h)
            hash_start += data5a[hash_start:hash_start+80].find('\x03\x03\x00\x00\x00\x0a\x01\x08')
            #print("hash_start_found: %X" % hash_start)
            #payload_off = len(data) - unpack('<L',data5a[\x12b0: \x12b0+ 4])[0] #+ 16 + 1 #\x0a + \x52 + \x0f + \x01 = 0x6d
            #print (binascii.hexlify(data5a[hash_start:hash_start+8]))
            if (data5a[hash_start:hash_start+8] == b'\x03\x03\x00\x00\x00\x0a\x01\x08'):
                hash_size = unpack('<L',data5a[hash_start+8:hash_start+8+4])[0]
                next_one = hash_start+12+ hash_size
                #print("hash_size: %d" % hash_size)
                #print ("next one: %s" % binascii.hexlify(data5a[next_one:next_one+8]))
                sample_size_off= next_one + 15
            #print ("sample_size_off: %s" % binascii.hexlify(data5a[sample_size_off:sample_size_off+8])) 
            sample_size = unpack('<Q',data5a[(sample_size_off):(sample_size_off+8)])[0]
            
            #payload_off = len(data) - unpack('<Q',data5a[(sample_size_off):(sample_size_off+8)])[0]

            #print "Payload_offset: 0x%x" % payload_off
            #print binascii.hexlify(str(data5a[(payload_off):(payload_off+8)]))
            
            #print "sample_size: 0x%x (%d)" % (sample_size, sample_size)

            if data5a[next_one + 5 :next_one + 8] != b'\x03\x20\x08':      
                perm_block_size = unpack('<L',data5a[sample_size_off + 9:sample_size_off + 13])[0]
                #print("Perm block size: %x" % perm_block_size)
                payload_off = sample_size_off + 13+ perm_block_size +19
            else:
                # I saw this happening with a file that had two hash blocks...indicating multiple files being squished inside a single VBN
                payload_off = sample_size_off + 13
                
            #print ("Payload_offset: 0x%x" % payload_off)
            sep_off = payload_off - 5
            #print ("Chunk: %s, Payload: %s " %(binascii.hexlify(data5a[sep_off:payload_off]), binascii.hexlify(data5a[payload_off:payload_off+8])))
            #print( binascii.hexlify(data5a[payload_off-5:payload_off-4]))
            chunk_size = 0
            if(unpack('<B',data5a[sep_off: sep_off+1])[0] == 0x09):
                chunk_size=unpack('<L',data5a[payload_off -4: payload_off])[0]
            else:
                chunk_size=unpack('<L',data5a[payload_off -4: payload_off])[0] 
                #raise("no chunk size!")
            print( "chunk size: %x" % chunk_size)
            dechunked += data5a[payload_off:chunk_size + payload_off]
            if payload_off+chunk_size +1 < len(data5a):
                if (unpack('<B',data5a[payload_off+chunk_size:chunk_size + payload_off+1])[0] == 0x09 ):
                    next_chunk_size = unpack('<L',data5a[payload_off + chunk_size + 1: payload_off+chunk_size + 5])[0]
                    #print( "next chunk size: %d" % next_chunk_size)

                n = -1
                m = 0
                lastb = payload_off + chunk_size
                for i in range(0, len(data), chunk_size):
                    if i > 0: #payload_off:
                        n += 1
                        next_off = (sep_off + i + (n*5) + 5 )
                        #print("i:%x n:%x next_off @ 0x%x [%s]" % (i, n ,next_off, binascii.hexlify(data5a[next_off : next_off + 5 ])))
                        if (unpack('<B',data5a[next_off: next_off+1 ])[0] == 0x09):
                            dechunked += data5a[next_off+5 : next_off+chunk_size+5]
                            #print("Write:%x @ %x:%x [%s] Ending:[%s]" % ( chunk_size -5, next_off+5, next_off+chunk_size , binascii.hexlify(data[next_off : next_off + 5 ]), binascii.hexlify(data5a[next_off+chunk_size:next_off+chunk_size+5+5+5]) ))
                            next_chunk = next_off+ chunk_size +5
                            if next_chunk < len(data5a):
                                if (data5a[next_chunk: next_chunk+1 ][0] != 0x09):
                                    chunk_size = 0
                                    #print("0x%x:[%s]" % (next_chunk, binascii.hexlify(data5a[next_chunk: next_chunk+5 ])))
                                    break
                            else:
                                break #end reached
                            #print("next_chunk:%x next_off:%x chunk_size:%x next_chunk[%s]" % (next_chunk, next_off, chunk_size ,binascii.hexlify(data5a[next_chunk :next_chunk +5]) ))
                            chunk_size=unpack('<L',data5a[next_chunk+1:next_chunk +5])[0]
                            lastb = next_off + chunk_size
                            #print("offset: %d (%x), New chunk size: %x [%s]" % (i, i, chunk_size, binascii.hexlify(data5a[payload_off +i+ (n*5): payload_off+5+i+(n*5)])))
                        else:
                            #Corner case... Bad SEP!
                            dechunked += data5a[payload_off:payload_off+ sample_size ]
                            #print("Garbage chunk encountered! i:%d m:%d %d (x%x) end:%d" % ( i, n, len(dechunked),len(dechunked), payload_off+ sample_size) )
                            break

            else:
                print ("Single chunk!")
                
                            
            for k in range(len(dechunked)):
                dechunked[k] ^= xorkeyff

            return (dechunked, len(dechunked),sample_size)
        else:
            #do something for other cases... empty
            return (dechunked, len(dechunked), len(dechunked) )

#fstats = os.stat(sys.argv[1])
    if not data:
        data = bytearray(file(sys.argv[1], "rb").read())
    payload_start = 0
    payload_end = 0
    payload_length = 0
    meta_count= 0
    offset = 0

    #header=defaultdict(defaultdict)
    meta = ""
    if data[0:4] == b'\x90\x12\x00\x00':
        n = data[4:255+5].find("\x00")
        if n > 0:
            orig_filename =    data[4:n+4]
            meta += (orig_filename+ ",")
        else:
            orig_filename = ""
        n = data[0x184:0x184+512].find(b'\x00')
        if n > 0:
            meta +=    data[0x184:0x184+n]
        else:
            meta += ""

        timestamp = str(datetime.datetime.fromtimestamp(unpack('<L',data[0xd70:0xd70 + 4])[0]))
        #print("timestamp: %s" % timestamp)
        meta += (',"' + timestamp+'"')
        #print("meta: %s" % meta)
        
        (extracted,d_len,d_size) = ExtractFromLocal(data)  
        payload_length = 0
        payload_length = d_size
        # print ("payload_length: %x" % payload_length )
        # pattern = re.compile(b'\x09..\x00\x00')
        # separs = [m.start() for m in pattern.finditer(data)]
        # if separs:
        #     print("Separator count: %d"% len(separs))
        # sanity check #1 
        # MZheaders = [n.start() for n in re.finditer(b'\x4d\x5a', data)]
        # if MZheaders:
            # #print ("Found possible: MZ headers first at: %s (0x%x): Full list: %s" % ( str(MZheaders[0]), int(MZheaders[0]), str(MZheaders)))
            # #print (binascii.hexlify(data[0:20]))
            # pepattern = re.compile(b'\x50\x45\x00\x00')
            # PEheaders = [o.start() for o in pepattern.finditer(data)]
            # for q in MZheaders:
                # hit = unpack("<H",data[q+60:q+62])[0]
                # if hit in PEheaders:
                    # print ("Found MZ: %s (0x%x), followed by PE: %s (0x%x)" % ( str(q), int(q), str(hit), int(hit)))           

        return meta, extracted
    else:
        print ("Not a valid Symantec Local Quarantine file!")
        return -1, -1

if __name__ == "__main__":
    ExtractPayloads(data=False)
