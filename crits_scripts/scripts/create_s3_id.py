import os

from crits.core.basescript import CRITsBaseScript

NUM_BYTES = 64
NUM_HEX_CHARS = NUM_BYTES * 2
SEG_SIZE = 63
SEPARATOR = '.'

# Creates a unique id suitable for a suffix for naming S3 buckets.
# The suffix is separated into segments of no more than SEG_SIZE by the
# SEPARATOR character.
# See http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
# for bucket naming restrictions
# Note: we are losing some randomness by replacing characters with SEPARATOR
def create_id():
    id = os.urandom(NUM_BYTES)
    id_hex = list(id.encode('hex'))

    for i in range (SEG_SIZE, NUM_HEX_CHARS, SEG_SIZE + 1):
       # bucket names cannot end with a period, so go back one if we are at the end
       if i == (NUM_HEX_CHARS - 1):
            id_hex[i - 1] = SEPARATOR
       else:
            id_hex[i] = SEPARATOR

    return "".join(id_hex)

def insert_id(id, infile, outfile):
    with open(infile,'r') as f:
        lines = f.readlines()
        f.close()

    with open(outfile, 'w') as f:
        for line in lines:
            if line.startswith("S3_ID"):
                f.write("S3_ID = \"" + id + "\"\n")
            else:
                f.write(line)

class CRITsScript(CRITsBaseScript):

    def __init__(self, user=None):
        super(CRITsScript, self).__init__(user=user)

    def run(self, argv):
        id = create_id()
        print id
