"""

...File: asmfmt.py

Purpose: Encode a x86 payload and avoid control characters
         and output format for use in the masm test project

..Usage: asmfmt.py -h

########################################################################

Copyright 2018 (c) Vozzie <https://vozzie.be>

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the 
"Software"), to deal in the Software without restriction, including 
without limitation the rights to use, copy, modify, merge, publish, 
distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so, subject to 
the following conditions:

 * The above copyright notice, this list of conditions and the 
   following disclaimer shall be included in all copies or substantial 
   portions of the Software.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * The name of Vozzie may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

########################################################################
"""

def main():
	import argparse
	import sys
	parser = argparse.ArgumentParser(description='Encode and format for masm.')
	parser.add_argument('in', type=argparse.FileType('r'), help='The input file with payload.')
	parser.add_argument('--out', type=argparse.FileType('w'), default=sys.stdout, help='The output file, default stdout.')
	args = vars(parser.parse_args())
	convert(args["in"], args["out"], args)
	
def convert(infile, outfile, size, args={}):
	from binascii import hexlify, unhexlify
	from phobectrl import encode_payload_and_create_table, remove_controlchars_from_size_and_mask
	
	table, payload = encode_payload_and_create_table(unhexlify(infile.read()))
	mask, size = remove_controlchars_from_size_and_mask(len(table) * 2)

	outfile.write('    ; Mov size to ecx\n')
	outfile.write('    Mov Ecx, 0' + swap4(size).hex() + 'H\n')
	outfile.write('    ; Mask size\n')
	if size.hex() == mask.hex(): outfile.write(';')
	outfile.write('    And Ecx, 0' + swap4(mask).hex() + 'H\n')
	
	outfile.write('\ntable:\n')
	outfile.write('\n    ; Index table of encoded bytes\n')
	for dw in table: outfile.write('    DW 0' + swap2(unhexlify(dw)).hex() + 'H\n')

	outfile.write('\npayload:\n')
	outfile.write('\n    ; Encoded payload\n')
	for db in payload: outfile.write('    DB 0' + hex(db)[2:].upper() + 'H\n')

def swap2(value):
	from struct import pack, unpack
	return pack('<H', *unpack('>H', value))

def swap4(value):
	from struct import pack, unpack
	return pack('<I', *unpack('>I', value))

if __name__ == "__main__": main()