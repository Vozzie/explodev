"""

...File: phobectrl.py

Purpose: Encode a x86 payload and avoid control characters.

..Usage: phobectrl.py -h

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
	parser = argparse.ArgumentParser(description='Encode a x86 payload to avoid control chars (c < 32).')
	parser.add_argument('in', type=argparse.FileType('r'), help='The input file with payload as hex string.')
	parser.add_argument('--out', type=argparse.FileType('w'), default=sys.stdout, help='The output file, default stdout.')
	parser.add_argument('--allow', type=str, default='', help='Allowed characters. String in 2 character hex format.')
	parser.add_argument('--verbose', action='store_true', help='Verbose output.')
	args = vars(parser.parse_args())
	args['out'].write(encode(args['in'].read(), args))
	
def encode(payload, args={}):
	'''
	Encodes a payload and removes all control characters (c < 32).
	
	Arguments
	
		payload: A hex string or bytearray.

		args
			.allow: A hex string or bytearray of allowed characters.
			.verbose: Boolean flag.

	Returns
	
		payload: The encoded payload.
	'''
	from binascii import hexlify, unhexlify

	allow = args['allow'] if 'allow' in args else ''
	verbose = args['verbose'] if 'verbose' in args else False

	if type(payload) is str: payload = unhexlify(payload)
	if type(allow) is str: allow = unhexlify(allow)
	
	if verbose:
		print('')
		print('] Encoding payload...')
	
	table, encoded = encode_payload_and_create_table(payload, allow=allow)
	stub = create_decoder_stub(len(table) * 2)

	table = ''.join(table)
	encoded = encoded.hex()
	
	result = (stub + table + encoded).upper()
	
	if verbose:
		print('')
		print('] Allowed bytes:  ' + str(hexlify(allow)))
		print('')
		print(']    Stub length:   {:>4}'.format(int(len(stub) / 2)))
		print(']   Table length: + {:>4}'.format(int(len(table) / 2)))
		print('] Payload length: + {:>4}'.format(int(len(encoded) / 2)))
		print(']   Total length: = {:>4}'.format(int(len(result) / 2)))
		print('')
		print('] Stub:\n{}\n'.format(stub))
		print('] Table:\n{}\n'.format(table))
		print('] Encoded:\n{}\n'.format(encoded))
		print('')
		print('] Result:\n{}\n'.format(result))
		
	return result
	
def create_decoder_stub(table_size):
	'''
	Creates the decoder stub.
	
	Arguments
	
		table_size: The size of the table in bytes.
		
	Returns
	
		A hex string.
	'''
	stub = [
		'EB', ''     , # 0, 1   | JMP SHORT ???
		'80CA80'     , # 2      | OR DL, 80
		'EB', ''     , # 3, 4   | JMP SHORT ???
		'5E'         , # 5      | POP ESI
		'B9', ''     , # 6, 7   | MOV ECX, ???
		''           , # 8      | AND ECX, ???
		'8BFE'       , # 9      | MOV EDI, ESI
		'2BF9'       , # 10     | SUB EDI, ECX
		'F7D9'       , # 11     | NEG ECX
		'D1E9'       , # 12     | SHR ECX, 1
		'33D2'       , # 13     | XOR EDX, EDX
		'668B544EFE' , # 14     | MOV DX, WORD PTR [ESI + ECX * 2 - 2]
		'6681E27F7F' , # 15     | AND DX, 7F7F
		'D0EE'       , # 16     | SHR DH, 1
		'72', ''     , # 17, 18 | JB SHORT ???
		''           , # 19     | NOP NOP
		'80243A7F'   , # 20     | AND BYTE PTR [EDX + EDI], 7F
		'E2', ''     , # 21, 22 | LOOPD SHORT ???
		'FFE7'       , # 23     | JMP EDI
		'E8', ''     ] # 24, 25 | CALL ???
	mask, size = remove_controlchars_from_size_and_mask(table_size)	
	if mask.hex() == size.hex():
		stub[1]  = '2D'
		stub[4]  = '20'
		stub[7]  = size.hex()
		stub[18] = 'DD'
		stub[19] = '9090'
		stub[22] = 'EA'
		stub[25] = 'D3FFFFFF'
	else:
		stub[1]  = '31'
		stub[4]  = '24'
		stub[7]  = size.hex()
		stub[8]  = '81E1' + mask.hex()
		stub[18] = 'D7'
		stub[22] = 'EC'
		stub[25] = 'CFFFFFFF'
	return ''.join(stub)

def encode_payload_and_create_table(payload, allow=b''):
	'''
	Encodes a payload removing all control characters(n < 32)
	
	Arguments
	
		payload: bytearray
		
	Returns table, payload
	
		table: array of hex string which are indexes of encoded bytes
		
		payload: the encoded payload
	'''
	table = []
	payload2 = bytearray()
	for index in range(0, len(payload)):
		value = payload[index]
		if value < 32 and not value in allow:
			high = (index & 0x3F80) >> 7
			low = (index & 0x7F) << 8
			table.append(hex(high | low | 0x8080)[2:])
			value |= 0x80
		payload2.append(value)
	return table, payload2
	
def remove_controlchars_from_size_and_mask(size):
	'''
	Removes control characters (n < 32) from size.
	
	Arguments
	
		size: int
		
	Returns result, mask
		
		result: the value with no control characters
		
		mask: the AND mask to restore to original value
	'''
	from struct import pack
	value = pack('<I', 0xFFFFFFFF - size + 1)
	mask = bytearray()
	size2 = bytearray()
	for b in value:
		if b & 0xE0:
			mask.append(b)
			size2.append(b)
		else:
			mask.append(b | 0x40)
			size2.append(b | 0x20)
	return mask, size2

if __name__ == '__main__': main()