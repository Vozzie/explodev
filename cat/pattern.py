"""#####################################################################

File: pattern.py

Purpose: Create a pattern for fuzzing an application.

Usage: pattern.py -h
	  
Author: Vozzie <https://www.vozzie.be>

Note: The createPattern method is a modified extract from 
      "mona.py", respectively copyright of:

########################################################################
<notice>

U{Corelan<https://www.corelan.be>}

Copyright (c) 2011-2018, Peter Van Eeckhoutte - Corelan GCV
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Corelan nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN GCV BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

</notice>
#####################################################################"""

import argparse

def main():
	parser = argparse.ArgumentParser(description='%(prog)s: Creates a pattern.')
	parser.add_argument('size', type=int, help='The size of the pattern.')
	parser.add_argument('--c1', type=str, default='', help='First charset, default "ABCDEFGHIJKLMNOPQRSTUVWXYZ".')
	parser.add_argument('--c2', type=str, default='', help='Second charset, default "abcdefghijklmnopqrstuvwxyz".')
	parser.add_argument('--c3', type=str, default='', help='Third charset, default "0123456789".')
	parser.add_argument('--extended', action='store_true', help='Output longer than 20280.')
	parser.add_argument('--silent', action='store_true', help='No other output.')
	args = parser.parse_args()
	print(createPattern(args.size, vars(args)))
	
def createPattern(size,args={}):
	"""
	Create a cyclic (metasploit) pattern of a given size
	
	Arguments:
	size - value indicating desired length of the pattern
	       if value is > 20280, the pattern will repeat itself until it reaches desired length
		   
	Return:
	string containing the cyclic pattern
	"""
	
	if not "extended" in args: args["extended"] = False
	if not "silent" in args: args["silent"] = False

	char1 = args["c1"] if "c1" in args and args["c1"] != '' else 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	char2 = args["c2"] if "c2" in args and args["c2"] != '' else 'abcdefghijklmnopqrstuvwxyz'
	char3 = args["c3"] if "c3" in args and args["c3"] != '' else '0123456789'
	
	if args["extended"]: char3 += ",.;+=-_!&()#@({})[]%"	# ascii, 'filename' friendly
	
	if not args["silent"]:
		if not args["extended"] and size > 20280 and (len(char1) <= 26 or len(char2) <= 26 or len(char3) <= 10):
			msg = "** You have asked to create a pattern > 20280 bytes, but with the current settings\n"
			msg += "the pattern generator can't create a pattern of " + str(size) + " bytes. As a result,\n"
			msg += "the pattern will be repeated for " + str(size-20280)+" bytes until it reaches a length of " + str(size) + " bytes.\n"
			msg += "If you want a unique pattern larger than 20280 bytes, please either use the -extended option\n"
			msg += "or extend one of the 3 charsets using options -c1, -c2 and/or -c3 **\n"
			print(msg)
			return ''
	
	pattern = []
	max = int(size)
	while len(pattern) < max:
		for ch1 in char1:
			for ch2 in char2:
				for ch3 in char3:
					if len(pattern) < max:
						pattern.append(ch1)

					if len(pattern) < max:
						pattern.append(ch2)

					if len(pattern) < max:
						pattern.append(ch3)

	pattern = "".join(pattern)
	return pattern

if __name__ == "__main__": main()