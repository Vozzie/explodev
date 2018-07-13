"""

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
 
"""

from pattern import createPattern

position = 1448
maximum = position + 4
pattern = createPattern(maximum)

with open('pattern.dat', 'w') as f:
	f.write(pattern)
