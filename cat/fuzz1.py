"""

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

"""

from pattern import createPattern 

with open('pattern.dat', 'w') as f:
	f.write(createPattern(8192))
