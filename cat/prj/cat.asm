;EasyCodeName=cat,1

.Code

start:
	Invoke Main
	Invoke ExitProcess, 0

Main Proc Private
	; Also overflowable, but not the intention.
	Local szItemBuffer[MAX_PATH]:CHAR
	Invoke GetCL, 1, Addr szItemBuffer
	.If Eax == 1
		Invoke ReadData, Addr szItemBuffer
	.Else
		Mov Eax, -1
	.EndIf
	Ret
Main EndP

ReadData Proc Private lpszFileName:LPSTR
	Local lpMem:DWord
	Local dwSize:DWord
	Invoke read_disk_file, lpszFileName, Addr lpMem, Addr dwSize
	.If Eax != 0
		Invoke PrintData, lpMem, dwSize
		Invoke GlobalFree, lpMem
		Xor Eax, Eax
	.Else
		Mov Eax, -2
	.EndIf
	Ret
ReadData EndP

PrintData Proc Private lpMem:DWord, dwSize:DWord
	Local szLine[1024]:CHAR
	Local szCRLF:DWord
	Mov szCRLF, 00D0AH
	Xor Eax, Eax
	.Repeat
		Invoke readline, lpMem, Addr szLine, Eax
		Push Eax
		Invoke StdOut, Addr szLine
		Invoke StdOut, Addr szCRLF
		Pop Eax
	.Until Eax == 0
	Ret
PrintData EndP

End start


;.Const

;.Data?

;.Data

;.Code

;start:
;	Invoke Main
;	Invoke ExitProcess, 0

;Main Proc Private
;	; Also overflowable, but not the intention.
;	Local szItemBuffer[MAX_PATH]:CHAR
;	Invoke GetCL, 1, Addr szItemBuffer
;	.If Eax == 1
;		Invoke ReadData, Addr szItemBuffer
;	.ElseIf Eax == 2
;		Invoke StdErr, TextAddr("Commandline argument is missing.", 13, 10)
;	.ElseIf Eax == 3 || Eax == 4
;		Invoke StdErr, TextAddr("Invalid commandline argument format.", 13, 10)
;	.Else
;		Invoke StdErr, TextAddr("Unknown error while parsing commandline argument.", 13, 10)
;	.EndIf
;	Ret
;Main EndP

;ReadData Proc Private lpszFileName:LPSTR
;	Local lpMem:DWord
;	Local dwSize:DWord
;	Invoke StdOut, TextAddr("Reading: ")
;	Invoke StdOut, lpszFileName
;	Invoke StdOut, TextAddr(13, 10)
;	Invoke read_disk_file, lpszFileName, Addr lpMem, Addr dwSize
;	.If Eax != 0
;		Invoke PrintData, lpMem, dwSize
;		Invoke GlobalFree, lpMem
;	.Else
;		Invoke StdErr, TextAddr("Failed to open the file for reading", 13, 10)
;	.EndIf
;	Ret
;ReadData EndP

;PrintData Proc Private lpMem:DWord, dwSize:DWord
;	Local szLine[1024]:CHAR
;	Xor Eax, Eax
;	.Repeat
;		Invoke readline, lpMem, Addr szLine, Eax
;		Push Eax
;		Invoke StdOut, Addr szLine
;		Invoke StdOut, TextAddr(13, 10)
;		Pop Eax
;	.Until Eax == 0
;	Ret
;PrintData EndP

;End start
