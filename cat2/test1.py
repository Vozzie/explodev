
import os

with open('test.dat', 'wb') as outfile:
	
	for i in range(255, -1, -1):
		
		current = bytearray('{:02x}'.format(i) * 5, 'ascii')
		outfile.write(current + bytes([i]) + current + b'\r\n')

os.system('START CMD.EXE /K ..\\cat\\cat.exe test.dat')
