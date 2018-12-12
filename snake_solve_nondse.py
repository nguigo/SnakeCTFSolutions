#!/usr/bin/env python3
import string

possible = string.printable 
given = [ 0x01, 0x95, 0x66, 0x3e,
		0x1b, 0x56, 0x64, 0x2c,
		0x28, 0x0a, 0x9a, 0x04,
		0xad, 0x0c, 0xc8, 0xd9 ]
ans = ''
savedbl = 0x00

def rshift(num, n):
	mask = 0x00
	if num >> 7:
		mask = ((0xFF << 8) >> n) & 0xFF
	num = num >> n
	num &= 0xFF
	num ^= mask
	return num

for i in range(0, len(given)):
	print(f'Checking index: {i}')
	for c in possible:
		print(c, end='\r')
		if i == 0:
			savedbl = ord(c)
		cl = savedbl << 6 & 0xFF
		bl = rshift(savedbl, 2)
		cl |= bl
		cl ^= 0xAE
		dl = rshift(cl, 3)
		cl = cl << 5 & 0xFF
		dl |= cl
		dl ^= 0x66
		al = rshift(dl, 1)
		dl = dl << 7 & 0xFF
		bl = rshift(ord(c), 4)
		bl |= dl
		bl |= al
		bl = ~bl & 0xFF
		bl = bl ^ ord(c)
		if bl == given[i]:
			ans += c
			savedbl = ~bl & 0xFF
			break
print(f'PASSFORMONSTER: {ans}')
