#!/usr/bin/env python3

import math 
import string
import random
from secret import flag, key

mapstr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!{}_"

def multiply(A ,B): 
	ac,ar,bc,br = len(A[0]), len(A), len(B[0]), len(B)
	if ac != br:
		return None
	result = []
	for i in range(ar):
		r = []
		for j in range(bc):
			r.append(0)
		result.append(r)
	for i in range(ar): 
		for j in range(bc): 
			for k in range(br): 
				result[i][j] += A[i][k] * B[k][j] 	
	return result


def comple_congruent (z):
	a = z.real % len(mapstr)
	b = z.imag % len(mapstr) 
	return a + b * 1j

def plain_to_matrix(msg ,n): 
	p = int(math.ceil(len(msg) // (2 * n))) + 1

	matrix_row_size = n
	matrix_col_size = p
	index = 0
	matrix_plain = []
	for i in range(matrix_row_size):
		col = []
		for j in range(matrix_col_size):
			if index >= len(msg):
				col.append(0 + 0.j)
			elif index == len(msg)-1:
				col.append(mapstr.index(msg[index]) + 0.j)
				index += 1
			else:
				col.append(mapstr.index(msg[index]) + mapstr.index(msg[index+1]) * 1.j)
				index += 2
		matrix_plain.append(col)
	return matrix_plain


def encrypt(flag ,key):
	n = len(key)
	p = int(math.ceil(len(flag) // (2 * n))) + 1
	matrix_plain = plain_to_matrix(flag, n)
	key_congruent = []
	for i in range(n):
		r = []
		for j in range(n):
			r.append(comple_congruent(key[i][j]))
		key_congruent.append(r)
	cipher = multiply (key_congruent, matrix_plain)
	result = []
	for i in range(n):
		r = []
		for j in range(p):
			r.append(comple_congruent(cipher[i][j]))
		result.append(r)
	return result

cipher = encrypt(flag, key)
print("cipher = ", cipher)


