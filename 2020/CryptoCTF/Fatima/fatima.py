#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from fastecdsa.curve import Curve
from fastecdsa.point import Point
import math, random
from flag import flag
import time 

def multiply(A, B): 
	ac, ar, bc, br = len(A[0]), len(A), len(B[0]), len(B)
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

def pow_matrix(A, n):
	R = circulant([1] + [0 for i in range(len(A)-1)])
	for _ in range(n):
		R = multiply(R, A)
	return R

def circulant(v):
	C, n = [], len(v)
	for i in range(n):
		C.append(v)
		tmp = []
		tmp.append (v[-1])
		tmp.extend(v[:-1])
		v = tmp
	return C

def spiral(A):
	row = len(A)
	col = len(A[0])
	top = 0
	left = 0
	tmp = []

	while (top < row and left < col) :       
		for i in range(left,col) : 
			tmp.append(A[top][i])              
		top += 1
		for i in range(top,row) : 
			tmp.append(A[i][col - 1])     
		col -= 1
		if ( top < row) : 
			for i in range(col - 1,(left - 1),-1) : 
				tmp.append(A[row - 1][i])  
			row -= 1
		  
		if (left < col) : 
			for i in range(row - 1,top - 1,-1) : 
				tmp.append(A[i][left])   
			left += 1
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

def revspiral(A):
	tmp = sum(spiral(A),[])
	tmp = tmp[::-1]
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

def sinwaveform(A):
	row = len(A)
	col = len(A[0])
	tmp = []
	for j in range(col):
		if j%2 == 0:
			for i in range(row):
				tmp.append(A[i][j])
		else:
			for i in range(row-1,-1,-1 ):
				tmp.append(A[i][j])
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

def helical(A):
	row = len(A)
	col = len(A[0])
	tmp = []
	dir = 0 
	for k in range(0,row):
		if dir == 0:
			i = k
			for j in range(0,k+1):
				tmp.append(A[i][j])
				i -= 1
			dir = 1
		else:
			j = k
			for i in range(0,k+1):
				tmp.append(A[i][j])
				j -= 1
			dir = 0
	for k in range(1, row):
		if dir == 0:
			i = row - 1
			for j in range(k, row):
				tmp.append(A[i][j])
				i -= 1
			dir = 1
		else:
			j = row - 1 
			for i in range(k, row):
				tmp.append(A[i][j])
				j -= 1
			dir = 0
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

def revhelical(A):
	tmp = sum(helical(A),[])
	tmp = tmp[::-1]
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(tmp[i*len(A[0]) + j])
		result.append(r)
	return result

dict_traversal = {
	1: spiral,
	2: revspiral,
	3: sinwaveform,
	4: helical,
	5: revhelical
}

def c2p(c, G):
	C = ord(c) * G
	return bin(C.x)[2:].zfill(8) + bin(C.y)[2:].zfill(8)

def aux(msg, G):
	enc = ''
	for c in msg:
		enc += c2p(c, G)
	return enc

def enmat(c, l):
	s = int(math.sqrt(len(c) // l))
	return [[int(c[i*l:i*l+l], 2) for i in range(s * j, s * (j + 1))] for j in range(s) ]

def encrypt(msg):
	name = 'curve'.encode('utf-8')
	p, a, b, q, gx, gy, aux = 241, 173, 41, 256, 53, 192, ''
	curve = Curve(name, p, a, b, q, gx, gy)
	G = Point(gx, gy, curve = curve)

	for c in msg:
		aux += c2p(c, G)
	B = enmat(aux, 3)
	S = list(range(1,6))
	random.shuffle(S)
	for i in range(5):
		B = dict_traversal[S[i]](B)
	C = circulant([0 for i in range(len(B)-1)] + [1])
	a, l = [random.randint(2, len(B)) for _ in '01']
	CL = pow_matrix(C, l)
	CAL = pow_matrix(CL, a)
	enc = (CL[0], multiply(B, CAL))
	return enc
print("enc = ", encrypt(flag))