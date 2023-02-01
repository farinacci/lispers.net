#!/usr/bin/python
# 
# s2-poster.py - Selector Poster for pushing loc8tr output
#
# Usage: python s2-poster.py <server-1>:<port> ... <server-n>:<port>
#
# This is a daemon program that watches for directories created by the
# loc8tr.py telemetry tool. When it finds a new directory, it will take
# the data from loc8tr.json, format it for Selector's injestion. After
# formatting, then a restful post is issued to the command line servers.
#
#------------------------------------------------------------------------------
from __future__ import print_function
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
import time
import os
import sys
import json
import socket
import requests
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
IiiIII111iI = False
if 34 - 34: iii1I1I / O00oOoOoO0o0O . O0oo0OO0 + Oo0ooO0oo0oO . OoO0O00 - I1ii11iIi11i
if 53 - 53: I11i / Oo0Ooo / II111iiii % Ii1I / OoOoOO00 . Oo0ooO0oo0oO
if 100 - 100: i1IIi
if 27 - 27: O00oOoOoO0o0O * OoooooooOO + I11i * Oo0ooO0oo0oO - i11iIiiIii - iii1I1I
if 30 - 30: iIii1I11I1II1 * iIii1I11I1II1 . II111iiii - oO0o
if 72 - 72: II111iiii - OoOoOO00
if 91 - 91: OoO0O00 . i11iIiiIii / oO0o % I11i / OoO0O00 - i11iIiiIii
if 8 - 8: o0oOOo0O0Ooo * I1ii11iIi11i * iIii1I11I1II1 . O00oOoOoO0o0O / O00oOoOoO0o0O % O00oOoOoO0o0O
def i11 ( ) :
 if 41 - 41: O0oo0OO0 . Oo0ooO0oo0oO * O00oOoOoO0o0O % i11iIiiIii
 if 74 - 74: iii1I1I * O00oOoOoO0o0O
 if 82 - 82: iIii1I11I1II1 % O00oOoOoO0o0O
 if 86 - 86: OoOoOO00 % I1IiiI
 oo = IiII1I1i1i1ii ( )
 if ( oo == [ ] ) : return ( False )
 if 44 - 44: oO0o / Oo0Ooo - II111iiii - i11iIiiIii % O0oo0OO0
 if 54 - 54: OOooOOo % O0 + I1IiiI - iii1I1I / I11i
 if 31 - 31: OoO0O00 + II111iiii
 if 13 - 13: OOooOOo * oO0o * I1IiiI
 oOOOO = 10
 while ( True ) :
  if 45 - 45: O0oo0OO0 + Ii1I
  if 17 - 17: o0oOOo0O0Ooo
  if 64 - 64: Ii1I % i1IIi % OoooooooOO
  if 3 - 3: iii1I1I + O0
  I1Ii = getoutput ( "date" )
  print ( "{} scanning loc8tr directories ..." . format ( o0oOo0Ooo0O ( I1Ii ) ) , end = " " )
  if 81 - 81: I1ii11iIi11i * O00oOoOoO0o0O * I11i - iii1I1I - o0oOOo0O0Ooo
  OooO0OO = iiiIi ( )
  IiIIIiI1I1 = getoutput ( "ls -1d loc8tr-* | wc -l" )
  IiIIIiI1I1 = int ( IiIIIiI1I1 ) - len ( OooO0OO ) if IiIIIiI1I1 . isdigit ( ) else 0
  print ( "found posted {}, new {}" . format ( IiIIIiI1I1 , len ( OooO0OO ) ) )
  if 86 - 86: i11iIiiIii + Ii1I + Oo0ooO0oo0oO * I11i + o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 / i11iIiiIii
  if 34 - 34: OoooooooOO + iIii1I11I1II1 + i11iIiiIii - I1ii11iIi11i + i11iIiiIii
  if 65 - 65: OoOoOO00
  for ii1I in OooO0OO :
   OooO0 = "{}/loc8tr.json" . format ( ii1I )
   print ( "Found {} to format and post" . format ( o0oOo0Ooo0O ( ii1I ) ) )
   if 35 - 35: OOooOOo % O0oo0OO0 % i11iIiiIii / OoooooooOO
   if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iii1I1I
   if 97 - 97: i11iIiiIii
   if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . O00oOoOoO0o0O
   o0OOOOO00o0O0 = o0o0OOO0o0 ( OooO0 )
   if ( o0OOOOO00o0O0 == { } ) : continue
   if 84 - 84: O00oOoOoO0o0O
   if 25 - 25: Oo0Ooo - O00oOoOoO0o0O . OoooooooOO
   if 22 - 22: O00oOoOoO0o0O + II111iiii % O0oo0OO0 . I11i . OoOoOO00
   if 76 - 76: OoOoOO00 - O0 % OOooOOo / I1ii11iIi11i / OoOoOO00
   oo0oooooO0 = 0
   for i11Iiii in oo :
    oo0oooooO0 += iI ( i11Iiii , o0OOOOO00o0O0 )
    if 28 - 28: OOooOOo - O00oOoOoO0o0O . O00oOoOoO0o0O + OoOoOO00 - OoooooooOO + O0
    if 95 - 95: OoO0O00 % oO0o . O0
    if 15 - 15: Oo0ooO0oo0oO / Ii1I . Ii1I - i1IIi
    if 53 - 53: O00oOoOoO0o0O + I1IiiI * oO0o
    if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
    if 60 - 60: I11i / I11i
   if ( oo0oooooO0 == len ( oo ) ) :
    os . system ( "touch {}/s2-posted" . format ( ii1I ) )
    if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - O0oo0OO0
    if 83 - 83: OoooooooOO
    if 31 - 31: II111iiii - OOooOOo . O0oo0OO0 % OoOoOO00 - O0
    if 4 - 4: II111iiii / Oo0ooO0oo0oO . iii1I1I
    if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % O0oo0OO0 - I1ii11iIi11i / oO0o
    if 50 - 50: I1IiiI
  time . sleep ( oOOOO )
  if 34 - 34: I1IiiI * II111iiii % iii1I1I * OoOoOO00 - I1IiiI
 return ( True )
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - O0oo0OO0 * iIii1I11I1II1 + iii1I1I
 if 50 - 50: II111iiii - Oo0ooO0oo0oO * I1ii11iIi11i / O0oo0OO0 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / O0oo0OO0 + iii1I1I - II111iiii / Oo0ooO0oo0oO - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
def IiII1I1i1i1ii ( ) :
 if 71 - 71: OOooOOo + Oo0ooO0oo0oO % i11iIiiIii + I1ii11iIi11i - O00oOoOoO0o0O
 if ( len ( sys . argv ) == 1 ) :
  print ( "Usage: python s2-poster.py <svr-1>:<port> ... <svr-n>:<port>" )
  return ( [ ] )
  if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 oo = sys . argv [ 1 : : ]
 if 16 - 16: I1IiiI * oO0o % O00oOoOoO0o0O
 for i11Iiii in oo :
  if ( i11Iiii . find ( ":" ) == - 1 ) :
   print ( "Need :<port> for server {}" . format ( i11Iiii ) )
   return ( [ ] )
   if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . Oo0ooO0oo0oO * I11i
  i1I11i1iI = i11Iiii . split ( ":" ) [ 1 ]
  if ( i1I11i1iI . isdigit ( ) == False ) :
   print ( ":<port> must be decimal" )
   return ( [ ] )
   if 15 - 15: Ii1I - O0 / oO0o * i1IIi
   if 92 - 92: OoOoOO00
 return ( oo )
 if 26 - 26: iii1I1I . O0oo0OO0
 if 68 - 68: OoO0O00
 if 35 - 35: OoO0O00 - iii1I1I / Oo0Ooo / OoOoOO00
 if 24 - 24: Oo0ooO0oo0oO - Oo0ooO0oo0oO / II111iiii - I1ii11iIi11i
 if 69 - 69: oO0o . O0oo0OO0 + Ii1I / Oo0Ooo - oO0o
 if 63 - 63: OOooOOo % oO0o * oO0o * OoO0O00 / I1ii11iIi11i
 if 74 - 74: II111iiii
 if 75 - 75: o0oOOo0O0Ooo . Oo0ooO0oo0oO
 if 54 - 54: II111iiii % OoOoOO00 % I11i % iIii1I11I1II1 + iIii1I11I1II1 * Oo0ooO0oo0oO
def iiiIi ( ) :
 O00O0oOO00O00 = "ls -1d loc8tr-*"
 i1 = getoutput ( O00O0oOO00O00 )
 if ( i1 . find ( "No such file or directory" ) != - 1 ) : return ( [ ] )
 i1 = i1 . split ( "\n" )
 if 57 - 57: O0 / O0oo0OO0 % OoO0O00 / O0oo0OO0 . OoOoOO00 / O0
 OooO0OO = [ ]
 for o000O0o in i1 :
  IiIIIiI1I1 = "{}/s2-posted" . format ( o000O0o )
  if ( os . path . exists ( IiIIIiI1I1 ) ) : continue
  OooO0OO . append ( o000O0o )
  if 42 - 42: OoOoOO00
 return ( OooO0OO )
 if 41 - 41: Oo0Ooo . Oo0ooO0oo0oO + O0 * o0oOOo0O0Ooo % Oo0Ooo * Oo0Ooo
 if 19 - 19: iii1I1I
 if 46 - 46: I1ii11iIi11i - Ii1I . iIii1I11I1II1 / I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * O0oo0OO0 . O00oOoOoO0o0O . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 if 87 - 87: Oo0ooO0oo0oO + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: Oo0ooO0oo0oO / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: O0oo0OO0 . iii1I1I . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iii1I1I
 if 37 - 37: iii1I1I - Oo0ooO0oo0oO * oO0o % i11iIiiIii - O0oo0OO0
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: O00oOoOoO0o0O
 if 57 - 57: oO0o . I11i . i1IIi
 if 42 - 42: I11i + I1ii11iIi11i % O0
 if 6 - 6: oO0o
 if 68 - 68: OoOoOO00 - OoO0O00
 if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
 if 1 - 1: iIii1I11I1II1 / II111iiii
 if 33 - 33: I11i
 if 18 - 18: o0oOOo0O0Ooo % iii1I1I * O0
 if 87 - 87: i11iIiiIii
 if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iii1I1I / iii1I1I - O0oo0OO0
 if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 91 - 91: iii1I1I % i1IIi % iIii1I11I1II1
 if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
 if 45 - 45: oO0o - O00oOoOoO0o0O - OoooooooOO - OoO0O00 . II111iiii / O0
 if 51 - 51: O0 + iii1I1I
 if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
 if 48 - 48: O0
 if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
 if 41 - 41: Ii1I - O0 - O0
 if 68 - 68: OOooOOo % O0oo0OO0
 if 88 - 88: iIii1I11I1II1 - Oo0ooO0oo0oO + OOooOOo
 if 40 - 40: I1IiiI * Ii1I + OOooOOo % iii1I1I
 if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + O0oo0OO0 / OoOoOO00
 if 23 - 23: O0
 if 85 - 85: Ii1I
def o0o0OOO0o0 ( loc8tr_json ) :
 try :
  OO = open ( loc8tr_json , "r" ) ; oo000o = OO . read ( ) ; OO . close ( )
 except :
  print ( "Cannot open file {}" . format ( loc8tr_json ) )
  print ( "" )
  return ( { } )
  if 44 - 44: i1IIi % II111iiii + I11i
 if ( oo000o == "" ) :
  print ( "File {} is empty" . format ( loc8tr_json ) )
  print ( "" )
  return ( { } )
  if 45 - 45: iii1I1I / iii1I1I + O0oo0OO0 + Oo0ooO0oo0oO
  if 47 - 47: o0oOOo0O0Ooo + Oo0ooO0oo0oO
 OoO = json . loads ( oo000o )
 if 88 - 88: iii1I1I . II111iiii * II111iiii % O0oo0OO0
 if 15 - 15: i1IIi * I1IiiI + i11iIiiIii
 if 6 - 6: Oo0ooO0oo0oO / i11iIiiIii + iii1I1I * oO0o
 if 80 - 80: II111iiii
 O0O = socket . gethostname ( )
 i1I1I = { "Reports" : [ { "reporter" : O0O , "report-data" : [ ] } ] }
 if 12 - 12: i11iIiiIii / OoO0O00
 if 80 - 80: O0oo0OO0 . i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: OoO0O00
 if 62 - 62: OOooOOo + O0
 oO0OOOO0 = "?"
 iI1I11iiI1i = "./lispers.net/lisp-version.txt"
 if ( os . path . exists ( iI1I11iiI1i ) ) :
  oO0OOOO0 = getoutput ( "cat {}" . format ( iI1I11iiI1i ) )
  if 78 - 78: oO0o % O0 % Ii1I
 i1I1I [ "Label" ] = "lispers.net version {}" . format ( oO0OOOO0 )
 if 46 - 46: OoooooooOO . i11iIiiIii
 if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
 if 87 - 87: Oo0Ooo . O00oOoOoO0o0O
 if 75 - 75: Oo0ooO0oo0oO + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iii1I1I
 for oO in OoO :
  I1Ii1I1 = OoO [ oO ] [ 0 ]
  IiII111iI1ii1 = { "rloc" : oO , "rloc-name" : I1Ii1I1 , "rloc-data" : { } }
  IiII111iI1ii1 [ "rloc-data" ] [ "traceroute" ] = OoO [ oO ] [ 1 ]
  IiII111iI1ii1 [ "rloc-data" ] [ "rtts" ] = OoO [ oO ] [ 3 ]
  IiII111iI1ii1 [ "rloc-data" ] [ "hop-counts" ] = OoO [ oO ] [ 4 ]
  IiII111iI1ii1 [ "rloc-data" ] [ "latencies" ] = OoO [ oO ] [ 5 ]
  i1I1I [ "Reports" ] [ 0 ] [ "report-data" ] . append ( IiII111iI1ii1 )
  if 37 - 37: oO0o - O0oo0OO0 % Oo0Ooo
  if 77 - 77: Oo0Ooo - i1IIi - I11i . OoOoOO00
 if ( IiiIII111iI ) :
  print ( "Selector JSON:" )
  print ( i1I1I )
  if 39 - 39: II111iiii / Oo0ooO0oo0oO + O0oo0OO0 / OoOoOO00
 return ( i1I1I )
 if 13 - 13: O00oOoOoO0o0O + O0 + iii1I1I % I1IiiI / o0oOOo0O0Ooo . O00oOoOoO0o0O
 if 86 - 86: oO0o * o0oOOo0O0Ooo % i1IIi . Ii1I . i11iIiiIii
 if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
 if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
 if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
 if 33 - 33: O0oo0OO0 + iii1I1I * oO0o / iIii1I11I1II1 - I1IiiI
 if 54 - 54: O0oo0OO0 / OOooOOo . oO0o % iii1I1I
 if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
 if 63 - 63: OoOoOO00 * iii1I1I
 if 69 - 69: O0 . OoO0O00
def iI ( server , selector_json ) :
 ii1111iII = "http://{}/col/api/netmon/lisp" . format ( server )
 iiiiI = json . dumps ( selector_json )
 if 62 - 62: OoooooooOO * I1IiiI
 print ( "Post to {} ..." . format ( ii1111iII ) , end = " " )
 if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
 try :
  i1OOoO = requests . post ( ii1111iII , data = iiiiI , timeout = 5 )
  print ( "{}, return-code: {}" . format ( OO0O000 ( "succeeded" ) , i1OOoO . status_code ) )
  return ( 1 )
 except Exception as iiIiI1i1 :
  print ( "{}, error response:\n{}\n" . format ( oO0O00oOOoooO ( "failed" ) , iiIiI1i1 . message ) )
  if 46 - 46: I1IiiI - OoooooooOO - I11i * II111iiii
 return ( 0 )
 if 34 - 34: I11i - iii1I1I / OOooOOo + I1ii11iIi11i * Ii1I
 if 73 - 73: OoOoOO00 . Ii1I * I1ii11iIi11i % I1ii11iIi11i % OoooooooOO
 if 63 - 63: iIii1I11I1II1 * i11iIiiIii % iIii1I11I1II1 * i11iIiiIii
 if 32 - 32: OOooOOo
 if 42 - 42: O00oOoOoO0o0O * O0 % i1IIi . OOooOOo / o0oOOo0O0Ooo
 if 32 - 32: I1IiiI * Oo0Ooo
 if 78 - 78: OOooOOo - OoooooooOO - I1ii11iIi11i / Oo0ooO0oo0oO / II111iiii
def o0oOo0Ooo0O ( string ) :
 return ( "\033[1m" + string + "\033[0m" )
 if 29 - 29: I1IiiI % I1IiiI
 if 94 - 94: iIii1I11I1II1 / Oo0Ooo % iii1I1I * iii1I1I * II111iiii
 if 29 - 29: OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo / OOooOOo * iIii1I11I1II1
 if 62 - 62: OOooOOo / oO0o - OoO0O00 . I11i
 if 11 - 11: I1ii11iIi11i . OoO0O00 * O00oOoOoO0o0O * OoooooooOO + Oo0ooO0oo0oO
 if 33 - 33: O0 * o0oOOo0O0Ooo - O0oo0OO0 % O0oo0OO0
 if 18 - 18: O0oo0OO0 / Oo0Ooo * O0oo0OO0 + O0oo0OO0 * i11iIiiIii * I1ii11iIi11i
def oO0O00oOOoooO ( string ) :
 return ( "\033[91m" + string + "\033[0m" )
 if 11 - 11: Oo0ooO0oo0oO / OoOoOO00 - O00oOoOoO0o0O * OoooooooOO + OoooooooOO . OoOoOO00
 if 26 - 26: Ii1I % I1ii11iIi11i
 if 76 - 76: O00oOoOoO0o0O * iii1I1I
 if 52 - 52: OOooOOo
 if 19 - 19: I1IiiI
 if 25 - 25: Ii1I / Oo0ooO0oo0oO
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + O00oOoOoO0o0O
def OO0O000 ( string ) :
 return ( "\033[92m" + string + "\033[0m" )
 if 71 - 71: O0oo0OO0 . II111iiii
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
 if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 58 - 58: I1IiiI
 if 53 - 53: i1IIi
 if 59 - 59: o0oOOo0O0Ooo
if ( __name__ == "__main__" ) :
 oOoO00O0 = i11 ( )
 exit ( oOoO00O0 )
 if 75 - 75: I1IiiI . Oo0ooO0oo0oO . O0 * O0oo0OO0
 if 4 - 4: Ii1I % oO0o * OoO0O00
 if 100 - 100: O0oo0OO0 * OOooOOo + OOooOOo
 if 54 - 54: OoooooooOO + o0oOOo0O0Ooo - i1IIi % i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
