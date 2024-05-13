# -----------------------------------------------------------------------------
#             
# Copyright 2013-2019 lispers.net - Dino Farinacci <farinacci@gmail.com>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.    
#
# -----------------------------------------------------------------------------
# 
# remove-lisp-iptables.py
#
# This python script deconifgures iptables that lisp_itr_kernel_filter() 
# configured. This script will also remove routes and ARP entries associated
# with vlan4094 if "program-hardware = yes" is configured.
# 
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
import os
import platform
from subprocess import getoutput
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
def ooO0oo0oO0 ( agg , prefix ) :
 oo00 , o00 = agg . split ( "/" )
 o00 = int ( o00 )
 Oo0oO0ooo = ( 2 ** o00 ) - 1
 Oo0oO0ooo <<= 32 - o00
 if 56 - 56: I11i - i1IIi
 oo00 = oo00 . split ( "." )
 oo00 = int ( oo00 [ 0 ] ) << 24 | int ( oo00 [ 1 ] ) << 16 | int ( oo00 [ 2 ] ) << 8 | int ( oo00 [ 3 ] )
 if ( prefix . find ( "/" ) != - 1 ) : prefix = prefix . split ( "/" ) [ 0 ]
 o00oOoo = prefix . split ( "." )
 o00oOoo = int ( o00oOoo [ 0 ] ) << 24 | int ( o00oOoo [ 1 ] ) << 16 | int ( o00oOoo [ 2 ] ) << 8 | int ( o00oOoo [ 3 ] )
 return ( ( o00oOoo & Oo0oO0ooo ) == ( oo00 & Oo0oO0ooo ) )
 if 78 - 78: I11i / OoO0O00 - O0 . IiII
 if 91 - 91: I1ii11iIi11i * iIii1I11I1II1 . IiII / Ii1I
 if 87 - 87: i1IIi / Ii1I . OoO0O00 * OoooooooOO - IiII * ooOoO0o
 if 82 - 82: I11i . I1Ii111 / IiII % II111iiii % iIii1I11I1II1 % IiII
if ( platform . uname ( ) [ 0 ] != "Linux" ) : exit ( 0 )
if 86 - 86: OoOoOO00 % I1IiiI
print ( "Removing iptables configuration" )
if 80 - 80: OoooooooOO . I1IiiI
OOO0O = [
 "sudo iptables -t raw -D PREROUTING -j lisp" ,
 "sudo iptables -t raw -F lisp" ,
 "sudo iptables -t raw -X lisp" ,
 "sudo ip6tables -t raw -D PREROUTING -j lisp" ,
 "sudo ip6tables -t raw -F lisp" ,
 "sudo ip6tables -t raw -X lisp" ,
 "sudo iptables -D POSTROUTING -t mangle -p tcp -j CHECKSUM --checksum-fill" ,
 "sudo iptables -D POSTROUTING -t mangle -p udp -j CHECKSUM --checksum-fill" ,
 "sudo ip6tables -D POSTROUTING -t mangle -p tcp -j CHECKSUM --checksum-fill" ,
 "sudo ip6tables -D POSTROUTING -t mangle -p udp -j CHECKSUM --checksum-fill" ,
 "sudo iptables -t nat -F POSTROUTING"
 ]
if 94 - 94: ooOoO0o
for IiI1i in OOO0O :
 os . system ( IiI1i + " 2> /dev/null" )
 if 61 - 61: I1ii11iIi11i + I11i / I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % OOooOOo . I1IiiI / I11i * I1IiiI
 if 31 - 31: II111iiii + OoO0O00 . I1Ii111
 if 68 - 68: I1IiiI - i11iIiiIii - OoO0O00 / OOooOOo - OoO0O00 + i1IIi
 if 48 - 48: OoooooooOO % o0oOOo0O0Ooo . I1IiiI - Ii1I % i1IIi % OoooooooOO
i1iIIi1 = getoutput ( "egrep 'program-hardware = yes' ./lisp.config" )
if ( i1iIIi1 == "" or i1iIIi1 [ 0 ] != " " ) : exit ( 0 )
if 50 - 50: i11iIiiIii - Ii1I
print ( "Removing programmed routes and arp entries" )
if 78 - 78: OoO0O00
IiI1i = 'ip route | egrep vlan4094 | egrep -v "metric 1"'
Iii1I111 = getoutput ( IiI1i )
Iii1I111 = [ ] if Iii1I111 == "" else Iii1I111 . split ( "\n" )
OO0O0O00OooO = getoutput ( "arp -n | egrep vlan4094" )
OO0O0O00OooO = [ ] if OO0O0O00OooO == "" else OO0O0O00OooO . split ( "\n" )
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
for i1iIIIiI1I in Iii1I111 :
 OOoO000O0OO = i1iIIIiI1I . split ( " via" ) [ 0 ]
 os . system ( "ip route delete {}" . format ( OOoO000O0OO ) )
 if 23 - 23: i11iIiiIii + I1IiiI
 if 68 - 68: OoOoOO00 . oO0o . i11iIiiIii
for II in OO0O0O00OooO :
 iI = II . split ( " " ) [ 0 ]
 os . system ( "arp -d {}" . format ( iI ) )
 if 22 - 22: Oo0Ooo % Ii1I
 if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
 if 100 - 100: Ii1I - Ii1I - I1Ii111
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if 97 - 97: i11iIiiIii
i1iIIi1 = "egrep 'eid-prefix = .*\n.*dynamic-eid = yes' lisp.config"
i1iIIi1 = getoutput ( i1iIIi1 )
if ( i1iIIi1 == "" ) : exit ( 0 )
if ( i1iIIi1 [ 0 ] in [ "<" , ">" , "#" ] ) : exit ( 0 )
i1iIIi1 = i1iIIi1 . split ( "\n" )
if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
o0OOOOO00o0O0 = [ ]
for o0o0OOO0o0 in i1iIIi1 :
 if ( o0o0OOO0o0 . find ( "eid-prefix" ) == - 1 ) : continue
 i1iIIIiI1I = o0o0OOO0o0 . split ( "= " ) [ 1 ]
 o0OOOOO00o0O0 . append ( i1iIIIiI1I )
 if 84 - 84: IiII
 if 25 - 25: Oo0Ooo - IiII . OoooooooOO
print ( "Found {} dynamic-EID prefixes: {}" . format ( len ( o0OOOOO00o0O0 ) , o0OOOOO00o0O0 ) )
if 22 - 22: IiII + II111iiii % I1Ii111 . I11i . OoOoOO00
Iii1I111 = getoutput ( "ip route" )
Iii1I111 = Iii1I111 . split ( "\n" )
if 76 - 76: OoOoOO00 - O0 % OOooOOo / I1ii11iIi11i / OoOoOO00
oo0oooooO0 = None
i11Iiii = [ ]
for i1iIIIiI1I in Iii1I111 :
 OOoO000O0OO = i1iIIIiI1I . split ( " " ) [ 0 ]
 if ( OOoO000O0OO in o0OOOOO00o0O0 ) : oo0oooooO0 = OOoO000O0OO
 if ( oo0oooooO0 == None ) : continue
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if ( ooO0oo0oO0 ( oo0oooooO0 , OOoO000O0OO ) ) :
  i11Iiii . append ( OOoO000O0OO )
 else :
  oo0oooooO0 = None
  if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
  if 45 - 45: I1Ii111 . OoOoOO00
  if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
for i1iIIIiI1I in i11Iiii :
 os . system ( "ip route delete {}" . format ( i1iIIIiI1I ) )
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
print ( "Deleted {} dynamic-EIDs:" . format ( len ( i11Iiii ) ) )
print ( "  " , i11Iiii )
if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
exit ( 0 )
if 8 - 8: OoOoOO00
if 60 - 60: I11i / I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
