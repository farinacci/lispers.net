#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
# remove-lisp-host-routes.py
#
# This python script will remove /32 host routes that were installed by
# lispers.net during RLOC probing for multi-homing.
#
# Only removes routes for global/public IP addresses to avoid removing
# system routes for private/local addresses.
#
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library . install_aliases ( )
import os
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
print ( "Removing LISP host-routes ..." )
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
Oooo0000 = getoutput ( "ip route | egrep 'via' | egrep -v 'default'" )
Oooo0000 += getoutput ( "ip -6 route | egrep 'via' | egrep -v 'default'" )
if 22 - 22: Ii1I . IiII
if ( Oooo0000 == "" ) :
 print ( "ip route grep returned nothing" )
 exit ( 1 )
 if 41 - 41: I1Ii111 . ooOoO0o * IiII % i11iIiiIii
 if 74 - 74: iII111i * IiII
oo00o0Oo0oo = [ ]
for i1iII1I1i1i1 in Oooo0000 . split ( "\n" ) :
 if ( i1iII1I1i1i1 == "" ) : continue
 i1iIIII = i1iII1I1i1i1 . split ( )
 if ( len ( i1iIIII ) < 5 ) : continue
 if 26 - 26: I1Ii111 . I11i - OOooOOo % O0 + OOooOOo
 i1iiIIiiI111 = i1iIIII [ 0 ]
 oooOOOOO = "" if ( i1iiIIiiI111 . find ( ":" ) == - 1 ) else "-6 "
 i1iiIII111ii = 32 if ( i1iiIIiiI111 . find ( ":" ) == - 1 ) else 128
 os . system ( "sudo ip {}route delete {}/{}" . format ( oooOOOOO , i1iiIIiiI111 , i1iiIII111ii ) )
 oo00o0Oo0oo . append ( i1iiIIiiI111 )
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
print ( "Removed routes:" , oo00o0Oo0oo )
if 78 - 78: OoO0O00
exit ( 0 )
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
