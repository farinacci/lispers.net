#
# provision-lisp.py
#
# For a dynamic LISP xTR node, provision a lisp.config file to be used by the
# lispers.net LISP subsystem. Use template file lisp.config.provision-xtr to
# add EIDs to the configuration. Configure EIDs in the kernel and set kernel
# routing tables for EID source selection. EIDs are randomly created so a LISP
# xTR can be configured in a plug-and-play way.
#
# Usage: python provision-lisp.py <device> <iid> [<ipv4-eid>] [<ipv6-eid>]
#
from __future__ import print_function
import sys
import os
import random
import time
import platform
try :
 from commands import getoutput
except :
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
 if 94 - 94: i1IIi % Oo0Ooo
def o0oO0 ( ) :
 oo00 = random . randint ( 0 , 0xffffff )
 o00 , Oo0oO0ooo , o0oOoO00o = ( oo00 >> 16 ) & 0xff , ( oo00 >> 8 ) & 0xff , oo00 & 0xff
 i1 = "240.{}.{}.{}" . format ( o00 , Oo0oO0ooo , o0oOoO00o )
 oOOoo00O0O = "fe00::{}:{}:{}" . format ( o00 , Oo0oO0ooo , o0oOoO00o )
 return ( i1 , oOOoo00O0O )
 if 15 - 15: I1IiiI
 if 90 - 90: IiII * i1IIi / Ii1I . OoO0O00 * oO0o
 if 16 - 16: ooOoO0o * IiII % I11i . I1Ii111 / IiII % iII111i
 if 27 - 27: IiII . i1IIi * OoOoOO00 % Ii1I / i1IIi
 if 3 - 3: IiII / ooOoO0o
 if 28 - 28: ooOoO0o + I1Ii111 - ooOoO0o . OoooooooOO
 if 97 - 97: OoO0O00 . I11i
 if 32 - 32: Oo0Ooo - II111iiii - i11iIiiIii % I1Ii111
def O0OoOoo00o ( device ) :
 iiiI11 = getoutput ( 'ip route | egrep "link src " | egrep {}' . format ( device ) )
 if ( iiiI11 == "" ) :
  iiiI11 = getoutput ( 'ip route | egrep "link  src " | egrep {}' . format ( device ) )
  if 91 - 91: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i + OOooOOo
  if ( iiiI11 == "" ) : return ( None )
  if 47 - 47: OoOoOO00 / Ii1I * OoooooooOO
 iiiI11 = iiiI11 . split ( ) [ - 1 ]
 return ( iiiI11 )
 if 9 - 9: I1IiiI - Ii1I % i1IIi % OoooooooOO
 if 3 - 3: iII111i + O0
 if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
 if 78 - 78: OoO0O00
 if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
 if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
 if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
def i1iIIIiI1I ( lisp_config ) :
 OOoO000O0OO = lisp_config . split ( "\n" )
 if 23 - 23: i11iIiiIii + I1IiiI
 oOo = i1 = oOOoo00O0O = None
 oOoOoO = False
 for ii1I in OOoO000O0OO :
  if ( oOoOoO == False ) :
   oOoOoO = ( ii1I . find ( "database-mapping" ) != - 1 )
   continue
   if 76 - 76: O0 / o0oOOo0O0Ooo . I1IiiI * Ii1I - OOooOOo
   if 76 - 76: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i % OOooOOo / OoooooooOO % oO0o
  if ( oOo == None and ii1I . find ( "instance-id = " ) != - 1 ) :
   oOo = ii1I . split ( " = " ) [ - 1 ]
   if 75 - 75: iII111i
  if ( ii1I . find ( "eid-prefix = " ) != - 1 ) :
   iiiI11 = ii1I . split ( " = " ) [ - 1 ]
   iiiI11 = iiiI11 . split ( "/" ) [ 0 ]
   if ( i1 == None and iiiI11 . count ( "." ) == 3 ) : i1 = iiiI11
   if ( oOOoo00O0O == None and iiiI11 . find ( ":" ) != - 1 ) : oOOoo00O0O = iiiI11
   if 97 - 97: i11iIiiIii
  if ( oOo != None and i1 != None and oOOoo00O0O != None ) : break
  if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 return ( oOo , i1 , oOOoo00O0O )
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
 if 64 - 64: OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
 if 74 - 74: iII111i * O0
 if 89 - 89: oO0o + Oo0Ooo
 if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
def III1ii1iII ( ) :
 oo0oooooO0 = len ( sys . argv )
 if ( oo0oooooO0 < 3 ) : return ( None , None , None , None )
 if 19 - 19: I11i + ooOoO0o
 ooo = sys . argv [ 1 ]
 if ( oo0oooooO0 == 2 ) : return ( ooo , None , None , None )
 if 18 - 18: o0oOOo0O0Ooo
 oOo = sys . argv [ 2 ]
 if ( oo0oooooO0 == 3 ) : return ( ooo , oOo , None , None )
 if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
 i1 = sys . argv [ 3 ]
 if ( oo0oooooO0 == 4 ) : return ( ooo , oOo , i1 , None )
 if 95 - 95: OoO0O00 % oO0o . O0
 oOOoo00O0O = sys . argv [ 4 ]
 return ( ooo , oOo , i1 , oOOoo00O0O )
 if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
 if 53 - 53: IiII + I1IiiI * oO0o
 if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
 if 60 - 60: I11i / I11i
 if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
 if 83 - 83: OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
def iii11 ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
ooo , oOo , i1 , oOOoo00O0O = III1ii1iII ( )
if ( ooo == None or oOo == None ) :
 print ( "Usage: python provision-lisp.py <device> <iid> [<ipv4-eid>] " + "[<ipv6-eid>]" )
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 exit ( 1 )
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
 if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
 if 16 - 16: I1IiiI * oO0o % IiII
 if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
i1I11i1iI = "./lisp.config"
if ( os . path . exists ( i1I11i1iI ) == False ) : i1I11i1iI += ".provision-xtr"
I1ii1Ii1 = open ( i1I11i1iI , "r" ) ; i1I11i1iI = I1ii1Ii1 . read ( ) ; I1ii1Ii1 . close ( )
if 15 - 15: II111iiii / iII111i . I1Ii111
if 68 - 68: OoO0O00
if 35 - 35: OoO0O00 - iII111i / Oo0Ooo / OoOoOO00
if 24 - 24: ooOoO0o - ooOoO0o / II111iiii - I1ii11iIi11i
if 69 - 69: oO0o . I1Ii111 + Ii1I / Oo0Ooo - oO0o
OO0O0OoOO0 = i1I11i1iI . find ( "<iid>" ) != - 1
if 10 - 10: OoooooooOO % iIii1I11I1II1
if ( OO0O0OoOO0 ) :
 if ( i1 == None ) : i1 , oOOoo00O0O = o0oO0 ( )
 O00o0O00 = O0OoOoo00o ( ooo )
 if 34 - 34: ooOoO0o
 print ( "Provisioning lisp.config file with EIDs [{}]{} & [{}]{}" . format ( oOo ,
 i1 , oOo , oOOoo00O0O ) )
 i1I11i1iI = i1I11i1iI . replace ( "<iid>" , oOo )
 i1I11i1iI = i1I11i1iI . replace ( "<v4-eid>" , i1 )
 i1I11i1iI = i1I11i1iI . replace ( "<v6-eid>" , oOOoo00O0O )
 i1I11i1iI = i1I11i1iI . replace ( "<v4-rloc>" , O00o0O00 )
 i1I11i1iI = i1I11i1iI . replace ( "<device>" , ooo )
 I1ii1Ii1 = open ( "./lisp.config" , "w" ) ; I1ii1Ii1 . write ( i1I11i1iI ) ; I1ii1Ii1 . close ( )
else :
 oOo , i1 , oOOoo00O0O = i1iIIIiI1I ( i1I11i1iI )
 if ( oOo == None ) :
  print ( "lisp.config file corrupt, remove it and rerun script" )
  exit ( 1 )
  if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 print ( "Using EIDs [{}]{} & [{}]{} found in lisp.config" . format ( oOo , i1 ,
 oOo , oOOoo00O0O ) )
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
if ( iii11 ( ) ) :
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 os . system ( "sudo ifconfig lo0 {}/32 alias" . format ( i1 ) )
 os . system ( "sudo route delete 240.0.0.0/8 > /dev/null" )
 os . system ( "sudo route add 240.0.0.0/8 {} > /dev/null" . format ( i1 ) )
 if 95 - 95: Ii1I
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 os . system ( "sudo ifconfig en0 inet6 {}/128 alias" . format ( oOOoo00O0O ) )
 os . system ( "sudo ndp -s fe80::1%en0 0:0:0:0:0:1" )
 os . system ( "sudo route delete -inet6 fe00::/16 > /dev/null" )
 os . system ( "sudo route add -inet6 fe00::/16 fe80::1%en0 > /dev/null" )
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 os . system ( "sudo sysctl -w net.inet.ip.forwarding=1 > /dev/null" )
 os . system ( "sudo sysctl -w net.inet6.ip6.forwarding=1 > /dev/null" )
 exit ( 0 )
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
 if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
 if 83 - 83: I11i / I1IiiI
 if 34 - 34: IiII
os . system ( "sudo ip addr add {}/32 dev lo 2> /dev/null" . format ( i1 ) )
os . system ( "sudo ip route del 240.0.0.0/8 2> /dev/null" )
os . system ( "sudo ip route add 240.0.0.0/8 dev lo src {}" . format ( i1 ) )
os . system ( "sudo ip route del 224.0.0.0/4 2> /dev/null" )
os . system ( "sudo ip route add 224.0.0.0/4 dev lo src {}" . format ( i1 ) )
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
os . system ( "sudo ifconfig {} mtu 1400" . format ( ooo ) )
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
os . system ( "sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null" )
os . system ( "sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null" )
if 87 - 87: i11iIiiIii
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
os . system ( "sudo ip addr add {}/128 dev {} 2> /dev/null" . format ( oOOoo00O0O , ooo ) )
os . system ( ( "sudo ip neighbor add fe80::1 lladdr 0:0:0:0:0:1 dev {} " + "2> /dev/null" ) . format ( ooo ) )
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
time . sleep ( 2 )
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
os . system ( "sudo ip route del fd00::/8 2> /dev/null" )
os . system ( "sudo ip route add fd00::/8 via fe80::1 dev {} src {}" . format ( ooo , oOOoo00O0O ) )
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
os . system ( "sudo ip route del fe00::/8 2> /dev/null" )
os . system ( "sudo ip route add fe00::/8 via fe80::1 dev {} src {}" . format ( ooo , oOOoo00O0O ) )
if 23 - 23: O0
if 85 - 85: Ii1I
os . system ( "sudo ip route del ff00::/8 2> /dev/null" )
os . system ( "sudo ip route add ff00::/8 via fe80::1 dev {} src {}" . format ( ooo , oOOoo00O0O ) )
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
exit ( 0 )
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
