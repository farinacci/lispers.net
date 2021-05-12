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
 for oOoOoO in OOoO000O0OO :
  if ( oOo == None and oOoOoO . find ( "instance-id = " ) != - 1 ) :
   oOo = oOoOoO . split ( " = " ) [ - 1 ]
   if 6 - 6: I1IiiI / Oo0Ooo % Ii1I
  if ( oOoOoO . find ( "eid-prefix = " ) != - 1 ) :
   iiiI11 = oOoOoO . split ( " = " ) [ - 1 ]
   iiiI11 = iiiI11 . split ( "/" ) [ 0 ]
   if ( i1 == None and iiiI11 . count ( "." ) == 3 ) : i1 = iiiI11
   if ( oOOoo00O0O == None and iiiI11 . find ( ":" ) != - 1 ) : oOOoo00O0O = iiiI11
   if 84 - 84: i11iIiiIii . o0oOOo0O0Ooo
  if ( oOo != None and i1 != None and oOOoo00O0O != None ) : break
  if 100 - 100: Ii1I - Ii1I - I1Ii111
 return ( oOo , i1 , oOOoo00O0O )
 if 20 - 20: OoooooooOO
 if 13 - 13: i1IIi - Ii1I % oO0o / iIii1I11I1II1 % iII111i
 if 97 - 97: i11iIiiIii
 if 32 - 32: Oo0Ooo * O0 % oO0o % Ii1I . IiII
 if 61 - 61: ooOoO0o
 if 79 - 79: Oo0Ooo + I1IiiI - iII111i
 if 83 - 83: ooOoO0o
def OO00o0OOO0 ( ) :
 Ii1iIIIi1ii = len ( sys . argv )
 if ( Ii1iIIIi1ii < 3 ) : return ( None , None , None , None )
 if 80 - 80: I11i * i11iIiiIii / I1Ii111
 I11II1i = sys . argv [ 1 ]
 if ( Ii1iIIIi1ii == 2 ) : return ( I11II1i , None , None , None )
 if 23 - 23: I1ii11iIi11i / o0oOOo0O0Ooo + I11i + I11i / II111iiii
 oOo = sys . argv [ 2 ]
 if ( Ii1iIIIi1ii == 3 ) : return ( I11II1i , oOo , None , None )
 if 26 - 26: OoooooooOO
 i1 = sys . argv [ 3 ]
 if ( Ii1iIIIi1ii == 4 ) : return ( I11II1i , oOo , i1 , None )
 if 12 - 12: OoooooooOO % OoOoOO00 / ooOoO0o % o0oOOo0O0Ooo
 oOOoo00O0O = sys . argv [ 4 ]
 return ( I11II1i , oOo , i1 , oOOoo00O0O )
 if 29 - 29: OoooooooOO
 if 23 - 23: o0oOOo0O0Ooo . II111iiii
 if 98 - 98: iIii1I11I1II1 % OoOoOO00 * I1ii11iIi11i * OoOoOO00
 if 45 - 45: I1Ii111 . OoOoOO00
 if 83 - 83: oO0o . iIii1I11I1II1 . I1ii11iIi11i
 if 31 - 31: Ii1I . Ii1I - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o * I1IiiI
 if 63 - 63: I1Ii111 % i1IIi / OoooooooOO - OoooooooOO
def iIii11I ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 69 - 69: oO0o % I1Ii111 - o0oOOo0O0Ooo + I1Ii111 - O0 % OoooooooOO
 if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
 if 4 - 4: II111iiii / ooOoO0o . iII111i
 if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
 if 50 - 50: I1IiiI
 if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
 if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
I11II1i , oOo , i1 , oOOoo00O0O = OO00o0OOO0 ( )
if ( I11II1i == None or oOo == None ) :
 print ( "Usage: python provision-lisp.py <device> <iid> [<ipv4-eid>] " + "[<ipv6-eid>]" )
 if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
 exit ( 1 )
 if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
 if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
 if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
 if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
 if 58 - 58: i11iIiiIii % I11i
 if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
oO0OOoO0 = "./lisp.config"
if ( os . path . exists ( oO0OOoO0 ) == False ) : oO0OOoO0 += ".provision-xtr"
I111Ii111 = open ( oO0OOoO0 , "r" ) ; oO0OOoO0 = I111Ii111 . read ( ) ; I111Ii111 . close ( )
if 4 - 4: oO0o
if 93 - 93: OoO0O00 % oO0o . OoO0O00 * I1Ii111 % Ii1I . II111iiii
if 38 - 38: o0oOOo0O0Ooo
if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
if 26 - 26: iII111i
OOO = oO0OOoO0 . find ( "<iid>" ) != - 1
if 59 - 59: II111iiii + OoooooooOO * OoOoOO00 + i1IIi
if ( OOO ) :
 if ( i1 == None ) : i1 , oOOoo00O0O = o0oO0 ( )
 Oo0OoO00oOO0o = O0OoOoo00o ( I11II1i )
 if 80 - 80: oO0o + OOooOOo - OOooOOo % iII111i
 print ( "Provisioning lisp.config file with EIDs [{}]{} & [{}]{}" . format ( oOo ,
 i1 , oOo , oOOoo00O0O ) )
 oO0OOoO0 = oO0OOoO0 . replace ( "<iid>" , oOo )
 oO0OOoO0 = oO0OOoO0 . replace ( "<v4-eid>" , i1 )
 oO0OOoO0 = oO0OOoO0 . replace ( "<v6-eid>" , oOOoo00O0O )
 oO0OOoO0 = oO0OOoO0 . replace ( "<v4-rloc>" , Oo0OoO00oOO0o )
 oO0OOoO0 = oO0OOoO0 . replace ( "<device>" , I11II1i )
 I111Ii111 = open ( "./lisp.config" , "w" ) ; I111Ii111 . write ( oO0OOoO0 ) ; I111Ii111 . close ( )
else :
 oOo , i1 , oOOoo00O0O = i1iIIIiI1I ( oO0OOoO0 )
 if ( oOo == None ) :
  print ( "lisp.config file corrupt, remove it and rerun script" )
  exit ( 1 )
  if 63 - 63: I1IiiI - I1ii11iIi11i + O0 % I11i / iIii1I11I1II1 / o0oOOo0O0Ooo
 print ( "Using EIDs [{}]{} & [{}]{} found in lisp.config" . format ( oOo , i1 ,
 oOo , oOOoo00O0O ) )
 if 98 - 98: iII111i * iII111i / iII111i + I11i
 if 34 - 34: ooOoO0o
 if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
 if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
 if 92 - 92: iII111i . I1Ii111
 if 31 - 31: I1Ii111 . OoOoOO00 / O0
 if 89 - 89: OoOoOO00
 if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
if ( iIii11I ( ) ) :
 if 4 - 4: ooOoO0o + O0 * OOooOOo
 if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
 if 25 - 25: I1ii11iIi11i
 if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
 os . system ( "sudo ifconfig lo0 {}/32 alias" . format ( i1 ) )
 os . system ( "sudo route delete 240.0.0.0/8 > /dev/null" )
 os . system ( "sudo route add 240.0.0.0/8 {} > /dev/null" . format ( i1 ) )
 if 13 - 13: OOooOOo / i11iIiiIii
 if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
 if 52 - 52: o0oOOo0O0Ooo
 if 95 - 95: Ii1I
 os . system ( "sudo ifconfig en0 inet6 {}/128 alias" . format ( oOOoo00O0O ) )
 os . system ( "sudo ndp -s fe80::1%en0 0:0:0:0:0:1" )
 os . system ( "sudo route delete -inet6 fe00::/16 > /dev/null" )
 os . system ( "sudo route add -inet6 fe00::/16 fe80::1%en0 > /dev/null" )
 if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
 if 91 - 91: O0
 if 61 - 61: II111iiii
 if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
 os . system ( "sudo sysctl -w net.inet.ip.forwarding=1 > /dev/null" )
 os . system ( "sudo sysctl -w net.inet6.ip6.forwarding=1 > /dev/null" )
 exit ( 0 )
 if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
 if 42 - 42: OoO0O00
 if 67 - 67: I1Ii111 . iII111i . O0
 if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
 if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
os . system ( "sudo ip addr add {}/32 dev lo 2> /dev/null" . format ( i1 ) )
os . system ( "sudo ip route del 240.0.0.0/8 2> /dev/null" )
os . system ( "sudo ip route add 240.0.0.0/8 dev lo src {}" . format ( i1 ) )
os . system ( "sudo ip route del 224.0.0.0/4 2> /dev/null" )
os . system ( "sudo ip route add 224.0.0.0/4 dev lo src {}" . format ( i1 ) )
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
os . system ( "sudo ifconfig {} mtu 1400" . format ( I11II1i ) )
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
os . system ( "sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null" )
os . system ( "sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null" )
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
os . system ( "sudo ip addr add {}/128 dev {} 2> /dev/null" . format ( oOOoo00O0O , I11II1i ) )
os . system ( ( "sudo ip neighbor add fe80::1 lladdr 0:0:0:0:0:1 dev {} " + "2> /dev/null" ) . format ( I11II1i ) )
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
time . sleep ( 2 )
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
os . system ( "sudo ip route del fd00::/8 2> /dev/null" )
os . system ( "sudo ip route add fd00::/8 via fe80::1 dev {} src {}" . format ( I11II1i , oOOoo00O0O ) )
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
os . system ( "sudo ip route del fe00::/8 2> /dev/null" )
os . system ( "sudo ip route add fe00::/8 via fe80::1 dev {} src {}" . format ( I11II1i , oOOoo00O0O ) )
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
os . system ( "sudo ip route del ff00::/8 2> /dev/null" )
os . system ( "sudo ip route add ff00::/8 via fe80::1 dev {} src {}" . format ( I11II1i , oOOoo00O0O ) )
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
exit ( 0 )
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
