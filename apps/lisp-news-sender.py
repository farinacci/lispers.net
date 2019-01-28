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
# lisp-news-sender.py
#
# This script will run and take information from the local system and send it
# as text on a multicast socket. Will use lisp-signal-free-multicast to get
# data to receivers.
#
# Usage: python lisp-news-sender.py <source> <group>
#

import sys
import socket
import datetime
import time
import urllib
import urllib2

#------------------------------------------------------------------------------

usage = "Usage: python lisp-news-sender.py <source> <group> [<delay>]"
source = ""
group = ""
port = ""
msocket = None

#------------------------------------------------------------------------------

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

def send_messages(messages):
    ts = datetime.datetime.now().strftime("%m/%d/%y %H:%M:%S.%f")
    for message in messages:
        print "Send message at {}:\n{}".format(ts, message), 

        #
        # Send the message.
        # 
        try: msocket.sendto(message, (group, port))
        except socket.error, e:
            print("socket.sendto() failed: {}".format(e))
        #endtry
        time.sleep(.25)
    #endfor
#enddef

def get_cool_message():
    ts = str(time.time()).split(".")[0]
    odd_even = int(ts) & 1
    message = "time is odd\n" if odd_even else "time is even\n"
    return([message])
#enddef

def get_headlines():
    try:
        u = urllib.urlopen("http://finance.yahoo.com/rss/topfinstories")
    except:
        try:
            u = urllib2.urlopen("http://finance.yahoo.com/rss/topfinstories")
        except:
            return(None)
        #endtry
    #endtry

    #endtry
    data = u.read()
    data = data[data.find("<item>")::]

    messages = []
    count = 0
    host = socket.gethostname()
    output = bold("Sent from multicast source '{}'\n".format(host))
    while (True):
        index = data.find("<title>")
        if (index == -1): break
        data = data[index+len("<title>")::]
        index = data.find("</title>")
        if (index == -1): break
        title = data[0:index]
        data = data[index::]

        index = data.find("<link>")
        if (index == -1): break
        data = data[index+len("<link>")::]
        index = data.find("</link>")
        if (index == -1): break
        link = data[0:index]
        data = data[index::]

        index = data.find("<pubDate>")
        if (index == -1): break
        data = data[index+len("<pubDate>")::]
        index = data.find("</pubDate>")
        if (index == -1): break
        pd = data[0:index]
        data = data[index::]

        output += "Headline: {}\n  Date: {}\n  URL: {}\n\n".format( \
            bold(title), pd, link)

        count += 1
        if (count % 3 == 0):
            messages.append(output)
            output = ""
        #endif
    #endwhile
    return(messages)
#enddef

#------------------------------------------------------------------------------

#
# Get command line parameters.
# 
if (len(sys.argv) < 3):
    print usage
    exit(1)
#endif

source = sys.argv[1]
group = sys.argv[2]
delay = int(sys.argv[3]) if (len(sys.argv) == 4) else 15

if (source.find(".") == -1 or group.find(".") == -1):
    print "Must supply IPv4 address in dotted decimal"
    exit(1)
#endif

port = group.split(".")
port = 0x800 + int(port[-2]) + int(port[-1])

#
# Open send UDP socket.
#
print "Open send socket ({} -> {}:{}) ... ".format(source, group, port),

try:
    msocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    msocket.bind((source, 0))
    print "succeeded"
except:
    print "failed"
    exit(1)
#endtry

#
# Start off looping and sending system status.
#
while (True):
    messages = get_headlines()
    if (messages != None): send_messages(messages)

    print "Delay {} seconds ... ".format(delay),
    sys.stdout.flush()
    time.sleep(delay)
    print ""

    messages = get_cool_message()
    send_messages(messages)

    print "Delay {} seconds ... ".format(delay),
    sys.stdout.flush()
    time.sleep(delay)
    print ""
#endwhile

msocket.close()
exit(0)

#------------------------------------------------------------------------------

