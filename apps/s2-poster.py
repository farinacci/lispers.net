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
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#endtry    
import time
import os
import sys
import json
import socket
import requests

#
# For temporary print()s.
#
debug = False

#------------------------------------------------------------------------------

#
# main
#
# Main program entry point.
#
def main():

    #
    # Get command line servers. Make sure they have port specified.
    #
    servers = get_command_line_servers()
    if (servers == []): return(False)

    #
    # Spin loop.
    #
    sleep_time = 10
    while (True):

        #
        # Check if there have been any new innovcations of loc8tr.py.
        #
        date = getoutput("date")
        print("{} scanning loc8tr directories ...".format(bold(date)), end=" ")

        what_to_post = get_directories()
        posted = getoutput("ls -1d loc8tr-* | wc -l")
        posted = int(posted) - len(what_to_post) if posted.isdigit() else 0
        print("found posted {}, new {}".format(posted, len(what_to_post)))

        #
        # For each new loc8tr directory created, process the json file within.
        #
        for loc8tr_dir in what_to_post:
            loc8tr_json = "{}/loc8tr.json".format(loc8tr_dir)
            print("Found {} to format and post".format(bold(loc8tr_dir)))

            #
            # Format for Selector.
            #
            selector_json = format_json(loc8tr_json)
            if (selector_json == {}): continue

            #
            # Send to each server configured on command line.
            #
            post_count = 0
            for server in servers:
                post_count += post_json(server, selector_json)
            #endfor

            #
            # If post worked for all servers, mark directory as posted and
            # don't do it another time.
            #
            if (post_count == len(servers)):
                os.system("touch {}/s2-posted".format(loc8tr_dir))
            #endif
        #endfor

        #
        # Sleep for a bit and check directories again.
        #
        time.sleep(sleep_time)
    #endwhile
    return(True)
#enddef

#
# get_command_line_servers
#
# Get list of server addresses in format <server-name-or-address>:<port>.
#
def get_command_line_servers():

    if (len(sys.argv) == 1):
        print("Usage: python s2-poster.py <svr-1>:<port> ... <svr-n>:<port>")
        return([])
    #endif
    servers = sys.argv[1::]

    for server in servers:
        if (server.find(":") == -1):
            print("Need :<port> for server {}".format(server))
            return([])
        #endif
        s = server.split(":")[1]
        if (s.isdigit() == False):
            print(":<port> must be decimal")
            return([])
        #endif
    #endfor
    return(servers)
#enddef

#
# get_directories
#
# Find all directories in current directory that start with "loc8tr-". And
# compare with what we have already stored. For the new ones we find, get
# the loc8tr.json file and format for S2 Selector Inc.        
#
def get_directories():
    cmd = "ls -1d loc8tr-*"
    dirs = getoutput(cmd)
    if (dirs.find("No such file or directory") != -1): return([])
    dirs = dirs.split("\n")

    what_to_post = []
    for l8r_dir in dirs:
        posted = "{}/s2-posted".format(l8r_dir)
        if (os.path.exists(posted)): continue
        what_to_post.append(l8r_dir)
    #endfor
    return(what_to_post)
#enddef    

#
# format_json
#
# Read json file and format it for Selector.
#
# loc8tr.py (input) format:
#
# {
#   "<rloc-1>" :
#     [ "<traceroute-data>", <ignore>, [<rtts>], [<hop-counts>], [<latency>],
#       <ignore> ], 
#   ...
#   "<rloc-n>" :
#     [ "<traceroute-data>", <ignore>, [<rtts>], [<hop-counts>], [<latency>],
#       <ignore> ], 
# }
#
#
# Selector (output) format:
#
# { "Reports" : [
#   { "reporter" : "<hostname-of-poster>", "report-data" : [
#     { "rloc" : "<rloc-1>", "rloc-data" :
#         { "traceroute" : <string>, "rtts" : ["<fp1>", "<fp2>", "<fp3>"],
#           "hop-counts" : ["<fhc1>/<rhc1>", "<fhc2>/<rhc2>", "<fhc3>/<rhc3>"]
#           "latencies" : ["<fl1>/<rl1>", "<fl2>/<rl2>", "<fl3>/<rl3>"]
#         }
#     },
#
#     ...
#
#     { "rloc" : "<rloc-n>", "rloc-data" :
#         { "traceroute" : <string>, "rtts" : [<fp1>, <fp2>, <fp3>],
#           "hop-counts" : ["<fhc1>/<rhc1>", "<fhc2>/<rhc2>", "<fhc3>/<rhc3>"]
#           "latencies" : ["<fl1>/<rl1>", "<fl2>/<rl2>", "<fl3>/<rl3>"]
#         }
#     }
#   ] }
# ] }
#
# Note that <rloc-1> ... <rloc-n> is in a unicast RLOC format of 1.1.1.1
# and a multicast RLOC format of 1.1.1.1%224.1.1.1 for example.
#
def format_json(loc8tr_json):
    try:
        f = open(loc8tr_json, "r"); buf = f.read(); f.close()
    except:
        print("Cannot open file {}".format(loc8tr_json))
        print("")
        return({})
    #endtry

    #endtr
    json_data = json.loads(buf)

    #
    # Selector data.
    #
    hostname = socket.gethostname() 
    s2_data = { "Reports" : [{ "reporter" : hostname, "report-data" : [] }] }

    #
    # Get lispers.net version number from file lisp-version.txt.
    #
    version = "?"
    if (os.path.exists("./lisp-version.txt")):
        version = getoutput("cat ./lisp-version.txt")
    #endif
    s2_data["Label"] = "lispers.net version {}".format(version)

    #
    # Traverse through each key in the loc8tor.py dictionary array.
    #
    for rloc in json_data:
        entry = { "rloc" : rloc, "rloc-data" : {} }
        entry["rloc-data"]["traceroute"] = json_data[rloc][0]
        entry["rloc-data"]["rtts"] = json_data[rloc][2]
        entry["rloc-data"]["hop-counts"] = json_data[rloc][3]
        entry["rloc-data"]["latencies"] = json_data[rloc][4]
        s2_data["Reports"][0]["report-data"].append(entry)
    #endfor

    if (debug):
        print("Selector JSON:")
        print(s2_data)
    #endif
    return(s2_data)
#enddef

#
# post_json
#
# Send post formatted json data to server.
#
# Selector's location on the server is "col/api/netmon/lisp". Typically to port
# 8000.
#
def post_json(server, selector_json):
    url = "http://{}/col/api/netmon/lisp".format(server)
    data = json.dumps(selector_json)

    print("Post to {} ...".format(url), end=" ")

    try:
        r = requests.post(url, data=data, timeout=5)
        print("{}, return-code: {}".format(green("succeeded"), r.status_code))
        return(1)
    except Exception as e:
        print("{}, error response:\n{}\n".format(red("failed"), e.message))
    #endtry
    return(0)
#enddef

#
# bold
#
# Return boldface string.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# red
#
# Return red colored string.
#
def red(string):
    return("\033[91m" + string + "\033[0m")
#enddef

#
# green
#
# Return green colored string.
#
def green(string):
    return("\033[92m" + string + "\033[0m")
#enddef

#------------------------------------------------------------------------------

#
# Main entry point.
#
if (__name__=="__main__"):
   status = main()
   exit(status)
#endif

#------------------------------------------------------------------------------

