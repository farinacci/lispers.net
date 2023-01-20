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
# lispconfig.py
#
# This file contains all configuration support for the LISP subsystem. That
# includes lisp.config file processing and the RESTful interface via the
# bottle module.
# 
# -----------------------------------------------------------------------------
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import str
from builtins import range
from past.utils import old_div
import lisp
import os
import time
import socket
import bottle
import hmac
import hashlib
import select
import copy
import math
from json import dumps as json_dumps
from subprocess import getoutput

#------------------------------------------------------------------------------

LISP_USER_TIMEOUT = 1800  # Let users stay in web interface for 1/2 hour

#
# This array decides where the command goes to get processed.
#
lisp_commands = {
    "lisp user-account"             : ["lisp-core"], 
    "lisp enable"                   : ["lisp-core"], 
    "lisp debug"                    : ["lisp-core"], 
    "lisp xtr-parameters"           : ["lisp-itr", "lisp-rtr", "lisp-etr"],
    "lisp interface"                : ["lisp-itr", "lisp-etr", "lisp-rtr"], 
    "lisp rtr-list"                 : ["lisp-core"],
    "lisp map-resolver"             : ["lisp-itr", "lisp-rtr"],
    "lisp map-cache"                : ["lisp-itr", "lisp-rtr"],
    "lisp itr-map-cache"            : ["lisp-itr"],
    "lisp rtr-map-cache"            : ["lisp-rtr"],
    "lisp map-server"               : ["lisp-itr", "lisp-etr"], 
    "lisp database-mapping"         : ["lisp-itr", "lisp-etr", "lisp-rtr"],
    "lisp group-mapping"            : ["lisp-etr"],
    "lisp glean-mapping"            : ["lisp-rtr"],
    "lisp explicit-locator-path"    : ["lisp-itr", "lisp-rtr", "lisp-etr",
                                       "lisp-ms"],
    "lisp replication-list-entry"   : ["lisp-itr", "lisp-rtr", "lisp-etr",
                                       "lisp-ms"],
    "lisp geo-coordinates"          : ["lisp-itr", "lisp-etr", "lisp-ms"],
    "lisp json"                     : ["lisp-itr", "lisp-etr", "lisp-rtr",
                                       "lisp-ms"],
    "lisp ddt-root"                 : ["lisp-mr"],
    "lisp referral-cache"           : ["lisp-mr"],
    "lisp site"                     : ["lisp-ms"],
    "lisp eid-crypto-hash"          : ["lisp-ms"],
    "lisp encryption-keys"          : ["lisp-ms"],
    "lisp map-server-peer"          : ["lisp-ms"],
    "lisp ms-authoritative-prefix"  : ["lisp-ms"],
    "lisp ddt-authoritative-prefix" : ["lisp-ddt"],
    "lisp delegation"               : ["lisp-ddt"],
    "lisp policy"                   : ["lisp-ms"],
    "show itr-map-cache"            : ["lisp-itr"],
    "show itr-rloc-probing"         : ["lisp-itr"],
    "show rtr-map-cache"            : ["lisp-rtr"],
    "show rtr-map-cache-dns"        : ["lisp-rtr"],
    "show rtr-rloc-probing"         : ["lisp-rtr"],
    "show database-mapping"         : ["lisp-etr"],
    "show referral-cache"           : ["lisp-mr"],
    "show delegations"              : ["lisp-ddt"],
    "show site"                     : ["lisp-ms"], 
    "show itr-dynamic-eid"          : ["lisp-itr"],
    "show etr-dynamic-eid"          : ["lisp-etr"],
    "show itr-keys"                 : ["lisp-itr"],
    "show etr-keys"                 : ["lisp-etr"],
    "show rtr-keys"                 : ["lisp-rtr"]
}

lisp_core_commands = {
    "lisp enable" : ["", {
        "itr" : [False, "yes", "no"], 
        "etr" : [False, "yes", "no"], 
        "rtr" : [False, "yes", "no"],
        "map-resolver" : [False, "yes", "no"], 
        "map-server" : [False, "yes", "no"], 
        "ddt-node" : [False, "yes", "no"] } ],

    "lisp debug" : ["", {
        "core" : [False, "yes", "no"], 
        "itr" : [False, "yes", "no"], 
        "etr" : [False, "yes", "no"], 
        "rtr" : [False, "yes", "no"],
        "map-resolver" : [False, "yes", "no"], 
        "map-server" : [False, "yes", "no"], 
        "ddt-node" : [False, "yes", "no"] } ],

    "lisp user-account" : ["", {
        "username" : [False],
        "password" : [False], 
        "super-user" : [False, "yes", "no"] } ],

    "lisp rtr-list" : ["", {
        "address" : [True] }]
}

#------------------------------------------------------------------------------

#
# lisp_banner_top
#
# This is the banner that goes on every web page.
#
def lisp_banner_top(no_hover):
    html_title = socket.gethostname()
    hostname = lisp.lisp_print_cour(html_title)
    if (no_hover == False):
        hover = getoutput("ifconfig")
        hostname = lisp.lisp_span(hostname, hover)
    #endif

    hostname = '''
        <a href="/lisp/traceback" style="text-decoration: none">{}</a>
    '''.format(hostname)

    banner = '''
        <head><title>{}</title></head>
        <body bgcolor="gray">
        <div style="margin:20px;background-color:#F5F5F5;padding:15px;
        border-radius:20px;border:5px solid #666666;">
        <table width="100%"><tr>
          <td align="left" width="50%">
            <a href="/lisp" style="text-decoration: none"><font size="8"><i>
            {}<font color="black">.</font>{}</i></font></a><br>
            <font size="4"><i>{}</i></font>
          </td>
          <td align="right" valign="bottom" width="50%">{}</td>
        </tr></table>
        <hr style="border: none; border-bottom: 1px solid gray;">
    '''.format(html_title, lisp.green("lispers", True), lisp.red("net", True), 
        lisp.bold("Scalable Open Overlay Networking", True), hostname)

    return(banner)
#enddef

#
# lisp_banner_bottom
#
# This is the banner that goes on every web page.
#
def lisp_banner_bottom():
    hostname = socket.gethostname()
    date = getoutput("date")
    uptime = lisp.lisp_print_elapsed(lisp.lisp_uptime)
    py = " (py2)" if lisp.lisp_is_python2() else " (py3)"

    banner = '''<br><hr style="border: none; border-bottom: 1px solid gray;">
        <i><font size="2">{} - Uptime 
        {}, Version {}<br>Copyright 2013-2019 - all rights reserved by
        <a href="http://www.lispers.net"><b>lispers.net</b></a> LLC<br>
        Features/Bugs go to <a href=
"mailto:support@lispers.net?subject=lispers.net v{} bug-report from '{}'">
        support@lispers.net</a></i></font><br><br>
    '''.format(date, uptime, lisp.bold(lisp.lisp_version + py, True),
        lisp.lisp_version + py, hostname)

    return(banner)
#enddef

#
# lisp_show_wrapper
#
# All show command output will be wrapped with a web header and footer.
#
def lisp_show_wrapper(output):
    return(lisp_banner_top(False) + output + lisp_banner_bottom())
#enddef

#
# lisp_table_header
#
# Print a consistent table header row for all show commands.
#
def lisp_table_header(title, *args):
    output = '''
        <font face="Sans-Serif"><h3><i>{}</i></h3></font>
        <table border="1" cellspacing="3x" cellpadding="5x">
        <tr>
    '''.format(title)

    for arg in args:
        output += '''
            <td><font face="Sans-Serif"><b>{}</b></font></td>
        '''.format(arg)
    #endfor
    output += "</tr>"
    return(output)
#enddef

#
# lisp_table_row
#
# Print a consistent table row for all show commands.
#
def lisp_table_row(*args):
    output = "<tr>"
    for arg in args:
        output += '''
            <td><font face="Sans-Serif">{}</font></td>
        '''.format(arg)
    #endfor
    output += "</tr>"
    return(output)
#enddef

#
# lisp_table_footer
#
# Print a consistent table footer for all show commands.
#
def lisp_table_footer():
    return("</table>")
#enddef

#
# lisp_write_last_changed_date
#
# Put timestamp in header line of file lisp.config.
#
def lisp_write_last_changed_date(new, line):
    ts = getoutput("date")
    l = line.find(":")
    line = line[0:l+1] + " " + ts + "\n"
    new.write(line)
    return
#enddef

#
# lisp_comment
#
# Return True if first character of a line from the configuration file line 
# has "#".
#
def lisp_comment(line):
    return(True if line[0] == "#" else False)
#enddef

#
# lisp_begin_clause
#
# Return true if "{" is found on line.
#
def lisp_begin_clause(line):
    return(False if line.find("{") == -1 else True)
#enddef
#
# lisp_end_clause
#
# Return true if "}" is found on line.
#
def lisp_end_clause(line):
    return(False if line.find("}") == -1 else True)
#enddef

#
# lisp_end_file
#
# Return True if line is last line from the configuration file of editable 
# part of file.
#
def lisp_end_file(line):
    return(True if (line[0:10] == "#---------" and line[-2] == "#") else False)
#enddef

#
# lisp_write_error
#
# Line has syntax error. Flag and write comment lines for rest of clause. Go
# see lisp_syntax_check() for why the line starts with "%".
#
def lisp_write_error(line, error):
    new_line = "%>>> " + line + " <<< " + error + "\n"
    return(new_line)
#enddef

#
# lisp_write_line
#
# Write line to a new clause. We are commenting it, assuming there may be
# an error in the clause. If there is not, we will line.replace("#", " ").
#
def lisp_write_line(line):
    return("#" + line + "\n")
#enddef

#
# lisp_not_supported
#
# Come here when a command is not yet implemented.
#
def lisp_not_supported():
    return(lisp_show_wrapper(""))
#enddef

#
# lisp_hash_password
#
# Take a plaintext password that came from the lisp.config file and hash
# it to be written out to the file. So we don't store plaintext passwords.
#
def lisp_hash_password(plaintext):
    p = plaintext.encode()
    ciphertext = hmac.new(b"lispers.net", p, hashlib.sha1).hexdigest()
    return(ciphertext)
#enddef

#
# lisp_validate_input_address_string
#
# Validate an input address string from a user can be of the following forms:
#
#     <address>
#     [<iid>]<address>
#     <address>-><group>
#     [<iid>]<address>->[<iid>]<group>
#
# An <address> can be a string when it is encoded by user as '<address>'.
#
def lisp_validate_input_address_string(input_str):
    eid_str = input_str
    group_str = None
    if (input_str.find("->") != -1):
        sg = input_str.split("->")
        eid_str = sg[0]
        group_str = sg[1]
    #endif

    index = lisp_valid_iid_format(eid_str)
    if (index == -1): return(False)
    if (index == len(eid_str)): return(True)

    addr_str = eid_str[index::]

    if (addr_str.find("/") == -1):
        good = lisp.lisp_valid_address_format("address", addr_str)
    else:
        good = lisp_valid_prefix_format(addr_str)
    #endif
    if (good == False): return(False)

    #
    # No "->" so no group, return.
    #
    if (group_str == None): return(True)

    index = lisp_valid_iid_format(group_str)
    if (index == -1): return(False)

    addr_str = group_str[index::]
    if (group_str.find("/") == -1):
        good = lisp.lisp_valid_address_format("address", addr_str)
    else:
        good = lisp_valid_prefix_format(addr_str)
    #endif
    if (good == False): return(False)
    return(True)
#enddef

#
# lisp_valid_iid_format
#
# Check the string to make sure we have a "[<iid>]" where <iid> is a decimal
# number from 0 to 0xffffffff. If brackets are not found, return 0. No
# "[<iid>]" is a valid one. If a valid string is found return index after
# the "]" character.
#
def lisp_valid_iid_format(iid_str):
    start = iid_str.find("[")
    if (start == -1): return(0)
    if (start != 0): return(-1)

    end  = iid_str.find("]")
    if (end == -1): return(-1)

    if ((start+1) == (end-1)):
        value = iid_str[start+1]
    else:
        value = iid_str[start+1:end-1]
    #endif
    if (value.isdigit() == False): return(-1)
    return(end + 1)
#enddef

#
# lisp_valid_prefix_format
#
# Check to see if the string is a valid prefix. We are validating IPv4 and IPv6
# prefixes to have a / and that the address format is correct. Allow
# Distinguished-Names to not require a slash.
#
def lisp_valid_prefix_format(prefix):
    if (prefix.find("'") == -1 and prefix.find("/") == -1): return(False)

    addr = prefix.split("/")
    if (len(addr) != 2): 
        if (prefix.find("'") == -1): return(False)
        addr = [prefix, len(prefix)]
    #endif
    return(lisp.lisp_valid_address_format("address", addr[0]))
#enddef

#
# lisp_validate_range
#
# Return -1 for mask-len if the range is not in a power-of-2 block. If value
# is "*", then the iid is 0 and the mask-length is 0. This is the ultimate
# default.
#
def lisp_validate_range(value):
    if (value == "*"): return([0, 0])

    value = value.split("-")
    lower = int(value[0])
    upper = int(value[1])
    if (lower > upper): return([0, -1])

    #
    # Range must be a power-of-2. Therefore, the upper must be 2**n - 1. Add
    # 1 and search for the bit. That will produce the mask length.
    #
    block = upper - lower + 1
    mask_len = str(math.log(block, 2))
    mask_len = mask_len.split(".")
    if (len(mask_len) == 1 or int(mask_len[1]) != 0): return([0, 0])

    mask_len = 32 - int(mask_len[0])
    return([lower, mask_len])
#enddef

#
# lisp_setup_kv_pairs
#
# For each sub-clause command; "prefix", "rloc", "delegate", "referral",
# "elp-node", "rle-node", "peer", "allowed-prefix", and "allowed-rloc",
# create an array with number of elements equal to the number of occurences
# of each sub-clause command.
#
# This allows to not supply every sub-command for a sub-clause. For example:
#
#    lisp map-cache {
#        prefix {
#            eid-prefix = 10.0.0.0/8
#        }
#        prefix {
#            instance-id = 13
#            eid-prefix = 11.0.0.0/8
#        }
#        rloc {
#            address = 1.1.1.1
#            geo-name = san-jose
#            priority = 1
#        }
#        rloc {
#            elp-name = via-att
#            priority = 1
#        }
#    }
#
def lisp_setup_kv_pairs(clause):
    kv_pairs = {}

    #
    # Remove comment lines so if keywords appear in comment lines they are
    # not counted.
    #
    index = clause.find("#")
    while (index != -1):
        end = clause[index::].find("\n")
        if (end == -1): end = 0
        clause = clause[:index] + clause[index+end+1::]
        index = clause.find("#")
    #endwhile

    count = clause.count(" prefix {")
    if (count != 0):
        kv_pairs["instance-id"] = [""] * count
        kv_pairs["secondary-instance-id"] = [""] * count
        kv_pairs["eid-prefix"] = [""] * count
        kv_pairs["group-prefix"] = [""] * count
        kv_pairs["mr-name"] = [""] * count
        kv_pairs["ms-name"] = [""] * count
        kv_pairs["dynamic-eid"] = [""] * count
        kv_pairs["signature-eid"] = [""] * count
        kv_pairs["register-ttl"] = [""] * count
        kv_pairs["send-map-request"] = [""] * count
        kv_pairs["subscribe-request"] = [""] * count
    #endif

    count = clause.count(" rloc {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["interface"] = [""] * count
        kv_pairs["rloc-record-name"] = [""] * count
        kv_pairs["elp-name"] = [""] * count
        kv_pairs["geo-name"] = [""] * count
        kv_pairs["rle-name"] = [""] * count
        kv_pairs["json-name"] = [""] * count
        kv_pairs["priority"] = [""] * count
        kv_pairs["weight"] = [""] * count
    #endif

    count = clause.count(" match {")
    if (count != 0):
        kv_pairs["instance-id"] = [""] * count
        kv_pairs["source-eid"] = [""] * count
        kv_pairs["destination-eid"] = [""] * count
        kv_pairs["source-rloc"] = [""] * count
        kv_pairs["destination-rloc"] = [""] * count
        kv_pairs["rloc-record-name"] = [""] * count
        kv_pairs["elp-name"] = [""] * count
        kv_pairs["geo-name"] = [""] * count
        kv_pairs["rle-name"] = [""] * count
        kv_pairs["json-name"] = [""] * count
        kv_pairs["datetime-range"] = [""] * count
    #endif

    count = clause.count(" elp-node {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["strict"] = [""] * count
        kv_pairs["probe"] = [""] * count
        kv_pairs["eid"] = [""] * count
    #endif

    count = clause.count(" rle-node {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["level"] = [""] * count
    #endif

    count = clause.count(" referral {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["priority"] = [""] * count
        kv_pairs["weight"] = [""] * count
    #endif

    count = clause.count(" delegate {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["node-type"] = [""] * count
        kv_pairs["priority"] = [""] * count
        kv_pairs["weight"] = [""] * count
        kv_pairs["public-key"] = [""] * count
    #endif

    count = clause.count(" allowed-rloc {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["priority"] = [""] * count
        kv_pairs["weight"] = [""] * count
    #endif

    count = clause.count(" allowed-prefix {")
    if (count != 0):
        kv_pairs["instance-id"] = [""] * count
        kv_pairs["eid-prefix"] = [""] * count
        kv_pairs["group-prefix"] = [""] * count
        kv_pairs["accept-more-specifics"] = [""] * count
        kv_pairs["force-proxy-reply"] = [""] * count
        kv_pairs["force-nat-proxy-reply"] = [""] * count
        kv_pairs["force-ttl"] = [""] * count
        kv_pairs["pitr-proxy-reply-drop"] = [""] * count
        kv_pairs["proxy-reply-action"] = [""] * count
        kv_pairs["require-signature"] = [""] * count
        kv_pairs["encrypt-json"] = [""] * count
        kv_pairs["echo-nonce-capable"] = [""] * count
        kv_pairs["policy-name"] = [""] * count
    #endif

    count = clause.count(" peer {")
    if (count != 0):
        kv_pairs["address"] = [""] * count
        kv_pairs["priority"] = [""] * count
        kv_pairs["weight"] = [""] * count
    #endif

    #
    # There is only one instance of the "lisp xtr-parameters" command.
    #
    count = clause.count("data-plane-security =")
    if (count != 0):
        kv_pairs["data-plane-security"] = [""] * count
    #endif
    count = clause.count("data-plane-logging =")
    if (count != 0):
        kv_pairs["data-plane-logging"] = [""] * count
    #endif
    count = clause.count("frame-logging =")
    if (count != 0):
        kv_pairs["frame-logging"] = [""] * count
    #endif
    count = clause.count("flow-logging =")
    if (count != 0):
        kv_pairs["flow-logging"] = [""] * count
    #endif
    count = clause.count("nat-traversal =")
    if (count != 0):
        kv_pairs["nat-traversal"] = [""] * count
    #endif
    count = clause.count("decentralized-nat =")
    if (count != 0):
        kv_pairs["decentralized-nat"] = [""] * count
    #endif
    count = clause.count("rloc-probing =")
    if (count != 0):
        kv_pairs["rloc-probing"] = [""] * count
    #endif
    count = clause.count("nonce-echoing =")
    if (count != 0):
        kv_pairs["nonce-echoing"] = [""] * count
    #endif
    count = clause.count("checkpoint-map-cache =")
    if (count != 0):
        kv_pairs["checkpoint-map-cache"] = [""] * count
    #endif
    count = clause.count("ipc-data-plane =")
    if (count != 0):
        kv_pairs["ipc-data-plane"] = [""] * count
    #endif
    count = clause.count("program-hardware =")
    if (count != 0):
        kv_pairs["program-hardware"] = [""] * count
    #endif
    count = clause.count("decentralized-push-xtr =")
    if (count != 0):
        kv_pairs["decentralized-push-xtr"] = [""] * count
    #endif
    count = clause.count("decentralized-pull-xtr-modulus =")
    if (count != 0):
        kv_pairs["decentralized-pull-xtr-modulus"] = [""] * count
    #endif
    count = clause.count("decentralized-pull-xtr-dns-suffix =")
    if (count != 0):
        kv_pairs["decentralized-pull-xtr-dns-suffix"] = [""] * count
    #endif
    count = clause.count("register-reachable-rtrs =")
    if (count != 0):
        kv_pairs["register-reachable-rtrs"] = [""] * count
    #endif

    #
    # There is a special case here where there are no sub-clauses but
    # "address" appears multiple times in a command clause. Let's allocate
    # enough array space to store all of them. This is referring to the
    # "lisp map-server" command.
    #
    if (kv_pairs == {}):
        count = max(clause.count("address ="), clause.count("dns-name ="))
        if (count != 0): kv_pairs["address"] = [""] * count
        if (count != 0): kv_pairs["dns-name"] = [""] * count
        count = clause.count("mr-name =")
        if (count != 0): kv_pairs["mr-name"] = [""] * count
        count = clause.count("ms-name =")
        if (count != 0): kv_pairs["ms-name"] = [""] * count
    #endif
    return(kv_pairs)
#enddef

#
# lisp_clause_syntax_error
#
# If lisp_syntax_check() built an array for the command 'parm', then it was
# in the required sub-command clause. Otherwise, we return an error and
# display a message to the log.
#
def lisp_clause_syntax_error(kv_pair, parm, clause):
    is_array = (parm in kv_pair and type(kv_pair[parm]) == list)
    if (is_array): return(False)

    err_str = lisp.bold("Syntax error", False)
    lisp.fprint("{}, '{}' not in '{}' clause".format(err_str, parm, clause))
    return(True)
#enddef

#
# lisp_syntax_check
#
# Return null string if the syntax checking was clean. Otherwise, return
# the command clause with ">>>".
#
def lisp_syntax_check(kv_pairs, clause):

    #
    # First look for number of subclauses of the same type. Assume the
    # syntax is correct.
    #
    new_kv_pairs = lisp_setup_kv_pairs(clause)

    clause = clause.split("\n")
    new_clause = ""
    open_brace = 0
    error = False
    index = 0
    last_subclause = ""

    for line in clause:
        if (len(line) == 0): continue
        if (line == ""): continue
        if (lisp_comment(line)):
            line = line.replace("#", "%")
            new_clause += lisp_write_line(line)
            continue
        #endif

        json = line.find("json-string") != -1

        if (lisp_begin_clause(line) and json == False):
            new_clause += lisp_write_line(line)
            open_brace += 1
            if (last_subclause == line):
                index += 1
            else:
                index = 0
                last_subclause = line
            #endif
            continue
        #endif
        if (lisp_end_clause(line) and json == False):
            open_brace -= 1
            if (open_brace == 0): 
                new_clause += lisp_write_line(line)
                break
             #endif
            if (error): 
                new_clause += "%" + line + "\n"
            else: 
                new_clause += lisp_write_line(line)
            #endif
            continue
        #endif
        if (error):
            new_clause += "%" + line + "\n"
            continue
        #endif

        #
        # An equal sign must be on the subcommand line. Allow equal sign to be
        # in data field.
        #
        cmd = line.split("=", 1)

        if (len(cmd) == 1):
            new_clause += lisp_write_error(line, "no equal sign")
            error = True
            continue
        #endif

        kw = cmd[0].replace(" ", "")

        #
        # For values we allow whitespace in. Allow distinguished-names to
        # have spaces in it as well as json-strings.
        #
        if (kw == "description" or kw == "geo-tag"):
            value = cmd[1]
        elif (kw == "json-string"):
            value = cmd[1][1::]
        else:
            if (kw == "eid-prefix" and cmd[1].count("'") == 2):
                value = cmd[1][1::]
            elif (kw == "instance-id"):
                value = cmd[1][1::]
            else:
                value = cmd[1].replace(" ", "")
            #endif
        #endif

        kw = kw.replace("\t", "")
        value = value.replace("\t", "")

        if (kw not in kv_pairs):
            new_clause += lisp_write_error(line, "invalid command keyword")
            error = True
            continue
        #endif

        #
        # If there is no value type, then this could be an "address" that needs
        # semantic check. There could also be a prefix that needs a format
        # check. Right now special case keyword "eid-prefix" to be a prefix
        # type.
        #
        if (len(kv_pairs[kw]) <= 1): 
            msg = ""
            if (kw == "eid-prefix" and not lisp_valid_prefix_format(value)):
                msg = "invalid prefix"
            #endif
            if (kw == "address" and not \
                lisp.lisp_valid_address_format(kw, value)):
                msg = "invalid address"
            #endif
            if (msg != ""):
                new_clause += lisp_write_error(line, msg)
                error = True
                continue
            #endif
        #endif

        #
        # Check if this command can have an instance-ID range, a "*", or
        # a single instance-ID value.
        #
        if (len(kv_pairs[kw]) == 4 and kv_pairs[kw][3]):
            if (kw == "instance-id"):
                is_range = (value.find("-") != -1)
                is_ultimate = (value == "*")

                if (is_range or is_ultimate):
                    lower, mask_len = lisp_validate_range(value)
                    if (mask_len == -1):
                        new_clause += lisp_write_error(line, "invalid range")
                        error = True
                        continue
                    #endif
                else:
                    lower = value
                    mask_len = 32
                #endif

                value = str(lower) + "-" + str(mask_len)
            #endif
        #endif
                
        #
        # Multi-instance commands and clauses makes value into an array. The
        # while loop is for cases where a command can appear multiple times
        # not inside of sub-clause.
        #
        if (kv_pairs[kw][0] and kw in new_kv_pairs):
            if (new_kv_pairs[kw][index] != ""): index += 1
            new_kv_pairs[kw][index] = value
        else:
            new_kv_pairs[kw] = value
        #endif

        #
        # Check value in range, if value type are integers, otherwise match
        # keyword type value. If value is a range, remove "-" and mask-len
        # to see if lower range value is allowable in range.
        #
        if (len(kv_pairs[kw]) > 1):
            value_type = kv_pairs[kw][1]
            if (type(value_type) == int):
                if (type(value) == str): value = value.split("-")[0]
                value = int(value)
                if (value < kv_pairs[kw][1] and value > kv_pairs[kw][2]):
                    new_clause += lisp_write_error(line, "invalid range value")
                    error = True
                    continue
                #endif
            elif (value not in kv_pairs[kw][1::]):
                new_clause += lisp_write_error(line, "invalid value keyword")
                error = True
                continue
            #endif
        #endif

        #
        # Write good command to return buffer.
        #
        new_clause += lisp_write_line(line)
    #endfor

    if (error == True):
        new_clause = new_clause.replace("%", "#")
    else:
        new_clause = new_clause.replace("#", "")
        new_clause = new_clause.replace("%", "#")
    #endif
    return([error, new_clause, new_kv_pairs])
#enddef

#
# lisp_process_command
#
# Process commands in components (not the lisp-core process except for debug
# commands).
#
# Variable "clause" is a string and not a byte string. Caller converts.
#
def lisp_process_command(lisp_socket, opcode, clause, process, command_set):

    #
    # For configuration commands get first two tokens. For show commands, a
    # summary or table display will have only two tokens. However, a detailed
    # display will have parameters following a "%" sign.
    #
    command = clause.split(" ")

    #
    # If debug command, turn on/off boolean.
    #
    if (clause.find("lisp debug") != -1):
        if (clause.find("= yes") != -1):
            lisp.lisp_debug_logging = True
            enable = lisp.bold("Enable", False)
            lisp.lprint("{} process debug logging".format(enable))
        #endif
        if (clause.find("= no") != -1):
            disable = lisp.bold("Disable", False)
            lisp.lprint("{} process debug logging".format(disable))
            lisp.lisp_debug_logging = False
        #endif
        return
    #endif

    #
    # Handle show commands differently than configuration commands. We have
    # to pass parameters for detailed displays and lookups.
    #
    is_show_command = (command[0] == "show")
    if (is_show_command):
        parameters = clause.split("%")
        command = parameters[0].split(" ")
        parm_len = len(parameters)
        if (parm_len == 2): 
            parameters = parameters[1]
        elif (parm_len == 3):
            parameters = parameters[1] + "%" + parameters[2] + "%"
        else:
            parameters = ""
        #endif
    #endif
    command = command[0] + " " + command[1]

    for cmds in command_set:
        if (command in cmds):
            command_processor, kv_pairs = cmds[command]
            break
        #endif
        if (cmds == command_set[-1]):
            lisp.lprint("Invalid command found '{}'".format(command))
            return
        #endif
    #endfor

    #
    # Configuration commands will have kv-pairs and will produce a new
    # clause the same as the input one or a commented out clause showing
    # the error line. Show commands don't have any input checking so they
    # will return show output. But the parameter passed to show commands could
    # be for a detailed display.
    # 
    error = False
    if (len(kv_pairs) != 0):
        error, new_clause, kv_pairs = lisp_syntax_check(kv_pairs, clause)
        if (error):
            lisp.lprint("Command syntax error: {}".format(new_clause))
        else:
            command_processor(kv_pairs)
        #endif
    else:
        if (is_show_command): kv_pairs = parameters
        new_clause = command_processor(kv_pairs)
    #endif

    ipc = lisp.lisp_command_ipc(new_clause, process)
    lisp.lisp_ipc(ipc, lisp_socket, "lisp-core")
    return
#enddef

#
# lisp_is_user_superuser
#
# Return True if supplied user is super-user.
#
def lisp_is_user_superuser(username):
    if (username == None): username = lisp_get_user()

    #
    # Get all "lisp user-account" commands.
    #
    users = getoutput("egrep -A 4 user-account ./lisp.config")
    
    username_str = "username = {}".format(username)
    index = users.find(username_str)
    end = users[index::].find("}")
    if (index == -1 or end == -1): return(False)

    superuser = users[index:index+end].find("super-user = yes")
    return(superuser != -1)
#enddef

#
# lisp_find_user_account
#
# Grep configuration file to find username and password.
#
def lisp_find_user_account(username, password):

    #
    # Get all "lisp user-account" commands.
    #
    users = getoutput("egrep -A 4 user-account ./lisp.config")

    #
    # Find this particular username. If we don't the username, the user is
    # not allowed access to this system.
    #
    index = users.find("username = {}\n".format(username))
    if (index == -1): return(False)

    users = users[index::]
    users = users.replace("\t", "")
    users = users.replace(" ", "")

    #
    # Get next line which is the password value. Get the line and extract
    # out the password value on the right-hand side of the "=".
    #
    index = users.find("password=")
    if (index == -1): return(False)

    #
    # Delimit string to "password=<pw>}".
    #
    users = users[index::]
    end = users.find("\n")
    if (end == -1): return(False)

    #
    # Get <pw> and compare to what was passed by web client. We need to
    # hash the plaintext password passed by client because it is stored
    # in lisp.config in ciphertext. The split() should give us the following
    # if the password stored is encrypted ["password", "", <ciphertext>] and
    # [password, <plaintext>] if file not processed yet. Validate in either
    # case.
    #
    pw = users[:end].split("=")
    if (pw[1] == ""):
        ciphertext = lisp_hash_password(password)
        if (pw[2] != ciphertext): return(False)
    else:
        if (pw[1] != password): return(False)
    #endif

    #
    # Both username and password match from configuration file. The user
    # is allowed access.
    #
    return(True)
#enddef

#
# lisp_validate_user
#
# Check if username and password valid from LISP configuration file. If so,
# create new entry in lispconfig.lisp_current_users list to store cookie.
#
def lisp_validate_user():
    username = bottle.request.forms.get('username')

    if (username == None):
        cookie = bottle.request.get_cookie("lisp-login")
        if (cookie): return(True)
    #endif

    password = bottle.request.forms.get('password')
    if (username == None or password == None): return(False)

    if (lisp_find_user_account(username, password) == False): return(False)

    #
    # We have a valid user. Store username with cookie and send to web client.
    #
    age = None if os.getenv("LISP_NO_USER_TIMEOUT") == "" else \
        LISP_USER_TIMEOUT
    bottle.response.set_cookie("lisp-login", username, max_age=age)
    return(True)
#enddef

#
# lisp_get_user
#
# Get username for current web session.
#
def lisp_get_user():
    username =  bottle.request.forms.get('username')
    if (username): return(username)

    return(bottle.request.get_cookie("lisp-login"))
#enddef

#
# lisp_login_page
#
# Username/password web page to authenticate user.
#
def lisp_login_page():
    output = '''
        <center><br><br>
        <form action="/lisp/login" method="post">
        <font size="3"><i>
        Username:<input type="text" name="username" />
        {}Password:<input type="password" name="password" />
        {}<input style="background-color:transparent;border-radius:10px;" type="submit" value="Login" />
        </i></font></form>
        </center>
    '''.format(lisp.lisp_space(4), lisp.lisp_space(2))
    return(lisp_banner_top(True) + output + "<br><hr>")
#enddef

#
# lisp_is_any_xtr_logging_on
#
# Grep configuration file for "data-plane-logging = " or "flow-logging = "
# and return True if value after "=" is "yes".
#
def lisp_is_any_xtr_logging_on(log_type):
    command = "egrep '" + log_type + " = '" + " ./lisp.config"
    command = getoutput(command)
    if (command == ""): return(False)

    #
    # Check if commented out or in diff section of configuration file.
    #
    command = command.split("\n")
    for c in command:
        found = c.find("    {} = ".format(log_type)) != -1
        if (c[0] == " " and found):
            command = c.replace(" ", "")
            command = command.split("=")
            if (command[1] == "yes"): return(True)
        #endif
    #endfor
    return(False)
#enddef

#
# lisp_landing_page
#
# When a browser connects to this system on a special port, this landing
# page will be displayed.
#
def lisp_landing_page():
    yes = lisp.green("yes", True)
    no = lisp.red("no", True)

    itr = yes if lisp.lisp_is_running("lisp-itr") else no
    etr = yes if lisp.lisp_is_running("lisp-etr") else no
    rtr = yes if lisp.lisp_is_running("lisp-rtr") else no
    mr = yes if lisp.lisp_is_running("lisp-mr") else no
    ms = yes if lisp.lisp_is_running("lisp-ms") else no
    ddt = yes if lisp.lisp_is_running("lisp-ddt") else no

    output = '''
        <center>
        <i><b>LISP Subsystem Run Status:</b>
        </center><br>
        <table border="1" align="center">
        <tr>
        <th><i>ITR</i></th>
        <th><i>RTR</i></th>
        <th><i>ETR</i></th>
        <th><i>MR</i></th>
        <th><i>DDT</i></th>
        <th><i>MS</i></th>
        </tr>
        <tr align="center">
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        </tr>
        </table>
        <br>
    '''.format(itr, rtr, etr, mr, ddt, ms)

    output += '''
        <center>
        <style type="text/css">
        form { display:inline }
        </style>

        <a href="/lisp/show/status">
        <button style="background-color:transparent;border-radius:10px;
        type="button">system status</button></a>
    '''

    dc = lisp_get_clause_for_api("lisp debug")[0]
    dc = dc["lisp debug"] if ("lisp debug" in dc) else None
    key = "lisp xtr-parameters"
    xl = lisp_get_clause_for_api(key)[0]
    xtr_logging = False
    if (key in xl):
        d = { "data-plane-logging" : "yes" }
        f = { "flow-logging" : "yes" }
        xtr_logging = (d in xl[key] or f in xl[key])
    #endif

    dc_dict = {}
    for entry in dc: dc_dict[list(entry.keys())[0]] = list(entry.values())[0]
    dc = dc_dict
    dc["ddt"] = dc["ddt-node"]
    dc["mr"] = dc["map-resolver"]
    dc["ms"] = dc["map-server"]

    #
    # Set up "show logging" button.
    #
    count = getoutput("wc -l logs/lisp-core.log")
    count = count.replace(" ", "")
    count = count.split("logs")[0]
    onoff = "on" if dc["core"] == "yes" else "off"
    output += '''
        <form>
        <select size="1" style="width: 110px"
                onchange="parent.window.location=this.value">
        <option value="">show logging:</option>
        <option value="/lisp/show/log/lisp-core/100">[{}] core log [{}]
        </option>'''.format(onoff, count)

    if (os.path.exists("./logs/lisp-itr.log")):
        count = getoutput("wc -l logs/lisp-itr.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["itr"] == "yes" else "off"
        output += '''
            <option value="/lisp/show/log/lisp-itr/100">[{}] ITR log [{}]
            </option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-rtr.log")):
        count = getoutput("wc -l logs/lisp-rtr.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["rtr"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-rtr/100">[{}] RTR 
           log [{}]</option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-etr.log")):
        count = getoutput("wc -l logs/lisp-etr.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["etr"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-etr/100">[{}] ETR 
            log [{}]</option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-xtr.log")):
        count = getoutput("wc -l logs/lisp-xtr.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["itr"] == "yes" or dc["etr"] == "yes" or \
            dc["rtr"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-xtr/100">[{}] XTR 
           log [{}]</option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-mr.log")):
        count = getoutput("wc -l logs/lisp-mr.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["mr"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-mr/100">[{}] MR 
            log [{}] </option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-ddt.log")):
        count = getoutput("wc -l logs/lisp-ddt.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["ddt"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-ddt/100">[{}] DDT 
            log [{}]</option>'''.format(onoff, count)
    #endif
    if (os.path.exists("./logs/lisp-ms.log")):
        count = getoutput("wc -l logs/lisp-ms.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if dc["ms"] == "yes" else "off"
        output += '''<option value="/lisp/show/log/lisp-ms/100">[{}] MS 
            log [{}]</option>'''.format(onoff, count)
    #endif
    flow_logging_on = lisp_is_any_xtr_logging_on("flow-logging")
    if (os.path.exists("./logs/lisp-flow.log")):
        count = getoutput("wc -l logs/lisp-flow.log")
        count = count.replace(" ", "")
        count = count.split("logs")[0]
        onoff = "on" if flow_logging_on else "off"
        output += '''<option value="/lisp/show/log/lisp-flow/100">[{}] flow 
            log [{}]</option>'''.format(onoff, count)
    #endif
    output += "</select></form>"

    #
    # Debug pull-down menu.
    #
    superuser = lisp_is_user_superuser(None)
    if (superuser):
        output += '''
            <form>
            <select size="1" style="width: 120px"
                    onchange="parent.window.location=this.value">
            <option value="">manage logging:</option>
        '''

        #
        # Put a "disable all" line in if any debug is turned on. Allows user
        # to turn off all debug logging with one menu click.
        #
        if ("yes" in list(dc.values()) or xtr_logging):
            output += '''<option value="/lisp/debug/{}%{}">disable all logging
                </option>'''.format("disable", "all")
        #endif

        data_plane_logging = False
        flow_logging = False
        for process in dc:
            if (lisp.lisp_is_running("lisp-" + process) == False): continue

            if (process in ["itr", "etr", "rtr"]): 
                data_plane_logging = True
                flow_logging = True
            #endif

            yesno = dc[process]
            p = process
            if (p == "mr"): p = "map-resolver"
            if (p == "ms"): p = "map-server"
            if (p == "ddt"): p = "ddt-node"
            
            output += '''<option value="/lisp/debug/{}%{}">{} {} logging
                </option>'''.format(p, "yes" if yesno == "no" else "no", 
                "enable" if yesno == "no" else "disable", 
                process.upper() if process != "core" else "core")
        #endfor
        if (data_plane_logging):
            on = lisp_is_any_xtr_logging_on("data-plane-logging")
            output += '''<option value="/lisp/debug/data-plane-logging%{}">{} 
                data-plane logging </option>'''.format( \
                "yes" if on == False else "no", 
                "enable" if on == False else "disable")
        #endif
        if (flow_logging):
            on = flow_logging_on
            output += '''<option value="/lisp/debug/flow-logging%{}">{} 
                flow logging </option>'''.format(
                "yes" if on == False else "no", 
                "enable" if on == False else "disable")
        #endif
        output += "</select></form>"
    #endif

    output += "<br><br>"

    #
    # Create coloring for the up/down status table.
    #
    Itr = lisp.lisp_button("{}:<br>show map-cache", None)
    if (lisp.lisp_is_running("lisp-itr")):
        Itr = '<a href="/lisp/show/itr/map-cache">' + Itr + '</a>'
        Itr = Itr.format(lisp.green("ITR", True))
    else:
        Itr = Itr.format(lisp.red("ITR", True))
        Itr = lisp.lisp_span(Itr, "ITR not running")
    #endif

    Rtr = lisp.lisp_button("{}:<br>show map-cache", None)
    if (lisp.lisp_is_running("lisp-rtr")):
        Rtr = '<a href="/lisp/show/rtr/map-cache">' + Rtr + '</a>'
        Rtr = Rtr.format(lisp.green("RTR", True))
    else:
        Rtr = Rtr.format(lisp.red("RTR", True))
        Rtr = lisp.lisp_span(Rtr, "RTR not running")
    #endif

    Mr = lisp.lisp_button("{}:<br>show referral-cache", None)
    if (lisp.lisp_is_running("lisp-mr")):
        Mr = '<a href="/lisp/show/referral">' + Mr + '</a>'
        Mr = Mr.format(lisp.green("MR", True))
    else:
        Mr = Mr.format(lisp.red("MR", True))
        Mr = lisp.lisp_span(Mr, "MR not running")
    #endif

    Ddt = lisp.lisp_button("{}:<br>show delegations", None)
    if (lisp.lisp_is_running("lisp-ddt")):
        Ddt = '<a href="/lisp/show/delegations">' + Ddt + '</a>'
        Ddt = Ddt.format(lisp.green("DDT", True))
    else:
        Ddt = Ddt.format(lisp.red("DDT", True))
        Ddt = lisp.lisp_span(Ddt, "DDT not running")
    #endif

    Ms = lisp.lisp_button("{}:<br>show site-cache", None)
    if (lisp.lisp_is_running("lisp-ms")):
        Ms = '<a href="/lisp/show/site">' + Ms + '</a>'
        Ms = Ms.format(lisp.green("MS", True))
    else:
        Ms = Ms.format(lisp.red("MS", True))
        Ms = lisp.lisp_span(Ms, "MS not running")
    #endif

    Etr = lisp.lisp_button("{}:<br>show database-mappings", None)
    if (lisp.lisp_is_running("lisp-etr")):
        Etr = '<a href="/lisp/show/database">' + Etr + '</a>'
        Etr = Etr.format(lisp.green("ETR", True))
    else:
        Etr = Etr.format(lisp.red("ETR", True))
        Etr = lisp.lisp_span(Etr, "ETR not running")
    #endif

    input_eid = lisp.lisp_eid_help_hover('<input type="text" name="eid" />')
    input_gpo = lisp.lisp_geo_help_hover( \
        '<input type="text" name="geo-point" size="30" required />')
    input_gpr = lisp.lisp_geo_help_hover( \
        '<input type="text" name="geo-prefix" size="30" required />')

    ad = lisp.lisp_button("API Documentation", "/lisp/show/api-doc")
    cd = lisp.lisp_button("Command Documentation", "/lisp/show/command-doc")
    ild = lisp.lisp_button("IETF LISP WG Drafts", 
        "http://datatracker.ietf.org/wg/lisp/")
    lfg = lisp.lisp_button("LISP Facebook Group", 
        "https://www.facebook.com/groups/407716795982512")
    llg = lisp.lisp_button("LISP LinkedIn Group", 
        "http://www.linkedin.com/groups/3776183")

    s = lisp.lisp_space(2)
    output += '''     
        <table><tr>
          <td width="50%" align="center">
          <table border="1">
            <tr><td align="center"><i><b>Data-Plane</b></i><br>
            {}{}{}{}{}{}{}
            </td></tr>
          </table>
          </td>
 
          <td width="50%" align="center">
          <table border="1">
            <tr><td align="center"><i><b>Control-Plane</b></i><br>
            {}{}{}{}{}{}{}
            </td></tr>
          </table>
          </td>
        </tr></table>

        <br><hr><br>

        <form action="/lisp/lig" method="post">
        <font face="Courier New" size="2">
        Run <b><i>lig</i></b> on EID: {}
        to Map-Resolver: <input type="text" name="mr" />
        count (1-5): <input type="text" name="count" />
        no-nat: <input type="checkbox" name="no-nat" value="yes">
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form><br><br>

        <form action="/lisp/rig" method="post">
        <font face="Courier New" size="2">
        Run <b><i>rig</i></b> on EID: {}
        to any DDT-node: <input type="text" name="ddt" />
        follow-all-referrals: <input type="checkbox" name="follow" 
        value="yes">
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form><br><br>

        <form action="/lisp/geo" method="post">
        <font face="Courier New" size="2">
        Run <b><i>geo-test</i></b> on geo-point: {}
        for geo-prefix: {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
        </center><br>

        <hr>
        <center><br>{}{}{}{}{}{}
        </center>

    '''.format(s, Itr, s, Rtr, s, Etr, s, s, Mr, s, Ddt, s, Ms, s, input_eid,
        input_eid, input_gpo, input_gpr, ad, cd, "<br><br>", ild, lfg, llg)

    return(lisp_show_wrapper(output))
#enddef

#
# lisp_drain_socket
#
# We received an IPC from someone we didn't expect. Drain the queue looking
# for the one we expected.
#
def lisp_drain_socket(lisp_socket, process):
    lisp.lprint("Draining socket looking for {}".format(process))

    saved_output = None
    while (True):
        try:
            select.select([lisp_socket], [], [])
        except:
            return(saved_output)
        #endtry

        lisp.lisp_ipc_lock.acquire()
        opcode, source, port, output = lisp.lisp_receive(lisp_socket, True)
        lisp.lisp_ipc_lock.release()

        if (source != process):
            lisp.lprint("Discarding IPC message from {}".format(source))
        elif (saved_output == None): 
            saved_output = output
        #endif
    #endwhile
    return
#enddef

#
# lisp_process_show_command
#
# Find out which process owns the command and send an IPC message to it to
# process the command. Then wait for the show output.
#
def lisp_process_show_command(lisp_socket, command):

    #
    # Check if parameter was specified.
    #
    show_command = command.split("%")
    show_command = show_command[0]

    #
    # There is only one element in the array for show commands.
    #
    process = lisp_commands[show_command]
    process = process[0]

    if (lisp.lisp_is_running(process) == False):
        output = ("<i>Process '{}' is not running, command cannot be " + \
            "executed</i><br>").format(process)
        return(lisp_show_wrapper(output))
    #endif

    ipc = lisp.lisp_command_ipc(command, "lisp-core")

    #
    # Critical section.
    #
    lisp.lisp_ipc_lock.acquire()

    lisp.lisp_ipc(ipc, lisp_socket, process)
    lisp.lprint("Waiting for response to show command '{}'".format(command))

    opcode, source, port, output = lisp.lisp_receive(lisp_socket, True)
    output = output.decode()

    lisp.lisp_ipc_lock.release()

    #
    # If we get a response from the process we are not expecting, drain
    # lisp-core's lisp_ipc_socket.
    #
    if (source == ""): 
        lisp.lprint("Command '{}' timed out to {}".format(command, process))
    elif (source != process):
        lisp.lprint("Received response from {} but expecting from {}".format( \
            source, process))
        output = lisp_drain_socket(lisp_socket, process)
        if (output == None): output = "<i>Fatal error, retry later</i><br>"
    #endif
    return(lisp_show_wrapper(output))
#enddef

#
# lisp_start_stop_process
#
# Start a process if the pyo file exists. Killall when caller says so.
#
def lisp_start_stop_process(process, startstop):
    if (startstop and lisp.lisp_is_running(process)): return
    if (startstop == False and lisp.lisp_is_running(process) == False): return

    logfile = "./logs/" + process + ".log"

    if (lisp.lisp_is_python2()):
        py = "python -O "
        filename = process + ".pyo"
    elif (lisp.lisp_is_python3()):
        py = "python3.8 -O "
        filename = process + ".pyc"
    else:
        lisp.lprint("Cannot manage process '{}', unsupported python version". \
            format(process))
    #endif
    
    if (lisp.lisp_is_ubuntu() or lisp.lisp_is_raspbian() or \
        lisp.lisp_is_debian() or lisp.lisp_is_debian_kali()):
        program = py + filename + " 2>&1 > " + logfile + " &"
    else:
        program = py + filename + " >& " + logfile + " &"
    #endif

    datestamp = getoutput("date")
    if (startstop and os.path.exists(filename)):
        lisp.lprint("Start process '{}' on {}".format(process, datestamp))
        os.system(program)
        time.sleep(1)
        return
    #endif

    if (startstop == False and os.path.exists(filename)):
        lisp.lprint("Stop process '{}' on {}".format(process, datestamp))
        pid = getoutput("pgrep -f " + filename)
        pid = pid.split("\n")[0]
        os.system("kill " + pid)
        os.system("rm " + process)
        return
    #endif
    return
#enddef

#
# lisp_enable_command
#
# Start or shut down processes by processing the "lisp enable" command.
#
def lisp_enable_command(clause):

    #
    # Only process this command if we are not in manual mode. Manual mode
    # means if there is a lisp.py in the current directory, we are in manual
    # mode (running each LISP component from command line via .py or .pyc 
    # files only.
    #
    if (os.path.exists("lisp.py") and os.path.exists("lisp.pyo") == False):
        lisp.lprint("In manual mode, ignoring 'lisp enable' command")
        return(clause)            
    #endif

    command = clause.split(" ")
    command = command[0] + " " + command[1]
    
    kv_pairs  = lisp_core_commands["lisp enable"]
    kv_pairs = kv_pairs[1]
    
    #
    # Do syntax check. kv_pairs change from static values to kw/value pairs
    # from the command line.
    #
    error, new_clause, kv_pairs = lisp_syntax_check(kv_pairs, clause)

    #
    # Return error clause.
    #
    if (error == True): return(new_clause)

    components = {"itr" : "lisp-itr", "etr" : "lisp-etr", "rtr" : "lisp-rtr",
        "map-resolver" : "lisp-mr", "map-server" : "lisp-ms", 
        "ddt-node" : "lisp-ddt"}

    # 
    # Process command.
    #
    for parameter in list(components.keys()):
        startstop = True if kv_pairs[parameter] == "yes" else False
        lisp_start_stop_process(components[parameter], startstop)
    #endfor
    return(new_clause)
#enddef

#
# lisp_debug_command
#
# Process the "lisp debug" command.
#
def lisp_debug_command(lisp_socket, clause, single_process):
    command = clause.split(" ")
    command = command[0] + " " + command[1]
    
    kv_pairs  = lisp_core_commands["lisp debug"]
    kv_pairs = kv_pairs[1]
    
    #
    # Do syntax check. kv_pairs change from static values to kw/value pairs
    # from the command line.
    #
    error, new_clause, kv_pairs = lisp_syntax_check(kv_pairs, clause)

    #
    # Return error clause.
    #
    if (error == True): return(new_clause)

    components = {"itr" : "lisp-itr", "etr" : "lisp-etr", "rtr" : "lisp-rtr",
        "map-resolver" : "lisp-mr", "map-server" : "lisp-ms", 
        "ddt-node" : "lisp-ddt", "core" : ""}

    for component in kv_pairs:
        process = components[component]
        if (single_process and single_process != process): continue

        yesno = kv_pairs[component]
        command = ("lisp debug {\n" + "    {} = {}\n".format( \
            component, yesno) + "}\n")

        #
        # Process enable/disable core debugging here.
        #
        if (component == "core"):
            lisp_process_command(None, None, command, None, [None])
            continue
        #endif

        command = lisp.lisp_command_ipc(command, "lisp-core")
        lisp.lisp_ipc(command, lisp_socket, process)
        if (single_process): break
    #endfor
    return(new_clause)
#enddef

#
# lisp_replace_password_in_clause
#
# Look for keyword string in clause and replace it with an ciphertext string.
#
def lisp_replace_password_in_clause(clause, keyword_string):
    index = clause.find(keyword_string)

    #
    # If not found there is no passwords in this clause.
    #
    if (index == -1): return(clause)

    #
    # If the password is already encrypted, just return.
    #
    index += len(keyword_string)
    end = clause[index::].find("\n")
    end += index
    password = clause[index:end].replace(" ", "")
    
    if (len(password) != 0 and password[0] == "="): return(clause)

    #
    # Get rid of whitespace around password plaintext value. Hash it and
    # and insert into clause. Prepend a "=" so we can identify the storing
    # of the password as ciphertext.
    #
    password = password.replace(" ", "")
    password = password.replace("\t", "")
    password = lisp_hash_password(password)
    clause = clause[0:index] + " =" + password + clause[end::]

    #
    # Return new clause.
    #
    return(clause)
#enddef

#
# lisp_user_account_command
#
# Accept username and password parameters. There is no semantic logic here
# and no data structure storage. Just syntax checking. We do this so the
# bottle process can get syntactically correct "lisp user-account" command.
#
def lisp_user_account_command(clause):

    command = clause.split(" ")
    command = command[0] + " " + command[1]
    
    kv_pairs  = lisp_core_commands["lisp user-account"]
    kv_pairs = kv_pairs[1]
    
    #
    # Do syntax check. kv_pairs change from static values to kw/value pairs
    # from the command line.
    #
    error, new_clause, kv_pairs = lisp_syntax_check(kv_pairs, clause)

    #
    # Store a ciphertext password unless it is already in the command.
    #
    if (error == False):
        new_clause = lisp_replace_password_in_clause(new_clause, "password =")
    #endif
    return(new_clause)
#enddef

#
# lisp_rtr_list_command
#
# Process the Map-Server "lisp rtr-list" command (in the lisp-core process).
#
def lisp_rtr_list_command(clause):
    command = clause.split(" ")
    command = command[0] + " " + command[1]
    
    kv_pairs  = lisp_core_commands["lisp rtr-list"]
    kv_pairs = kv_pairs[1]

    #
    # Do syntax check. kv_pairs change from static values to kw/value pairs
    # from the command line.
    #
    error, new_clause, kv_pairs = lisp_syntax_check(kv_pairs, clause)

    if (error): return(new_clause)

    lisp.lisp_ms_rtr_list = []
    if ("address" in kv_pairs):
        for addr_str in kv_pairs["address"]:
            addr = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
            addr.store_address(addr_str)
            lisp.lisp_ms_rtr_list.append(addr)
        #endfor
    #endif
    return(new_clause)
#enddef

#
# lisp_process_command_lines
#
# Process each supported command. Dispatch to component. This function is
# called only by the lisp-core process.
#
def lisp_process_command_lines(lisp_socket, old, new, line):
    command = line.split("{")
    command = command[0]
    command = command[0:-1]

    lisp.lprint("Process the '{}' command".format(command))

    #
    # Found invalid command with no curly brackets delimiting it.
    #
    if (command not in lisp_commands):
        line = "#>>> " + line.replace("\n", " <<< invalid command\n")
        new.write(line)
        return
    #endif

    #
    # Found invalid command with curly brackets delimiting it.
    #
    processes = lisp_commands[command] 
    write_once = False
    for process in processes:
        if (process == ""):
            line = lisp_write_error(line, "invalid command")
            new.write(line)
            return
        #endif

        if (write_once == False):
            clause = line
            count = 1
            for line in old:
                if (lisp_begin_clause(line)): count += 1
                clause += line
                if (lisp_end_clause(line)): 
                    count -= 1
                    if (count == 0): break
                #endif
            #endfor
        #endif

        #
        # If process is not running, do not do anything with command.
        #
        if (lisp.lisp_is_running(process) == False):
            if (write_once == False): 
                for line in clause: new.write(line)
                write_once = True
            #endif
            lisp.lprint("Process '{}' is not running, do not send command". \
                format(process))
            continue
        #endif

        #
        # Call local function if command for this process. Otherwise, send 
        # clasue over internal socket. And then wait for a response clause.
        #
        if (process == "lisp-core"):
            if (clause.find("enable") != -1):
                new_clause = lisp_enable_command(clause)
            #endif
            if (clause.find("debug") != -1):
                new_clause = lisp_debug_command(lisp_socket, clause, None)
            #endif
            if (clause.find("user-account") != -1):
                new_clause = lisp_user_account_command(clause)
            #endif
            if (clause.find("rtr-list") != -1):
                new_clause = lisp_rtr_list_command(clause)
            #endif
        else:
            ipc = lisp.lisp_command_ipc(clause, "lisp-core")
            lisp.lisp_ipc(ipc, lisp_socket, process)
            lisp.lprint("Waiting for response to config command '{}'".format( \
                command))
    
            opcode, source, port, new_clause = lisp.lisp_receive(lisp_socket, 
                True)

            if (source == ""):
                lisp.lprint("Command timed out to {}".format(process))
                new_clause = clause
            elif (source != process):
                lisp.lprint("Fatal IPC error to {}, source {}".format(process,
                    source))
            #endif
            new_clause = new_clause.decode()
        #endif

        #
        # Write the return clause to the new configuraiton file. If there are
        # errors they are identified in the clause buffer.
        #
        if (write_once == False):
            for line in new_clause: new.write(line)
            write_once = True
        #endif
    #endfor
    return
#enddef

#
# lisp_process_config_file
#
# Parse config file to process any changes.
#
def lisp_process_config_file(lisp_socket, file_name, startup):
    lisp.lprint("Processing configuration file {}".format(file_name))

    #
    # First check to see if config file exists. If not, can't do anything.
    #
    if (os.path.exists(file_name) == False):
        lisp.lprint("LISP configuration file '{}' does not exist".format( \
            file_name))
        return
     #endif

    diff_name = file_name + ".diff"
    backup_name = file_name + ".bak"
    new_name = file_name + ".temp"
    config_header = "# lispers.net lisp.config file"

    #
    # Validate integrity of configuration file by checking for "lispers.net"
    # in first two lines.
    #
    cmd = 'egrep "{}" {}'.format(config_header, file_name)
    found = getoutput(cmd)
    if (found == ""):
        lisp.lprint("*** lisp.config configuration file is corrupt ***")
        return
    #endif

    #
    # Now copy and process each line in old to write to new starting from
    # the top of existing configuration file.
    #
    old = open(file_name, "r")
    new = open(new_name, "w")
    for line in old:
        if (line.find(config_header) == 0):
            if (startup):
                new.write(line)
            else:
                lisp_write_last_changed_date(new, line)
            #endif
            continue
        #endif

        if (line.find("# Hostname:") == 0):
            new.write("# Hostname: " + lisp.lisp_hostname + "\n")
            continue
        #endif

        if (lisp_end_file(line)): 
            new.write(line + "\n")
            break
        #endif

        if (lisp_comment(line)):
            new.write(line)
            continue
        #endif

        all_spaces = line.replace(" ", "")
        all_spaces = all_spaces.replace("\n", "")
        if (all_spaces == ""): continue

        #
        # Found command, go process it now.
        #
        lisp_process_command_lines(lisp_socket, old, new, line)
    #endfor
    old.close()
    new.close()

    #
    # Do a diff and store in lisp.config.diff
    #
    if (os.path.exists(diff_name) == False): 
        os.system("touch {}".format(diff_name))
    #endif
    if (startup == False):
        os.system("diff {} {} > {}".format(backup_name, new_name, diff_name))
    #endif

    #
    # Copy current lisp.config file to backup so when it is changed later, 
    # we have an old copy that can be diff'ed. 
    #
    os.system("cp {} {}; rm -f {}; cp {} {}".format(new_name, file_name, 
        new_name, file_name, backup_name))
    return
#enddef

#
# lisp_send_commands
#
# A process just came up, send it the commands it is responsible for. This
# function is only called by the lisp-core process.
#
def lisp_send_commands(lisp_socket, process):
    file_name = "./lisp.config"
    config = open(file_name, "r")
    capture = False
    indent = 0

    #
    # Go through each line of the configuration file.
    #
    for line in config:
        if (lisp_end_file(line)): break
        if (lisp_comment(line) or line[0] == "\n"): continue

        if (lisp_begin_clause(line)):
            if (indent == 0):
                clause = ""
                command = line.split("{")
                command = command[0]
                command = command[0:-1]
                if (command in lisp_commands):
                    capture = (process in lisp_commands[command]) or \
                        (command == "lisp debug")
                #endif
            #endif
            indent += 1
        #endif

        #
        # Capture line.
        #
        if (capture): clause += line

        #
        # Only when we find the command end of clause (and not one from a
        # subclause), we are at the end of the command clause.
        #
        if (lisp_end_clause(line) == False): continue
        indent -= 1
        if (indent != 0): continue
        if (capture == False): continue

        #
        # No need to wait for a response. We don't have to write it back to
        # the configuration file and we know the syntax check has been done
        # already.
        #
        lisp.lprint("Send command '{}' to restarting process '{}'".format( \
            command, process))

        #
        # The debug command is special since only the sub-clause for the
        # specific companent is sent.
        #
        if (command == "lisp debug"):
            lisp_debug_command(lisp_socket, clause, process)
            capture = False
            continue
        #endif

        clause = lisp.lisp_command_ipc(clause, "lisp-core")
        lisp.lisp_ipc(clause, lisp_socket, process)

        #
        # Wait for response. Do nothing with it. The process will want to
        # respond and we need to clear the IPC send buffer in it.
        #
        lisp.lprint("Waiting for response to config command '{}'".format( \
            command))

        opcode, source, port, packet = lisp.lisp_receive(lisp_socket, True)

        if (source == ""):
            lisp.lprint("Command timed out to {}".format(process))
        elif (source != process):
            lisp.lprint("Fatal IPC error to {}, IPC source {}".format(process,
                source))
        #endif
        capture = False
    #endfor
    return
#enddef

#
# lisp_config_process
#
# Watch for configuration file changes in file 'lisp.config' and process
# changes when timestamp of file changes.
#
def lisp_config_process(lisp_socket):
    lisp.lisp_set_exception()
    file_name = "./lisp.config"
    last = ""
    startup = True

    while (True):
        ts = os.path.getmtime(file_name)
        if (ts != last):

            lisp.lisp_ipc_lock.acquire()
            lisp_process_config_file(lisp_socket, file_name, startup)
            lisp.lisp_ipc_lock.release()

            startup = False
            last = os.path.getmtime(file_name)
        #endif
        time.sleep(1)
    #endwhile
    return
#enddef

#------------------------------------------------------------------------------

#
# ----- Functions used by both the lisp-itr and lisp-rtr processes. -----
#

#
# lisp_map_resolver_command
#
# Store configured map-resolvers.
#
def lisp_map_resolver_command(kv_pair):
    mr_name = None

    for kw in list(kv_pair.keys()):
        if (kw == "mr-name"):
            mr_name = kv_pair[kw][0]
            continue
        #endif
        if (kw == "address" or kw == "dns-name"):
            map_resolvers = kv_pair[kw]
            for value in map_resolvers:
                if (value == ""): continue
                addr_str = value if (kw == "address") else None
                dns_name = value if (kw == "dns-name") else None
                lisp.lisp_mr(addr_str, dns_name, mr_name)
            #endfor
        #endif
    #endfor
    return
#enddef

#
# lisp_map_cache_command
#
# Process static map-cache command.
#
def lisp_map_cache_command(kv_pair):
    prefix_set = []
    if (lisp_clause_syntax_error(kv_pair, "eid-prefix", "prefix")): return
    for i in range(len(kv_pair["eid-prefix"])):
        mc = lisp.lisp_mapping("", "", [])
        prefix_set.append(mc)
    #endfor

    rloc_set = []
    if ("address" in kv_pair):
        if (lisp_clause_syntax_error(kv_pair, "address", "rloc")): return
        for i in range(len(kv_pair["address"])):
            rloc = lisp.lisp_rloc()
            rloc_set.append(rloc)
        #endfor
    #endif

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]
        if (kw == "instance-id"):
            for i in range(len(prefix_set)):
                mc = prefix_set[i]
                v = value[i]
                if (v == ""): v = "0"
                mc.eid.instance_id = int(v)
                mc.group.instance_id = int(v)
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for i in range(len(prefix_set)):
                mc = prefix_set[i]
                v = value[i]
                if (v != ""): mc.eid.store_prefix(v)
            #endfor
        #endif
        if (kw == "group-prefix"):
            for i in range(len(prefix_set)):
                mc = prefix_set[i]
                v = value[i]
                if (v != ""): mc.group.store_prefix(v)
            #endfor
        #endif
        if (kw == "send-map-request"):
            for i in range(len(prefix_set)):
                mc = prefix_set[i]
                v = value[i]
                if (v == "yes"): mc.action = lisp.LISP_SEND_MAP_REQUEST_ACTION
            #endfor
        #endif
        if (kw == "subscribe-request"):
            for i in range(len(prefix_set)):
                mc = prefix_set[i]
                v = value[i]
                if (v == "yes"): mc.action = lisp.LISP_SEND_PUBSUB_ACTION
            #endfor
        #endif
        if (kw == "rle-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): 
                    rloc.rle_name = v
                    if (v in lisp.lisp_rle_list):
                        rloc.rle = lisp.lisp_rle_list[v]
                    #endif
                #endif
            #endfor
        #endif
        if (kw == "elp-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): 
                    rloc.elp_name = v
                    if (v in lisp.lisp_elp_list):
                        rloc.elp = lisp.lisp_elp_list[v]
                        rloc.elp.select_elp_node()
                    #endif
                #endif
            #endfor
        #endif
        if (kw == "rloc-record-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rloc_name = v
            #endfor
        #endif

        if (kw == "priority"): 
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.weight = int(v)
            #endfor
        #endif
        if (kw == "address"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rloc.store_address(v)
            #endfor
        #endif
    #endfor

    #
    # Store in map-cache data structures. If multiple prefixes were configured,
    #  we need a different physical set of RLOCs.
    #
    for mc in prefix_set:
        mc.rloc_set = rloc_set
        mc.build_best_rloc_set()
        mc.add_cache()
        rloc_set = copy.deepcopy(rloc_set)
    #endfor
    return
#enddef

#
# lisp_display_map_cache
#
# Callback from class lisp_cache.walk_cache().
#
def lisp_display_map_cache(mc, output):
    ts = lisp.lisp_print_elapsed(mc.uptime)
    eid_str= mc.print_eid_tuple()
    hover = "Recent Sources: "
    hover += "none\n" if (mc.recent_sources == {}) else "\n"
    for s in mc.recent_sources:
        t = mc.recent_sources[s]
        hover += "  " + s + ": " + lisp.lisp_print_elapsed(t) + "\n"
    #endfor
    eid_str = lisp.lisp_span(eid_str, hover[0:-1])
    action = mc.action

    #
    # If mapping source is None, that means we are the ITR and received the
    # map-notify from the lisp-etr process. Otherwise, we have the address
    # of the map-server we can display.
    #
    source = mc.mapping_source
    if (source == None):
        source = "map-notify"
    else:
        source = "static" if source.is_null() else \
            source.print_address_no_iid()
    #endif

    if (mc.checkpoint_entry): source = "checkpoint"
    if (mc.gleaned): source = "gleaned"
    ttl = mc.print_ttl()

    action = "encapsulate" if action == lisp.LISP_NO_ACTION else \
        lisp.lisp_map_reply_action_string[action]

    if (len(mc.rloc_set) == 0):
        stats = mc.stats.get_stats(True, True)
        output += lisp_table_row(eid_str, ts + "<br>" + ttl, "--", source, 
            stats, action, "--")
        return([True, output])
    #endif

    for rloc in mc.rloc_set: 
        rloc_str = ""
        if (rloc.rloc_exists()):
            if (rloc.rloc.is_null() == False):
                rloc_str += rloc.rloc.print_address_no_iid() + "<br>"
                hover = ""
                enc = lisp.lisp_nonce_echoing and rloc.echo_nonce_capable
                if (lisp.lisp_rloc_probing):
                    hover += rloc.print_rloc_probe_state(enc)
                #endif
                if (enc):
                    en = lisp.lisp_get_echo_nonce(rloc.rloc, None)
                    if (en): hover += en.print_echo_nonce()
                #endif
                if (hover != ""): rloc_str = lisp.lisp_span(rloc_str, hover)
            #endif
        #endif

        if (rloc.translated_port != 0):
            rloc_str += "encap-port: {}<br>".format(rloc.translated_port)
        #endif

        if (rloc.rloc_name):
            rloc_str += "rloc-name: {}<br>".format(lisp.blue(rloc.rloc_name, 
                True))
        #endif

        if (rloc.geo): 
            rloc_str += "geo: {}<br>".format(rloc.geo.print_geo_url())
        #endif
        if (rloc.elp): 
            elp = rloc.elp.print_elp(True)
            rloc_str += "elp: {}<br>".format(elp)
        #endif
        if (rloc.rle): 
            rle = rloc.rle.print_rle(True, True)
            rloc_str += "rle: {}<br>".format(rle)
        #endif
        if (rloc.json):
            if (lisp.lisp_is_json_telemetry(rloc.json.json_string) == None):
                json = "json: { ... }<br>"
                rloc_str += lisp.lisp_span(json, rloc.json.print_json(False))
            #endif
        #endif

        #
        # Calculate rate.
        #
        stats = rloc.stats.get_stats(True, True)

        #
        # Print RLOC-probe info. May be one per next-hop for this RLOC-record.
        #
        state = ""
        r = rloc
        while (r != None):
            spaces = ""
            if (r.rloc_next_hop != None):
                d, n = r.rloc_next_hop
                state += "next-hop {}({}), ".format(n, d)
                spaces = lisp.lisp_space(2)
            #endif

            state_change = lisp.lisp_print_elapsed(r.last_state_change)
            if (state_change == "never"):
                state_change = lisp.lisp_print_elapsed(r.uptime)
            #endif
            s = r.print_state()
            if (r.unreach_state() or r.no_echoed_nonce_state()): 
                s = lisp.red(s, True)
            #endif
            state += s + " since " + state_change

            if (lisp.lisp_rloc_probing):
                rtt = r.print_rloc_probe_rtt()
                if (rtt != "none"):
                    state += "<br>{}rtt: {}, hops: {}, latency: {}".format( \
                        spaces, rtt, r.print_rloc_probe_hops(),
                        r.print_rloc_probe_latency())
                #endif
            #endif

            r = r.next_rloc
            if (r == None): break
            state += "<br>"
        #endwhile

        if (action == "encapsulate"):
            port = lisp.LISP_DATA_PORT
            if (lisp.lisp_i_am_rtr and rloc.translated_port != 0):
                port = rloc.translated_port
            #endif
                
            addr_str = rloc.rloc.print_address_no_iid() + ":" + str(port)
            if (addr_str in lisp.lisp_crypto_keys_by_rloc_encap):
                key = lisp.lisp_crypto_keys_by_rloc_encap[addr_str][1]
                if (key != None and key.shared_key != None): 
                    action = "encap-crypto-" + key.cipher_suite_string
                #endif
            #endif
        #endif

        output += lisp_table_row(eid_str, ts + "<br>" + ttl, rloc_str, source,
           stats, state + "<br>" + action, 
           str(rloc.priority) + "/" +  str(rloc.weight) + "<br>" + \
           str(rloc.mpriority) + "/" +  str(rloc.mweight))

        if (eid_str != ""): eid_str = ""
        if (ts != ""): ts, ttl, source = ("", "", "")
    #endfor
    return([True, output])
#enddef

#
# lisp_walk_map_cache
#
# Walk the entries in the lisp_map_cache(). And then subsequently walk the
# entries in lisp_mapping.source_cache().
#
def lisp_walk_map_cache(mc, output):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): return(lisp_display_map_cache(mc, output))

    if (mc.source_cache == None): return([True, output])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    output = mc.source_cache.walk_cache(lisp_display_map_cache, output)
    return([True, output])
#enddef

#
# lisp_show_myrlocs
#
# Show the local acquired RLOCs in the ITR, RTR, and ETR display.
#
def lisp_show_myrlocs(output):
    if (lisp.lisp_myrlocs[2] == None):
        output += "No local RLOCs found"
    else:
        device = lisp.lisp_print_cour(lisp.lisp_myrlocs[2])
        v4 = lisp.lisp_myrlocs[0].print_address_no_iid() if \
            lisp.lisp_myrlocs[0] != None else "not found"
        v4 = lisp.lisp_print_cour(v4)
        flag = "-f inet" if lisp.lisp_is_macos() else "-4"
        routes = getoutput("netstat -rn {}".format(flag))
        v4 = lisp.lisp_span(v4, routes)

        v6 = lisp.lisp_myrlocs[1].print_address_no_iid() if \
            lisp.lisp_myrlocs[1] != None else "not found"
        v6 = lisp.lisp_print_cour(v6)
        flag = "-f inet6" if lisp.lisp_is_macos() else "-6"
        routes = getoutput("netstat -rn {}".format(flag))
        v6 = lisp.lisp_span(v6, routes)

        line = "<i>Local RLOCs found on interface </i>{}<i>, " + \
            "IPv4: </i>{}<i>, IPv6: </i>{}"
        output += lisp.lisp_print_sans(line).format(device, v4, v6)
    #endif
    output += "<br>"
    return(output)
#enddef

#
# lisp_display_nat_info
#
# Display the lisp.lisp_nat_state_info table.
#
def lisp_display_nat_info(output, dc, dodns):
    length = len(lisp.lisp_nat_state_info)
    if (length == 0): return(output)

    hover = "{} entries in the NAT-traversal port table".format(length)
    title = lisp.lisp_span("NAT-Traversed xTR Information:", hover)

    if (dodns):
        output += lisp_table_header(title, "xTR Hostname",
            "Translated<br>Address", "Translated<br>{} Port".format(dc),
            "Last<br>Info-Request", "NAT DNS Name")
    else:
        output += lisp_table_header(title, "xTR Hostname",
            "Translated<br>Address", "Translated<br>{} Port".format(dc),
            "Last<br>Info-Request")
    #endif

    for xtr_array in list(lisp.lisp_nat_state_info.values()):
        for nat_info in xtr_array:
            addr = nat_info.address
            uptime = nat_info.uptime
            hostname = nat_info.hostname
            port = nat_info.port

            if (nat_info.timed_out()):
                uptime = lisp.red(lisp.lisp_print_elapsed(uptime), True)
            else:
                uptime = lisp.lisp_print_elapsed(uptime)
            #endif

            if (dodns):
                try:
                    nat = socket.gethostbyaddr(addr)[0]
                except:
                    nat = "?"
                #endtry
                output += lisp_table_row(hostname, addr, port, uptime, nat)
            else:
                output += lisp_table_row(hostname, addr, port, uptime)
            #endif
        #endfor
    #endfor

    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_itr_rtr_show_command
#
# Display state in an ITR or RTR.
#
def lisp_itr_rtr_show_command(parameter, itr_or_rtr, lisp_threads, dns=False):

    #
    # Do lookup if there is a parameter supplied.
    #
    if (parameter != ""): 
        return(lisp_show_map_cache_lookup(parameter))
    #endif

    output = ""

    #
    # Show local found RLOCs.
    #
    output = lisp_show_myrlocs(output)

    #
    # Show decapsulation stats.
    #
    if (itr_or_rtr == "RTR"):
        output = lisp_show_decap_stats(output, itr_or_rtr)
    #endif

    #
    # Show data-plane stats.
    #
    if (len(lisp_threads) > 1):
        s = []
        for i in range(len(lisp_threads)):
            t = lisp_threads[i]
            s.append("{} Input Stats<br>queue-size: {}".format(t.thread_name, 
                t.input_queue.qsize()))
        #endfor
        output += lisp_table_header("LISP-RTR Forwarding Stats:", *s)
                                               
        s = []
        for i in range(len(lisp_threads)):
            t = lisp_threads[i]
            s.append(t.input_stats.get_stats(False, True))
        #endfor
        output += lisp_table_row(*s)
        output += lisp_table_footer()
    #endif

    dns_suffix = lisp.lisp_decent_dns_suffix
    if (dns_suffix == None):
        dns_suffix = ":"
    else:
        dns_suffix = "&nbsp;(dns-suffix '{}'):".format(dns_suffix)
    #endif

    #
    # Show map-resolvers configured.
    #
    hover = "{} map-resolvers configured".format( \
        len(lisp.lisp_map_resolvers_list))
    title = "LISP-{} Configured Map-Resolvers{}".format(itr_or_rtr, dns_suffix)
    title = lisp.lisp_span(title, hover)

    output += lisp_table_header(title, "Map-Resolver", "Last Used", 
        "Map-Requests<br>Sent", "Negative Map-Replies<br>Received", 
        "Last Negative<br>Map-Reply", "Average RTT")

    for mr in list(lisp.lisp_map_resolvers_list.values()):
        mr.resolve_dns_name()
        mr_name = "" if mr.mr_name == "all" else mr.mr_name + "<br>"
        addr_str = mr_name + mr.map_resolver.print_address_no_iid()
        if (mr.dns_name): addr_str += "<br>" + mr.dns_name

        ts = lisp.lisp_print_elapsed(mr.last_used)
        lnmr = lisp.lisp_print_elapsed(mr.last_reply)
        avg_rtt = 0 if mr.neg_map_replies_received == 0 else \
            float(old_div(mr.total_rtt, mr.neg_map_replies_received))
        avg_rtt = str(round(avg_rtt, 3)) + " ms"

        output += lisp_table_row(addr_str, ts, mr.map_requests_sent,
            mr.neg_map_replies_received, lnmr, avg_rtt)
    #endfor
    output += lisp_table_footer()

    #
    # Show database-mappings configured.
    #
    if (itr_or_rtr == "ITR"): output = lisp_show_db_list("ITR", output)

    #
    # Do specific map-cache lookup.
    #
    banner = "<br>Enter EID for Map-Cache lookup:"

    input_rectangle = \
        lisp.lisp_eid_help_hover('<input type="text" name="eid" />')
    i_or_r = itr_or_rtr.lower()

    banner = '''
         <form action="/lisp/show/{}/map-cache/lookup" method="post">
         <font size="3"><i>{}</i> {}
         <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></form>
    '''.format(i_or_r, lisp.lisp_print_sans(banner), input_rectangle)

    rloc_state_link = '<a href="/lisp/show/{}/rloc-probing">RLOC State</a>'. \
        format(i_or_r)
    keys = '<a href="/lisp/show/{}/keys"><br>RLOC Keys</a>'.format(i_or_r)

    #
    # Create link to /lisp/show/lisp-xtr if lisp-xtr is running.
    #
    ztr = os.path.exists("./show-ztr")
    mc_str = "Map-Cache"
    if (os.getenv("LISP_RUN_LISP_XTR") != None or ztr):
        mc_str = '<a href="/lisp/show/lisp-xtr">Map-Cache</a>'
    #endif

    #
    # Show map-cache.
    #
    hover = "{} entries in the map-cache".format( \
        lisp.lisp_map_cache.cache_size())
    title = "LISP-{} {}:{}".format(itr_or_rtr, mc_str, lisp.lisp_space(4))
    title = lisp.lisp_span(title, hover)

    #
    # Put a 'clear cache" button in if superuser. That means that the clear
    # button shows up but the clear can't be done if you are not superuser.
    #
    title += lisp.lisp_button("clear cache", 
        "/lisp/clear/{}/map-cache".format(itr_or_rtr.lower()))
    title += banner


    output += lisp_table_header(title,  "EID-Prefix or (S,G)", 
        "Uptime<br>TTL", "RLOC Record" + keys, "Map-Reply Source", 
        "RLOC Send Stats", rloc_state_link + "<br>RLOC Action",
        "Unicast Priority/Weight<br>Multicast Priority/Weight")

    output = lisp.lisp_map_cache.walk_cache(lisp_walk_map_cache, output)
    output += lisp_table_footer()

    #
    # Show ELP configuration, if it exists.
    #
    if (len(lisp.lisp_elp_list) != 0): output = lisp_show_elp_list(output)

    #
    # Show RLE configuration, if it exists.
    #
    if (len(lisp.lisp_rle_list) != 0): output = lisp_show_rle_list(output)

    #
    # Show JSON configuration, if it exists.
    #
    if (len(lisp.lisp_json_list) != 0): output = lisp_show_json_list(output)

    #
    # Show NAT-traversal lisp_nat_state_info table for an RTR.
    #
    if (itr_or_rtr == "RTR"):
        output = lisp_display_nat_info(output, "Data", dns)
    #endif

    #
    # Return output so header and footer for page can be added.
    #
    return(output)
#enddef

#
# lisp_itr_rtr_show_rloc_probe_command
#
# Display the contents of the RLOC-probe list via the web interface.
#
def lisp_itr_rtr_show_rloc_probe_command(itr_or_rtr):
    title = "LISP-{} RLOC-Probe Information:".format(itr_or_rtr)
    output = lisp_table_header(title, "RLOC Key State", "RLOC-Probe State")

    for rlocs in list(lisp.lisp_rloc_probe_list.values()):
        eid_str = ""
        for r, e, g in rlocs:
            ee = lisp.green(lisp.lisp_print_eid_tuple(e, g), True)
            eid_str += lisp.lisp_print_cour(ee) + "<br>"
        #endfor
        eid_str = ", EIDs ({}):<br>".format(len(rlocs)) + eid_str
            
        r, e, g = rlocs[0]

        #
        # Build column 1.
        #
        n = lisp.lisp_hex_string(r.last_rloc_probe_nonce)
        if (r.translated_rloc.not_set()):
            rs = r.rloc.print_address_no_iid()
        else:
            rs = "{}{}{}".format(r.translated_rloc.print_address_no_iid(),
                lisp.bold(":", True), r.translated_port)
        #endif
        rs = lisp.bold(lisp.lisp_print_cour(rs), True)
        rn = r.rloc_name
        if (rn != None):
            rn = lisp.bold(rn, True)
            rs += ", {}".format(lisp.lisp_print_cour(lisp.blue(rn, True)))
        #endif
        state = r.print_state()
        if (r.up_state() == False): state = lisp.red(r.print_state(), True)
        rs = "RLOC " + rs + ", {}".format(state)
            
        col1 = rs + eid_str

        #
        # If a multicast RLOC, print out all ETRs that have replied.
        #
        probe_list = [r]
        if (r.multicast_rloc_probe_list != {}):
            probe_list += list(r.multicast_rloc_probe_list.values())
        #endif

        #
        # Build column 2.
        #
        col2 = ""
        for r in probe_list:
            if (len(probe_list) != 1):
                rs = r.rloc.print_address_no_iid()
                rs = lisp.bold(lisp.lisp_print_cour(rs), True)
                if (probe_list.index(r) != 0): col2 += "<br><br>"
                if (r.rloc.is_multicast_address()):
                    col2 += "RLOC {}:<br>".format(rs)
                else:
                    rn = ", " + r.rloc_name if r.rloc_name != None else ""
                    col2 += "mRLOC {}{}:<br>".format(rs, rn)
                #endif
            #endif

            req = lisp.lisp_print_elapsed(r.last_rloc_probe)
            req = lisp.lisp_print_cour(req)
            rep = lisp.lisp_print_elapsed(r.last_rloc_probe_reply)
            rep = lisp.lisp_print_cour(rep)
            n = lisp.lisp_hex_string(r.last_rloc_probe_nonce)
            n = lisp.lisp_print_cour("0x" + n)
            col2 += ("Last probe-request sent: {}, " + \
                "last probe-reply received: {}, nonce: {}<br>").format(req,
                rep, n)

            rtt = r.print_recent_rloc_probe_rtts()
            rtt = lisp.lisp_print_cour(rtt)
            hops = r.print_recent_rloc_probe_hops()
            hops = lisp.lisp_print_cour(hops)
            lat = r.print_recent_rloc_probe_latencies()
            lat = lisp.lisp_print_cour(lat)
            h = r.print_rloc_probe_hops()
            h = lisp.lisp_print_cour(h)
            l = r.print_rloc_probe_latency()
            l = lisp.lisp_print_cour(l)
            r = r.print_rloc_probe_rtt()
            r = lisp.lisp_print_cour(r)
            col2 += ("Telemetry: rtt: {}, hops: {}, latency: {}<br>" + \
                "recent-rtts: {}, recent-hops: {}, recent-latencies: {}"). \
                format(r, h, l, rtt, hops, lat)
        #endfor

        #
        # Print 2-column row.
        #
        output += lisp_table_row(col1, col2)
    #endfor

    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_xtr_command
#
# Process xtr-parameters subclause commands.
#
def lisp_xtr_command(kv_pair):

    #
    # If env variable LISP_RUN_LISP_XTR is defined turn, configure "ipc-
    # data-plane = yes".
    #
    if (os.getenv("LISP_RUN_LISP_XTR") != None):
        kv_pair["ipc-data-plane"] = ["yes"]
    #endif

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw][0]
        if (kw == "rloc-probing"):
            lisp.lisp_rloc_probing = (value == "yes")
            if (value == "no"): lisp.lisp_rloc_probe_list = {}
        #endif
        if (kw == "nonce-echoing"):
            lisp.lisp_nonce_echoing = (value == "yes")
            if (value == "no"): lisp.lisp_nonce_echo_list = {}
        #endif
        if (kw == "data-plane-security"):
            lisp.lisp_data_plane_security = (value == "yes")
            if (value == "no"): 
                lisp.lisp_crypto_keys_by_nonce = {}
                lisp.lisp_crypto_keys_by_rloc_encap = {}
                lisp.lisp_crypto_keys_by_rloc_decap = {}
            #endif
        #endif
        if (kw == "data-plane-logging"):
            lisp.lisp_data_plane_logging = (value == "yes")
        #endif
        if (kw == "frame-logging"):
            lisp.lisp_frame_logging = (value == "yes")
        #endif
        if (kw == "flow-logging"):
            lisp.lisp_flow_logging = (value == "yes")
            if (value == "yes"): os.system("touch ./log-flows")
        #endif
        if (kw == "nat-traversal"):
            lisp.lisp_nat_traversal = (value == "yes")
        #endif
        if (kw == "decentralized-nat"):
            lisp.lisp_decent_nat = (value == "yes")
        #endif
        if (kw == "program-hardware"):
            lisp.lisp_program_hardware = (value == "yes")
        #endif
        if (kw == "checkpoint-map-cache"):
            lisp.lisp_checkpoint_map_cache = (value == "yes")
            cf = lisp.lisp_checkpoint_filename
            if (value == "no" and os.path.exists(cf)):
                os.system("rm {}".format(cf))
            #endif
        #endif
        if (kw == "ipc-data-plane"):
            turn_onoff = (value == "yes")
            if (turn_onoff and lisp.lisp_ipc_data_plane == False):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                lisp.lisp_ipc_dp_socket = s
            #endif
            if (turn_onoff == False and lisp.lisp_ipc_data_plane):
                lisp.lisp_ipc_dp_socket.close()
                lisp.lisp_ipc_dp_socket = None
            #endif
            lisp.lisp_ipc_data_plane = turn_onoff
        #endif
        if (kw == "decentralized-push-xtr"):
            lisp.lisp_decent_push_configured = (value == "yes")
        #endif
        if (kw == "decentralized-pull-xtr-modulus"):
            lisp.lisp_decent_modulus = int(value)
        #endif
        if (kw == "decentralized-pull-xtr-dns-suffix"):
            lisp.lisp_decent_dns_suffix = value
        #endif
        if (kw == "register-reachable-rtrs"):
            lisp.lisp_register_all_rtrs = (value == "no")
        #endif
    #endfor
    return
#enddef

#
# lisp_show_json_list
#
# Put the JSON list in an output buffer (in html format).
#
def lisp_show_json_list(output):

    title = "Configured JSON Entries:"
    output += lisp_table_header(title, "JSON Name", "JSON String")

    json_list = sorted(lisp.lisp_json_list)
    for json_name in json_list:
        json = lisp.lisp_json_list[json_name]
        json_string = lisp.lisp_print_cour(json.print_json(True))
        output += lisp_table_row(json_name, json_string)
    #endfor
    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_show_rle_list
#
# Put the RLE list in an output buffer (in html format).
#
def lisp_show_rle_list(output):

    title = "Configured Replication List Entries (RLEs):"
    output += lisp_table_header(title, "RLE Name", "RLE Nodes")

    rle_list = sorted(lisp.lisp_rle_list)
    for rle_name in rle_list:
        rle = lisp.lisp_rle_list[rle_name]
        output += lisp_table_row(rle_name, rle.print_rle(True, True))
    #endfor
    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_show_elp_list
#
# Put the ELP list in an output buffer (in html format).
#
def lisp_show_elp_list(output):
    title = "Configured Explicit Locator Paths (ELPs):"
    output += lisp_table_header(title, "ELP Name", "ELP Nodes")

    elp_list = sorted(lisp.lisp_elp_list)
    for elp_name in elp_list:
        elp = lisp.lisp_elp_list[elp_name]
        output += lisp_table_row(elp_name, elp.print_elp(False))
    #endfor
    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_geo_command
# 
# Process "lisp geo-coordinates" command.
#
def lisp_geo_command(kv_pair):

    #
    # Get geo name. If none supplied, return.
    #
    if ("geo-name" not in kv_pair): return
    geo_name = kv_pair["geo-name"]
    geo = lisp.lisp_geo(geo_name)

    #
    # Get coordinates, if non supplied reutrn.
    #
    if ("geo-tag" not in kv_pair): return

    #
    # Remove leading space that the command will give us.
    #
    geo_tag = kv_pair["geo-tag"][1::]
    if (geo.parse_geo_string(geo_tag) == False): return

    #
    # Put in list by name.
    #
    lisp.lisp_geo_list[geo_name] = geo
    return
#enddef

#
# lisp_elp_command
# 
# Process "lisp explicit-locator-path" command.
#
def lisp_elp_command(kv_pair):

    elp = None
    elp_nodes = []
    if ("address" in kv_pair):
        for i in range(len(kv_pair["address"])):
            elp_node = lisp.lisp_elp_node()
            elp_nodes.append(elp_node)
        #endfor
    #endif

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]

        if (kw == "elp-name"):
            elp = lisp.lisp_elp(value)
            continue
        #endif

        for node in elp_nodes: 
            index = elp_nodes.index(node)
            if (index >= len(value)): index = len(value) - 1
            v = value[index]
            if (kw == "probe"): node.probe = (v == "yes")
            if (kw == "strict"): node.strict = (v == "yes")
            if (kw == "eid"): node.eid = (v == "yes")
            if (kw == "address"): node.address.store_address(v)
        #endif
    #endfor

    #
    # elp-name parameter was not specified. A name is required.
    #
    if (elp == None): return

    #
    # Put ELP in list by name.
    #
    elp.elp_nodes = elp_nodes
    lisp.lisp_elp_list[elp.elp_name] = elp
    return
#enddef

#
# lisp_rle_command
# 
# Process "lisp replication-list-entry" command.
#
def lisp_rle_command(kv_pair):

    rle = None
    rle_nodes = []
    if ("address"in kv_pair):
        for i in range(len(kv_pair["address"])):
            rle_node = lisp.lisp_rle_node()
            rle_nodes.append(rle_node)
        #endfor
    #endif

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]

        if (kw == "rle-name"):
            rle = lisp.lisp_rle(value)
            continue
        #endif

        for node in rle_nodes: 
            index = rle_nodes.index(node)
            if (index >= len(value)): index = len(value) - 1
            v = value[index]
            if (kw == "level"): 
                if (v == ""): v = "0"
                node.level = int(v)
            #endif
            if (kw == "address"): node.address.store_address(v)
        #endif
    #endfor

    #
    # rle-name parameter was not specified. A name is required.
    #
    if (rle == None): return

    #
    # Put RLE in list by name.
    #
    rle.rle_nodes = rle_nodes
    rle.build_forwarding_list()
    lisp.lisp_rle_list[rle.rle_name] = rle
    return
#enddef

#
# lisp_json_command
# 
# Process "lisp json" command.
#
def lisp_json_command(kv_pair):

    try:
        json_name = kv_pair["json-name"]
        json_string = kv_pair["json-string"]
    except:
        return
    #endtry

    json = lisp.lisp_json(json_name, json_string)
    json.add()
    return
#enddef

#
# lisp_get_lookup_string
#
# From a web interface bar, get an address string that can be of the following
# form:
#     <address>
#     [<iid>]<address>
#     <address>-><group>
#     [<iid>]<address>->[<iid>]<group>
#
def lisp_get_lookup_string(input_str):

    #
    # Check if "S->G" was supplied.
    #
    eid_str = input_str
    group_str = None
    if (input_str.find("->") != -1):
        sg = input_str.split("->")
        eid_str = sg[0]
        group_str = sg[1]
    #endif

    eid = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    group = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)

    #
    # If prefix supplied we are doing an exact match lookup.
    #
    address = eid_str.split("/")
    if (len(address) == 1):
        eid.store_address(address[0])
        eid_exact = False
    else:
        eid.store_prefix(eid_str)
        eid_exact = True
    #endif

    group_exact = eid_exact
    if (group_str):
        address = group_str.split("/")
        if (len(address) == 1):
            group.store_address(address[0])
            group_exact = False
        else:
            group.store_prefix(eid_str)
            group_exact = True
        #endif
    #endif
    return([eid, eid_exact, group, group_exact])
#enddef

#
# lisp_show_map_cache_lookup
#
# Do lookup and return results to the lisp-core process.
#
def lisp_show_map_cache_lookup(eid_str):
    eid, eid_exact, group, group_exact = lisp_get_lookup_string(eid_str)

    output = "<br>"

    lookup_key = eid if (group.is_null()) else group
    lookup_exact = eid_exact if (group.is_null()) else group_exact

    entry = lisp.lisp_map_cache.lookup_cache(lookup_key, lookup_exact)
    if (entry == None):
        output += "{} {}".format(lisp.lisp_print_sans("Lookup not found for"),
            lisp.lisp_print_cour(eid_str))
    else:
        if (lookup_key == group):
            sentry = entry.lookup_source_cache(eid, eid_exact)
            if (sentry): entry = sentry
        #endif

        ts = lisp.lisp_print_elapsed(entry.uptime)
        output += "{} {} {} {} {} {} {}".format( \
            lisp.lisp_print_sans("Exact" if eid_exact else "Longest"),
            lisp.lisp_print_sans("match lookup for"),
            lisp.lisp_print_cour(eid_str),
            lisp.lisp_print_sans("found"),
            lisp.lisp_print_cour(entry.print_eid_tuple()),
            lisp.lisp_print_sans("with uptime"),
            lisp.lisp_print_cour(ts))
    #endif
    output += "<br>"
    return(output)
#enddef

#
# lisp_get_clause_for_api
#
# Find command in configuration file and return as a dictionary array. If
# not found return { "?" : "?" }.
#
def lisp_get_clause_for_api(command):
    config = open("./lisp.config", "r")
    clause = { command : [] }
    subclause = {}
    all_commands = []

    indent = 0
    capture = False
    for line in config:
        if (lisp_end_file(line)): break
        if (lisp_comment(line)): continue

        #
        # If we found command, start capturing each subsequent line until
        # we reach the final "}". Note there can be many "}" since we allow
        # nesting.
        #
        if (line.find(command + " {") != -1): 
            indent += 1
            capture = True
            continue
        #endif
        if (capture == False): continue

        if (lisp_begin_clause(line)):
            indent += 1
            subcommand = line.replace(" ", "")
            subcommand = subcommand.replace("\t", "")
            subcommand = subcommand.replace("\n", "")
            subcommand = subcommand.replace("{", "")
            subclause = { subcommand : {} }
            continue
        #endif

        #
        # Go find more commands if what was requested was a command that
        # can appear multiple times.
        #
        if (lisp_end_clause(line)): 
            indent -= 1
            if (indent): 
                clause[command].append(subclause)
                subclause = {}
                continue
            #endif
            all_commands.append(clause)
            clause = { command : [] }
            capture = False
            continue
        #endif

        line = line.replace(" ", "")
        line = line.replace("\t", "")
        line = line.replace("\n", "")
        line = line.replace("{", "")
        line = line.split("=")
        value = "" if len(line) == 1 else line[1]
        key = line[0]

        if (len(subclause) == 0):
            clause[command].append({key : value})
        else:
            subclause[subcommand][key] = value
        #endif
    #endfor

    config.close()

    if (len(all_commands) == 0):
        all_commands = [{ "?" : [{"?" : "not-found"}] }]
    #endif
    return(all_commands)
#enddef

#
# lisp_duplicate_command_clause
#
# Check to see if command clause already is in the lisp.config file.
#
def lisp_duplicate_command_clause(command, clause):
    f = open("./lisp.config", "r")

    clause = command + " {\n" + clause
    for line in f:
        if (lisp_begin_clause(line) == False): continue
        if (line.find(command) == -1): continue

        gather = line
        for line in f:
            gather += line
            if (line[0] != "}"): continue
            if (gather != clause): break
            f.close()
            return(True)
        #endfor
        if (lisp_end_file(line)): break
    #endfor

    f.close()
    return(False)
#enddef

#
# lisp_put_clause_for_api
#
# Take dictionary array and store for config clause in database.
#
def lisp_put_clause_for_api(data):

    #
    # Validate command by looking at lisp_commands[].
    #
    command = list(data.keys())[0]
    if (command not in list(lisp_commands.keys())): 
        return([{ command : [{"?" : "add/replace"}] }])
    #endif

    replace_only_command = \
        (command in ["lisp enable", "lisp debug", "lisp xtr-parameters"])

    #
    # If we are going to add a command clause, if it doesn't exist, add it
    # before end of file. If it exists but is a different instance, insert
    # before other ones.
    #
    append = False
    if (replace_only_command == False):
        append = True
        out = getoutput("egrep '{}' ./lisp.config".format(command))
        out = out.split("\n")
        for line in out: 
            if (line[0:len(command)] == command): append = False
        #endfor
    #endif

    #
    # Build command syntax from dictionary array.
    #
    parms = data[command]
    parms = lisp_unicode_to_ascii(parms)
    clause = command + " {\n" if append else ""

    #
    # The parameter list can take the following structure:
    #
    #  { keyi : valuei, ... keyn : valuen }
    #  [ {keyi : valuei, ... }, {keyi : valuei, ... } ]
    #  [ {keyi : valuei, keyj : { ... } ... }, ... ]
    #
    for parm in parms:
        if (type(parms) == dict):
            value = parms[parm]
            if (type(value) == dict): value = json_dumps(value)
            clause += "    " + parm + " = " + value + "\n"
            continue
        #endif

        for key in parm:
            if (type(parm) == dict):
                keyword = key
                value = parm[key]
            #endif
            if (type(parm) == list):
                keyword = list(key.keys())[0]
                value = list(key.values())[0]
            #endif

            if (type(value) != dict):
                clause += "    " + key + " = " + parm[key] + "\n"
                continue
            #endif

            #
            # Insert indentation level.
            #
            clause += "    " + keyword + " {\n"
            for k in value: clause += "        " + k + " = " + value[k] + "\n"
            clause += "    }\n"
        #endfor
    #endfor
    clause += "}\n"

    # 
    # Check if entire command clause is already in lisp.config file.
    #
    if (lisp_duplicate_command_clause(command, clause)): 
        return([{ command : [{"!" : "duplicate"}] }])
    #endif

    read_file = "./lisp.config"
    write_file = read_file + ".temp"

    rf = open(read_file, "r")
    wf = open(write_file, "w")

    found_command = False
    skip = False
    for line in rf:
        if (skip):
            if (lisp_end_clause(line) == False): continue
            skip = False
            continue
        #endif

        #
        # We are inserting or maybe replacing an existing clause.
        #
        if (found_command == False and lisp_begin_clause(line) and 
            line[0:len(command)] == command):
            if (replace_only_command == False):
                wf.write(line)
                for nline in clause: wf.write(nline)
                found_command = True
            #endif
        #endif

        #
        # Exit if we got to end of file.
        #
        if (lisp_end_file(line)): 
            if (append): 
                for nline in clause: wf.write(nline)
            #endif
            wf.write(line)
            found_command = True
            break
        #endif

        #
        # Copy line from old file to new file.
        #
        wf.write(line)

        #
        # Here we do a replace if the command is a single instance and can
        # be replaced. 
        #
        if (lisp_begin_clause(line) and line[0:len(command)] == command):
            if (replace_only_command):
                skip = True
                for nline in clause: wf.write(nline)
            #endif
        #endif
    #endfor

    rf.close()
    wf.close()

    os.system("cp {} {}".format(write_file, read_file))
    os.system("rm {}".format(write_file))
    return([{ command : [{"!" : "add/replace"}] }])
#enddef

#
# lisp_remove_clause_for_api
#
# Take dictionary array and remove configruation clause from configuration
# file.
#
def lisp_remove_clause_for_api(data):

    #
    # Validate command by looking at lisp_commands[].
    #
    command = list(data.keys())[0]
    if (command not in list(lisp_commands.keys())): 
        return([{ command : [{"?" : "delete"}] }])
    #endif

    #
    # Build command syntax from dictionary array.
    #
    parms = data[command]
    parms = lisp_unicode_to_ascii(parms)

    #
    # Setup subcommand to match on so we know what clause to remove.
    #
    subcommands = []
    key = list(parms.keys())[0]
    value = parms[key]

    if (type(value) == dict):
        for key in list(value.keys()):
            command_value = value[key]
            subcommands.append(key + " = " + command_value)
        #endfor
    else:
        subcommands.append(key + " = " + value)
    #endif

    #
    # Do special case. If this is a delete for a user-account, do not allow
    # the superuser account to be removed.
    #
    if (command == "lisp user-account"):
        clause = getoutput("egrep -A4 '{}' ./lisp.config".format( \
            subcommands[0]))

        if (clause.find("super-user = yes") != -1):
            return([{ "lisp user-account" : [{"?" : "found-superuser"}] }])
        #endif
    #endif

    #
    # If we find a match from the single parameter supplied by the API,
    # then we can break out of loop below.
    #
    partial_match = ("lisp user-account", "lisp site", "lisp map-server",
        "lisp policy")

    read_file = "./lisp.config"
    rf = open(read_file, "r")

    found = False
    occurence = 0
    for line in rf:
        if (line.find(command) == -1): continue
        occurence += 1

        for line in rf:
            if (lisp_begin_clause(line)): continue
            stop = (lisp_end_clause(line) and found)
            if (stop): break

            match_line = line.replace(" ", "")
            match_line = match_line.replace("\n", "")
            match_line = match_line.replace("=", " = ")

            if (match_line not in subcommands): 
                found = False
                if (len(subcommands) > 1): break
                continue
            #endif
            found = True

            stop = (command in partial_match)
            if (stop): break
        #endfor

        if (stop): break
    #endfor

    rf.close()

    if (not found):
        return([{ command : [{"?" : "not-found"}] }])
    #endif

    rf = open(read_file, "r")

    write_file = read_file + ".temp"
    wf = open(write_file, "w")

    #
    # Now remove the clause by writing all lines of the old file to the
    # new file minus the clause we found in the above loop.
    #
    found = False
    for line in rf:
        if (line.find(command) != -1): occurence -= 1
        if (occurence == 0 and not found): 
            if (line[0] == "}"): found = True
            continue
        #endif
        wf.write(line)
    #endif

    wf.close()
    rf.close()

    os.system("cp {} {}".format(write_file, read_file))
    os.system("rm {}".format(write_file))
    return([{ command : [{"!" : "delete"}] }])
#enddef

#
# lisp_u2a_walk_dict_array
#
# Convert dictionary array from unicode to ascii.  This function is needed
# we have dictionary arrays that need to be decoded as well as arrays of
# dictionary arrays that need to be decoded.
#
def lisp_u2a_walk_dict_array(adata, a_dict):
    for key in a_dict:
        if (type(a_dict[key]) == dict):
            vdata = {}
            value = a_dict[key]
            for k in value: vdata[str(k)] = str(value[k])
            adata[str(key)] = vdata
        else:
            adata[str(key)] = str(a_dict[key])
        #endif
    #endfor
    return
#enddef

#
# lisp_unicode_to_ascii
#
# Convert unicode dictionary array to ascii dictionary array.
#
def lisp_unicode_to_ascii(udata):
    was_dict = (type(udata) == dict)
    if (was_dict): udata = [ udata ]

    ascii_data = []
    for label in udata:
        adata = {}

        if (type(label) == dict):
            lisp_u2a_walk_dict_array(adata, label)
        elif (type(label) == list):
            l_array = []
            for element in label: 
                ldata = {}
                lisp_u2a_walk_dict_array(ldata, element)
                l_array.append(ldata)
            #endfor
            adata = l_array
        else:
            adata = { str(list(label.keys())[0]) : adata }
        #endif
        ascii_data.append(adata)
    #endfor

    if (was_dict): ascii_data = ascii_data[0]
    return(ascii_data)
#enddef

#
# lisp_replace_db_list
#
# Return True if lisp_mapping() database-entry exists in lisp.lisp_db_list.
# And if it does replace it with the db supplied to this function. There is
# one corner case we want to take care of here. This function also handles
# a corner case on the ETR. We do not want to register private address RLOCs
# to the mapping system or they get stuck in ITR map-caches. So if a translated
# RLOC and port exists, we copy from the old to the new db data structure.
#
def lisp_replace_db_list(db):
    index = -1
    for db_list in lisp.lisp_db_list:
        if (db.match_eid_tuple(db_list)): 
            index = lisp.lisp_db_list.index(db_list)
            break
        #endif
    #endfor
    if (index == -1): return(False)

    #
    # Check for translated RLOCs in the old db's RLOC-set. If found, copy
    # them to same "interface=<device>".
    #
    if (lisp.lisp_nat_traversal and lisp.lisp_i_am_etr):
        for rloc in db_list.rloc_set:
            if (rloc.is_rloc_translated() == False): continue
            r = db.get_rloc_by_interface(rloc.interface)
            if (r == None): continue
            r.store_translated_rloc(rloc.translated_rloc, rloc.translated_port)
            r.rloc_name = rloc.rloc_name
        #endfor
    #endif

    lisp.lisp_db_list[index] = db
    return(True)
#endddef

#
# lisp_map_server_command
#
# Store configured map-servers.
#
def lisp_map_server_command(kv_pairs):
    addresses = []
    dns_names = []
    key_id = 0
    alg_id = 0
    password = ""
    proxy_reply = False
    merge = False
    refresh = False
    want = False
    site_id = 0
    ms_name = None
    ekey_id = 0
    ekey = None

    for kw in list(kv_pairs.keys()):
        value = kv_pairs[kw]
        if (kw == "ms-name"): 
            ms_name = value[0]
        #endif
        if (kw == "address"):
            for i in range(len(value)):
                addresses.append(value[i])
            #endfor
        #endif
        if (kw == "dns-name"):
            for i in range(len(value)):
                dns_names.append(value[i])
            #endfor
        #endif
        if (kw == "authentication-type"):
            alg_id = lisp.LISP_SHA_1_96_ALG_ID if (value == "sha1") else \
                lisp.LISP_SHA_256_128_ALG_ID if (value == "sha2") else ""
        #endif
        if (kw == "authentication-key"):
            if (alg_id == 0): alg_id = lisp.LISP_SHA_256_128_ALG_ID
            auth_key = lisp.lisp_parse_auth_key(value)
            key_id = list(auth_key.keys())[0]
            password = auth_key[key_id]
        #endif
        if (kw == "proxy-reply"):
            proxy_reply = True if value == "yes" else False
        #endif
        if (kw == "merge-registrations"):
            merge = True if value == "yes" else False
        #endif
        if (kw == "refresh-registrations"):
            refresh = True if value == "yes" else False
        #endif
        if (kw == "want-map-notify"):
            want = True if value == "yes" else False
        #endif
        if (kw == "site-id"):
            site_id = int(value)
        #endif
        if (kw == "encryption-key"):
            ekey = lisp.lisp_parse_auth_key(value)
            ekey_id = list(ekey.keys())[0]
            ekey = ekey[ekey_id]
        #Endif
    #endfor

    #
    # Store internal data structure.
    #
    for addr_str in addresses:
        if (addr_str == ""): continue
        ms = lisp.lisp_ms(addr_str, None, ms_name, alg_id, key_id, password, 
            proxy_reply, merge, refresh, want, site_id, ekey_id, ekey)
    #endfor
    for name in dns_names:
        if (name == ""): continue
        ms = lisp.lisp_ms(None, name, ms_name, alg_id, key_id, password, 
            proxy_reply, merge, refresh, want, site_id, ekey_id, ekey)
    #endfor
    return(ms)
#enddef

#
# lisp_database_mapping_command
# 
# This function supports adding additional RLOCs to a database-mapping entry
# that already exists.
#
def lisp_database_mapping_command(kv_pair, ephem_port=None, replace=True):
    nat_interfaces = []
    prefix_set = []
    rloc_set = []

    num_rlocs = 1
    if ("address" in kv_pair):
        if (lisp_clause_syntax_error(kv_pair, "address", "rloc")): return
        num_rlocs = len(kv_pair["address"])
    elif ("interface" in kv_pair):
        if (lisp_clause_syntax_error(kv_pair, "interface", "rloc")): return
        num_rlocs = len(kv_pair["interface"])
    #endif
    for i in range(num_rlocs):
        rloc = lisp.lisp_rloc()
        rloc_set.append(rloc)
    #endfor

    if (lisp_clause_syntax_error(kv_pair, "eid-prefix", "prefix")): return
    for i in range(len(kv_pair["eid-prefix"])):
        db = lisp.lisp_mapping("", "", rloc_set)
        prefix_set.append(db)
    #endfor

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]
        if (kw == "mr-name"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                db.use_mr_name = "all" if value[0] == "" else value[i]
            #endfor
        #endif
        if (kw == "ms-name"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                db.use_ms_name = "all" if value[0] == "" else value[i]
            #endfor
        #endif
        if (kw == "instance-id"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                v = ["0"] if (v == "") else v.split()
                for vv in v: v[v.index(vv)] = int(vv)
                db.eid.instance_id = v[0]
                db.eid.iid_list = v[1::]
                db.group.instance_id = v[0]
            #endfor
        #endif
        if (kw == "secondary-instance-id"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                if (v == ""): continue
                db.secondary_iid = int(v)
                if (db.eid.address == 0):
                    lisp.lisp_default_secondary_iid = int(v)
                #endif
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                if (v != ""): db.eid.store_prefix(v)
                if (db.eid.address == 0):
                    lisp.lisp_default_secondary_iid = db.secondary_iid
                #endif
            #endfor
        #endif
        if (kw == "group-prefix"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                if (v != ""): db.group.store_prefix(v)
            #endfor
        #endif
        if (kw == "dynamic-eid"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                if (v == "yes"): db.dynamic_eids = {}
            #endfor
        #endif
        if (kw == "signature-eid"):
            for i in range(len(prefix_set)):
                db = prefix_set[i]
                v = value[i]
                db.signature_eid = (v == "yes")
            #endfor
        #endif
        if (kw == "register-ttl"):
            for i in range(len(prefix_set)):
                if (value[i] == ""): continue
                db = prefix_set[i]
                db.register_ttl = int(value[i])
            #endfor
        #endif
        if (kw == "priority"): 
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.weight = int(v)
            #endfor
        #endif
        if (kw == "address"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rloc.store_address(v)
            #endfor
        #endif
        if (kw == "interface"):
            hostname = lisp.lisp_hostname
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): 
                    rloc.interface = v
                    addr = lisp.lisp_get_interface_address(v)
                    if (addr): 
                        rloc.rloc.copy_address(addr)
                        lisp.lisp_myrlocs[0] = addr
                    #endif
                    rloc.rloc_name = hostname
                    nat_interfaces.append(rloc)
                #endif
            #endfor
        #endif
        if (kw == "elp-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.elp_name = v
            #endfor
        #endif
        if (kw == "rle-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rle_name = v
            #endfor
        #endif
        if (kw == "json-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.json_name = v
            #endfor
        #endif
        if (kw == "geo-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.geo_name = v
            #endfor
        #endif
        if (kw == "rloc-record-name"):
            for i in range(len(rloc_set)):
                rloc = rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rloc_name = v
            #endfor
        #endif
    #endfor

    #
    # If there was more than one NAT interface found, change each RLOC-name
    # to <hostname>-<device-name>. We use variable hostname just in case
    # the user configured a "rloc-record-name", where when we are doing
    # NAT-traversal, we have to overwrite the above convention.
    #
    if (len(nat_interfaces) > 1):
        for rloc in nat_interfaces: 
            rloc.rloc_name = hostname + "-" + rloc.interface
        #endfor
    #endif

    #
    # Store in database list.
    #
    for db in prefix_set:
        db.rloc_set = copy.deepcopy(db.rloc_set)
        db.sort_rloc_set()
        db.add_db()
        if (replace and lisp_replace_db_list(db)): continue
        lisp.lisp_db_list.append(db)
    #endfor

    #
    # Write to data-plane.
    #
    lisp.lisp_write_ipc_database_mappings(ephem_port)

    #
    # Set default instance-ID to be the first database-mapping command in
    # the lisp.config configuration file. This can be overwritten by using
    # "lisp interface" commands where an instance-ID can be assigned per 
    # interface.
    #
    lisp.lisp_default_iid = lisp.lisp_db_list[0].eid.instance_id

    #
    # Check to see if we are doing L2-overlays. The presents of an EID-prefix
    # of "0000-0000-0000/0" with "dynamic-eid = yes" means we are.
    #
    # Check to see if we (the ITR) is acting as a PITR. The presents of an 
    # IPv4 or IPv6 default EID-prefix means we are.
    #
    for db in prefix_set:
        if (db.group.is_null() == False): continue
        if (db.eid.address == 0 and db.eid.mask_len == 0):
            if (db.eid.is_ipv4() or db.eid.is_ipv6()):
                lisp.lisp_pitr = True
                break
            #endif
        #endif

        if (db.dynamic_eids == None): continue
        if (db.eid.is_mac() and db.eid.address == 0 and db.eid.mask_len == 0):
            lisp.lisp_l2_overlay = True
            break
        #endif
    #endif

    #
    # We may have to retrieve a new local address if the one we choose is
    # now an EID. Issue log message if an RLOC became an EID due ot this
    # newly configured database-mapping command.
    #
    had_rloc = (lisp.lisp_myrlocs[0] != None)
    lisp.lisp_get_local_addresses()

    if (lisp.lisp_myrlocs[0] == None and had_rloc):
        lisp.lprint("No RLOCs found, local addresses changed from RLOC to EID")
    #endif

    # 
    # If we are programming hardware and a dynamic-EID-prefix has been 
    # configured, then add a route to the kernel so hardware can uRPF fail
    # to punt the packet for dynamic-EID discovery.
    #
    # An Arista box will need the following CLI interface:
    #
    # int <interface>
    #   ip verify unicast source reachable-via rx 
    #
    #   /proc/sys/net/ipv4/conf/<interface>/rp_filter is 0
    #
    # The following on Fedora will tell you the setting on each interface:
    #
    #     sysctl -a | egrep "\.rp_filter"
    # and:
    #
    # platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1
    #
    if (lisp.lisp_program_hardware == False): return

    found = False
    for db in prefix_set:
        if (db.dynamic_eids == None): continue
        dyn_eid = db.eid.print_prefix_no_iid()
        found = lisp.lisp_i_am_itr
        os.system("ip route add {} dev ma1".format(dyn_eid))
    #endfor
    if (lisp.lisp_program_hardware and found):
        cmd = "platform trident diag s cpu_control_1 URPF_MISS_TOCPU=1"
        lisp.lisp_send_to_arista(cmd, None)
    #endif
#enddef

#
# lisp_show_db_list
#
# Show database-mappings configured in ITR and ETR.
#
def lisp_show_db_list(itr_or_etr, output):
    hover = "{} database-mapping entries".format(len(lisp.lisp_db_list))
    title = "LISP-{} Configured Database Mappings:".format(itr_or_etr)
    title = lisp.lisp_span(title, hover)

    keys = '<a href="/lisp/show/etr/keys"><br>RLOC Keys</a>'

    if (itr_or_etr == "ITR"):
        output += lisp_table_header(title, "EID-Prefix Record",
            "Uptime", "RLOC Record", "Unicast<br>Priority/Weight",
            "Multicast<br>Priority/Weight", "Use MR")
    else:
        output += lisp_table_header(title, "EID-Prefix Record",
            "Uptime", "RLOC Record" + keys, "Unicast<br>Priority/Weight",
            "Multicast<br>Priority/Weight", "Receive Stats", 
            "Map-Replies<br>Sent", "Use MS")
    #endif

    for db in lisp.lisp_db_list:
        db_ts = lisp.lisp_print_elapsed(db.uptime)
        mrs = db.map_replies_sent

        #
        # For display discovered dynamic-EIDs.
        #
        prefix_url = ""
        if (db.dynamic_eid_configured()):
            url = db.eid.print_prefix_url()
            length = len(db.dynamic_eids)
            itr = itr_or_etr.lower()
            prefix_url = ("<br><a href='/lisp/show/{}/dynamic-eid/{}'>" + \
                "{} dynamic-eids</a>").format(itr, url, length)
        #endif

        first_time = True
        for rloc in db.rloc_set: 
            if (first_time):
                prefix = db.print_eid_tuple()
                prefix = db.star_secondary_iid(prefix)
                prefix += prefix_url
                ts = db_ts
                first_time = False
            else:
                prefix, ts, mrs = ("", "", "")
            #endif
                
            rloc_str = "" if rloc.rloc.is_null() else \
                rloc.rloc.print_address_no_iid()

            if (rloc.interface != None): 
                rloc_str += " ({})".format(rloc.interface)
            #endif
            if (rloc_str != ""): rloc_str += "<br>"

            if (rloc.translated_rloc.not_set() == False):
                rloc_str += "translated RLOC: {}<br>".format( \
                    rloc.translated_rloc.print_address_no_iid())
            #endif

            rloc_name = rloc.print_rloc_name(True)
            if (rloc_name != ""): rloc_str += rloc_name + "<br>"

            if (rloc.geo_name != None):
                rloc_str += "geo: " + rloc.geo_name + "<br>"
            #endif
            if (rloc.elp_name != None):
                rloc_str += "elp: " + rloc.elp_name + "<br>"
            #endif
            if (rloc.rle_name != None):
                rloc_str += "rle: " + rloc.rle_name + "<br>"
            #endif
            if (rloc.json_name != None):
                rloc_str += "json: " + rloc.json_name + "<br>"
            #endif

            if (itr_or_etr == "ITR"):
                output += lisp_table_row(prefix, ts, rloc_str,
                    str(rloc.priority) + "/" + str(rloc.weight), 
                    str(rloc.mpriority) + "/" + str(rloc.mweight), 
                    db.use_mr_name)
            else:
                stats = rloc.stats.get_stats(True, True)
                output += lisp_table_row(prefix, ts, rloc_str,
                    str(rloc.priority) + "/" + str(rloc.weight), 
                    str(rloc.mpriority) + "/" + str(rloc.mweight), stats,
                    mrs, db.use_ms_name)
            #endif
        #endfor
    #endfor
    output += lisp_table_footer()

    #
    # Show geo-coord configuration, if it exists.
    #
    if (len(lisp.lisp_geo_list) != 0):
        title = "Configured Geo-Coordinates:"
        output += lisp_table_header(title, "Geo Name", 
            "Geo-Prefix or Geo-Point")
        geo_list = sorted(lisp.lisp_geo_list)
        for geo_name in geo_list:
            geo = lisp.lisp_geo_list[geo_name]
            output += lisp_table_row(geo_name, geo.print_geo_url())
        #endfor
        output += lisp_table_footer()
    #endif
    return(output)
#enddef

#
# lisp_interface_command
#
# Process the "lisp interface" command.
#
def lisp_interface_command(kv_pair):
    interface_name = None
    device_name = None
    instance_id = None
    dynamic_eid = None
    dynamic_eid_device_name = None
    dyn_eid_timeout = None
    mt_eid = None
    lisp_nat = None

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]
        if (kw == "interface-name"): interface_name = value
        if (kw == "device"): device_name = value
        if (kw == "instance-id"): instance_id = value
        if (kw == "dynamic-eid"): dynamic_eid = value
        if (kw == "multi-tenant-eid"): mt_eid = value
        if (kw == "dynamic-eid-device"): dynamic_eid_device_name = value
        if (kw == "dynamic-eid-timeout"): dyn_eid_timeout = value
        if (kw == "lisp-nat"): lisp_nat = (value == "yes")
    #endfor

    if (device_name == None): return

    #
    # Do special addition of interface "eth0" here on EOS systems. If eth0
    # is a switchport and EOS configures a vlan over this port, then we will
    # not discover eth0 interfaces in the Linux kernel. And the packet will
    # arrive to the lisp-itr process as coming in on "eth0".
    #
#   if (device_name != "eth0"): return
    if (device_name in lisp.lisp_myinterfaces and mt_eid == None):
        interface = lisp.lisp_myinterfaces[device_name]
    else:
        interface = lisp.lisp_interface(device_name)
        lisp.lisp_myinterfaces[device_name] = interface
    #endif

    #
    # Add to global data structures.
    #
    interface.interface_name = interface_name
    if (instance_id != None): 
        if (instance_id.isdigit() == False): instance_id = "0"
        interface.instance_id = int(instance_id)
    #endif
    if (dynamic_eid != None): 
        interface.dynamic_eid.store_prefix(dynamic_eid)
        interface.dynamic_eid.instance_id = interface.instance_id
    #endif
    if (dynamic_eid_device_name != None): 
        interface.dynamic_eid_device = dynamic_eid_device_name
    #endif
    if (dyn_eid_timeout != None): 
        interface.dynamic_eid_timeout = int(dyn_eid_timeout)
    #endif
    if (mt_eid != None): 
        interface.multi_tenant_eid.store_prefix(mt_eid)
        interface.multi_tenant_eid.instance_id = int(interface.instance_id)
        lisp.lisp_multi_tenant_interfaces.append(interface)
    #endif
    if (lisp_nat):
        check = "sudo iptables -t nat -C POSTROUTING -o {} -j MASQUERADE"
        check  = getoutput(check.format(device_name))
        if (check != ""):
            loopback = lisp.lisp_get_loopback_address()
            if (loopback):
                add = "sudo iptables -t nat -A POSTROUTING -s {} -j ACCEPT"
                os.system(add.format(loopback))
            #endif
            add = "sudo iptables -t nat -A POSTROUTING -o {} -j MASQUERADE"
            os.system(add.format(device_name))
            os.system("sudo sysctl net.ipv4.ip_forward=1")
        #endif
    #endif
    
    lisp.lisp_iid_to_interface[instance_id] = interface

    #
    # Create interface based socket for multi-tenancy. Only if OS supports
    # the setsockopt SO_BINDTODEVICE.
    #
    if ("SO_BINDTODEVICE" in dir(socket)): interface.set_socket(device_name)
    if ("PF_PACKET" in dir(socket)): interface.set_bridge_socket(device_name)

    #
    # Get local addresses to reassign the RLOC interface's instance-ID.
    #
    lisp.lisp_get_local_addresses()

    #
    # If dynamic-EID is configured, turn on uRPF on interface if we are doing
    # hardware programming. Make sure the sysctl is done after the "ip verify
    # ..." command.
    #
    if (dynamic_eid != None and lisp.lisp_program_hardware):
        cmd = "ip verify unicast source reachable-via rx"
        lisp.lisp_send_to_arista(cmd, device_name)
        cmd = 'sysctl -w "net.ipv4.conf.{}.rp_filter=0"'.format(device_name)
        os.system(cmd)
    #endif

    #
    # Write to data-plane.
    #
    lisp.lisp_write_ipc_interfaces()
    return
#enddef

#
# lisp_parse_eid_in_url
#
# Parse the convention for passing EID-prefixes in URL. Used by lisp_show_
# site_command() and lisp_show_dyn_eid_command().
#
def lisp_parse_eid_in_url(command, eid_prefix):
    group_str = ""

    #
    # Check for "[*]".
    #
    if (eid_prefix == "0--0"): 
        command = command + "%[0]/0%"
    elif (eid_prefix.find("-name-") != -1):
        eid_prefix = eid_prefix.split("-")
        if (len(eid_prefix) > 4):
            eid_prefix = [eid_prefix[0], "name", "-".join(eid_prefix[2:-1]),
                eid_prefix[-1]]
        #endif

        #
        # A Distinguished-Name.
        #
        eid_str = "[" + eid_prefix[0] + "]'" + eid_prefix[2] + "'" +  "/" + \
            eid_prefix[3]
        command = command + "%" + eid_str + "%"
    elif (eid_prefix.count("-") in [9, 10]):

        #
        # A Geo-String.
        #
        eid_prefix = eid_prefix.split("-")
        eid_str = "[" + eid_prefix[0] + "]" + "-".join(eid_prefix[1:-1]) + \
            "/" + eid_prefix[-1]
        command = command + "%" + eid_str + "%"
    elif (eid_prefix.find(".") == -1 and eid_prefix.find(":") == -1):
        eid_prefix = eid_prefix.split("-")

        #
        # An E.164 address.
        #
        if (eid_prefix[1] == "plus"):
            eid_str = "[" + eid_prefix[0] + "]+" + eid_prefix[2] + \
                "/" + eid_prefix[3]
            command = command + "%" + eid_str + "%"
        else:

            #
            # A MAC address.
            #
            eid_str = "[" + eid_prefix[0] + "]" + eid_prefix[1] + "-" + \
                eid_prefix[2] + "-" + eid_prefix[3] + "/" + eid_prefix[4]

            #
            # Look for MAC based (S,G).
            #
            if (len(eid_prefix) == 10):
                group_str = "[" + eid_prefix[5] + "]" + eid_prefix[6] + "-" + \
                    eid_prefix[7] + "-" + eid_prefix[8] + "/" + eid_prefix[9]
                command = command + "%" + eid_str + "%" + group_str
            else:
                command = command + "%" + eid_str + "%"
            #endif
        #endif

    else: 
            
        #
        # An IPv4 or IPv6 unicast or multicast entry.
        #
        eid_prefix = eid_prefix.split("-")
        if (eid_prefix[1] == "*"): 
            eid_str = ""
            group_str = "[" + eid_prefix[2] + "]" + eid_prefix[3] + "/" + \
                eid_prefix[4]
        else:
            eid_str = "[" + eid_prefix[0] + "]" + eid_prefix[1] + "/" + \
                eid_prefix[2]
            if (len(eid_prefix) == 6):
                group_str = "[" + eid_prefix[3] + "]" + eid_prefix[4] + \
                    "/" + eid_prefix[5]
            #endif
        #endif
        command = command + "%" + eid_str + "%" + group_str
    #endif
    return(command)
#enddef

#
# lisp_show_dynamic_eid_command
#
# Do look in lisp_db_list and display all discovered dynamic-EIDs.
#
def lisp_show_dynamic_eid_command(parm):
    output = ""
    if (parm == ""): return(output)

    eid = lisp_get_lookup_string(parm.split("%")[0])
    eid = eid[0]

    db = lisp.lisp_db_for_lookups.lookup_cache(eid, False)
    if (db == None): return(output)

    itr = "ITR" if lisp.lisp_i_am_itr else "ETR"
    eid_str = db.print_eid_tuple()

    title = "LISP-{} Discovered Dynamic EIDs for {}:".format(itr, eid_str)
    
    if (itr == "ITR"):
        output = lisp_table_header(title, "Dynamic-EID", "Interface", "Uptime",
            "Last Packet", "Inactivity Timeout")
    else:
        output = lisp_table_header(title, "Dynamic-EID", "Interface", "Uptime",
            "Inactivity Timeout")
    #endif

    for dyn_eid in list(db.dynamic_eids.values()):
        eid = dyn_eid.dynamic_eid.print_address()
        uts = lisp.lisp_print_elapsed(dyn_eid.uptime)
        to = str(dyn_eid.timeout) + " secs"
        if (itr == "ITR"):
            lts = lisp.lisp_print_elapsed(dyn_eid.last_packet)
            output += lisp_table_row(eid, dyn_eid.interface, uts, lts, to)
        else:
            output += lisp_table_row(eid, dyn_eid.interface, uts, to)
        #endif
    #endfor
    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_clear_decap_stats
#
# Process user clear of ETR or RTR's decapsulation statistics.
#
# Variable "command" is a string and not a byte string. Caller converts.
#
def lisp_clear_decap_stats(command):
    stat_name = command.split("%")[1]
    lisp.lisp_decap_stats[stat_name] = lisp.lisp_stats()
#enddef

#
# lisp_show_decap_stats
#
# Show decapsulation stats for an ETR or RTR.
#
def lisp_show_decap_stats(output, etr_or_rtr):
    u = etr_or_rtr.upper()
    l = etr_or_rtr.lower()

    s = []
    for key in lisp.lisp_decap_stats:
        html = "<a href='/lisp/clear/{}/stats/{}'>{}</a>".format(l, key, key)
        s.append(html)
    #endif

    header = "LISP-{} Decapsulation Stats:".format(u)
    output += lisp_table_header(header, *s)

    s = []
    for stat in list(lisp.lisp_decap_stats.values()):
        s.append(stat.get_stats(False, True))
    #endfor
    output += lisp_table_row(*s)
    output += lisp_table_footer()
    return(output)
#enddef

#
# lisp_show_crypto_list
#
# Print out the lisp_crypto_keys_by_rloc_encap array in a readable way for 
# debugging.
#
def lisp_show_crypto_list(xtr):
    output = ""
    nonce_entries = len(lisp.lisp_crypto_keys_by_nonce) != 0

    if (lisp.lisp_i_am_itr or lisp.lisp_i_am_rtr):
        if (nonce_entries):
            title = "LISP-{} Nonce Crypto State".format(xtr)
            output += lisp_table_header(title, "Nonce", "Uptime", "Key-ID", 
                "Key Material")
            for key in lisp.lisp_crypto_keys_by_nonce:
                col1 = "0x" + lisp.lisp_hex_string(key)
                value = lisp.lisp_crypto_keys_by_nonce[key]
                for kid in value:
                    if (kid == None): continue
                    ut = lisp.lisp_print_elapsed(kid.uptime)
                    keys = kid.print_keys(False)
                    output += lisp_table_row(col1, ut, kid.key_id, keys)
                    col1 = ""
                #endfor
            #endfor
            output += lisp_table_footer()
        #endif
    
        title = "LISP-{} Encapsulation Crypto State".format(xtr)
        output += lisp_table_header(title, "RLOC", "Uptime", "Last Rekey", 
            "Rekey Count", "Use Count", "Key-ID", "Key Material")
        for key in lisp.lisp_crypto_keys_by_rloc_encap:
            col1 =  key
            value = lisp.lisp_crypto_keys_by_rloc_encap[key]
            for kid in value:
                if (kid == None): continue
                ut = lisp.lisp_print_elapsed(kid.uptime)
                rt = lisp.lisp_print_elapsed(kid.last_rekey)
                keys = kid.print_keys(False)
                output += lisp_table_row(col1, ut, rt, kid.rekey_count, 
                    kid.use_count, kid.key_id, keys)
                col1 = ""
            #endfor
        #endfor
        output += lisp_table_footer()
    #endif

    if (lisp.lisp_i_am_etr or lisp.lisp_i_am_rtr):
        title = "LISP-{} Decapsulation Crypto State".format(xtr)
        output += lisp_table_header(title, "RLOC", "Uptime", "Last Rekey", 
            "Rekey Count", "Use Count", "Key-ID", "Key Material")
        for key in lisp.lisp_crypto_keys_by_rloc_decap:
            col1 =  key
            value = lisp.lisp_crypto_keys_by_rloc_decap[key]
            for kid in value:
                if (kid == None): continue
                ut = lisp.lisp_print_elapsed(kid.uptime)
                rt = lisp.lisp_print_elapsed(kid.last_rekey)
                keys = kid.print_keys(False)
                output += lisp_table_row(col1, ut, rt, kid.rekey_count, 
                    kid.use_count, kid.key_id, keys)
                col1 = ""
            #endfor
        #endfor
        output += lisp_table_footer()
    #endif
    return(output)
#enddef

#------------------------------------------------------------------------------
