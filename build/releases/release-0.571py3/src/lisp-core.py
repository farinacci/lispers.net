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
# lisp-core.py
#
# This is the core process that is used to demux to the specific LISP 
# functional components. The 4342 listen socket is centralized here.
#
#
#        +------------- data encapsulation via network --------------+
#        |                                                           |
#        |               IPC when mr & ms colocated                  |
#        |           +--------------------------------+              |
#        |           |                                |              |
#        |           |  IPC when mr & ddt colo        |              |
#        |           |    +------------+              |              |
#        |           |    |            |              |              |
#        |           |    |            v              v              v 4341
#  +-------------+  +----------+   +----------+   +----------+   +----------+ 
#  | lisp-[ir]tr |  | lisp-mr  |   | lisp-ddt |   | lisp-ms  |   | lisp-etr |
#  +-------------+  +----------+   +----------+   +----------+   +----------+ 
#        ^ IPC          ^ IPC          ^ IPC          ^ IPC          ^ IPC
#        |              |              |              |              |
#        |              |              |              |              |
#        |              |              |              |              |
#        +--------------+--------------+--------------+--------------+
#                                      |
#                                      | for dispatching control messages
#                                +-----------+
#                                | lisp-core |
#                                +-----------+
#                                      | 4342
#                                      |
#                                  via network
#
# -----------------------------------------------------------------------------
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import str
from past.utils import old_div
import lisp
import lispconfig
import multiprocessing
import threading
from subprocess import getoutput
import time
import os
import bottle
import json
import sys
import socket

#
# Moving from CherryPy to cheroot. Happened during py2 -> py3 conversion.
#
from cheroot.wsgi import Server as wsgi_server
from cheroot.ssl.builtin import BuiltinSSLAdapter as ssl_adaptor

#------------------------------------------------------------------------------

#
# Global variables.
#
lisp_build_date = ""

lisp_control_listen_socket = None
lisp_ipc_socket = None
lisp_ipc_control_socket = None
lisp_sockets = [None, None, None]
lisp_encap_socket = None

#------------------------------------------------------------------------------

#
# lisp_api_get
#
# Ask the LISP subsystem for configuration information.
#
@bottle.route('/lisp/api', method="get")
@bottle.route('/lisp/api/<command>', method="get")
@bottle.route('/lisp/api/<command>/<data_structure>', method="get")
def lisp_api_get(command = "", data_structure=""):
    data = [{ "?" : [{"?" : "not-auth"}] }]

    #
    # Authenticate.
    #
    if (bottle.request.auth != None): 
        username, pw = bottle.request.auth
        if (lispconfig.lisp_find_user_account(username, pw) == False): 
            return(json.dumps(data))
        #endif
    else:
        if (bottle.request.headers["User-Agent"].find("python") != -1):
            return(json.dumps(data))
        #endif
        if (lispconfig.lisp_validate_user() == False): 
            return(json.dumps(data))
        #endif
    #endif

    #
    # First check for dynamic data. That is go get data from appropriate 
    # process. Return from process in JSON format.
    #
    if (command == "data" and data_structure != ""):
        jdata = bottle.request.body.readline()
        if (type(jdata) == bytes): jdata = jdata.decode()
        data = json.loads(jdata) if jdata != "" else ""
        if (data != ""): data = list(data.values())[0]
        if (data == []): data = ""

        if (type(data) == dict and type(list(data.values())[0]) == dict):
            data = list(data.values())[0]
        #endif

        data = lisp_get_api_data(data_structure, data)
        return(data)
    #endif

    #
    # A valid user can access data now.
    #        
    if (command != ""):
        command = "lisp " + command
    else:
        jdata = bottle.request.body.readline()
        if (type(jdata) == bytes): jdata = jdata.decode()
        if (jdata == ""): 
            data = [{ "?" : [{"?" : "no-body"}] }]
            return(json.dumps(data))
        #endif

        data = json.loads(jdata)
        command = list(data.keys())[0]
    #endif

    data = lispconfig.lisp_get_clause_for_api(command)
    return(json.dumps(data))
#enddef

#
# lisp_get_api_system
#
# Return system information in dictionary array (JSON format).
#
def lisp_get_api_system():
    data = {}
    data["hostname"] = socket.gethostname()
    data["system-uptime"] = getoutput("uptime")
    data["lisp-uptime"] = lisp.lisp_print_elapsed(lisp.lisp_uptime)
    data["lisp-version"] = lisp.lisp_version

    yesno = "yes" if os.path.exists("./logs/lisp-traceback.log") else "no"
    data["traceback-log"] = yesno

    v4 = lisp.lisp_myrlocs[0]
    v6 = lisp.lisp_myrlocs[1]
    v4 = "none" if (v4 == None) else v4.print_address_no_iid()
    v6 = "none" if (v6 == None) else v6.print_address_no_iid()
    data["lisp-rlocs"] = [v4, v6]
    return(json.dumps(data))
#enddef

#
# lisp_get_api_data
#
# Send IPC message to process that owns the dynamic data strucutre we 
# are retrieving via the API. Variable data for the 'map-cache' and
# 'site-cache' API contains:
#
# { "eid-prefix" : <eid>, "group-prefix" : <group>, "instance-id" : <iid> }
#
# For 'map-resolver' and 'map-server" API contains:
#
# { "address" : <address>" } or { "dns-name" : <dns-name> }
#
# For 'site-cache-summary', there is no data required.
#
def lisp_get_api_data(data_structure, data):
    valid_apis = ["site-cache", "map-cache", "system", "map-resolver",
        "map-server", "database-mapping", "site-cache-summary"]

    if (data_structure not in valid_apis): return(json.dumps([]))

    #
    # lisp-core process handles the system lispapi.get_system() API.
    #
    if (data_structure == "system"): return(lisp_get_api_system())

    #
    # Build IPC, acquire lock, and send IPC message. Then wait.
    #
    if (data != ""): data = json.dumps(data)
    ipc = lisp.lisp_api_ipc("lisp-core", data_structure + "%" + data)

    if (data_structure in ["map-cache", "map-resolver"]):
        if (lisp.lisp_is_running("lisp-rtr")): 
            lisp.lisp_ipc_lock.acquire()
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-rtr")
        elif (lisp.lisp_is_running("lisp-itr")): 
            lisp.lisp_ipc_lock.acquire()
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-itr")
        else:
            return(json.dumps([]))
        #endif
    #endif
    if (data_structure in ["map-server", "database-mapping"]):
        if (lisp.lisp_is_running("lisp-etr")): 
            lisp.lisp_ipc_lock.acquire()
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-etr")
        elif (lisp.lisp_is_running("lisp-itr")): 
            lisp.lisp_ipc_lock.acquire()
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-itr")
        else:
            return(json.dumps([]))
        #endif
    #endif
    if (data_structure in ["site-cache", "site-cache-summary"]):
        if (lisp.lisp_is_running("lisp-ms")): 
            lisp.lisp_ipc_lock.acquire()
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-ms")
        else:
            return(json.dumps([]))
        #endif
    #endif

    lisp.lprint("Waiting for api get-data '{}', parmameters: '{}'".format( \
        data_structure, data))
    
    opcode, source, port, output = lisp.lisp_receive(lisp_ipc_socket, True)
    lisp.lisp_ipc_lock.release()
    output = output.decode()
    return(output)
#enddef

#
# lisp_api_put_delete
#
# Tell the LISP subsystem to add/replace or remove a command clause.
#
@bottle.route('/lisp/api', method="put")
@bottle.route('/lisp/api/<command>', method="put")
@bottle.route('/lisp/api/<command>', method="delete")
def lisp_api_put_delete(command = ""):
    data = [{ "?" : [{"?" : "not-auth"}] }]
    if (bottle.request.auth == None): return(data)

    #
    # Authenticate.
    #
    if (bottle.request.auth != None): 
        username, pw = bottle.request.auth
        if (lispconfig.lisp_find_user_account(username, pw) == False): 
            return(json.dumps(data))
        #endif
    else:
        if (bottle.request.headers["User-Agent"].find("python") != -1):
            return(json.dumps(data))
        #endif
        if (lispconfig.lisp_validate_user() == False): 
            return(json.dumps(data))
        #endif
    #endif

    #
    # If the request is to add, change, or remove a "user-account" command,
    # the validated user must be configured as a superuser.
    #
    if (command == "user-account"):
        if (lispconfig.lisp_is_user_superuser(username) == False): 
            data = [{ "user-account" : [{"?" : "not-auth"}] }]
            return(json.dumps(data))
        #endif
    #endif

    #
    # A valid user can access data now.
    #        
    jdata = bottle.request.body.readline()
    if (type(jdata) == bytes): jdata = jdata.decode()
    if (jdata == ""): 
        data = [{ "?" : [{"?" : "no-body"}] }]
        return(json.dumps(data))
    #endif

    data = json.loads(jdata)
    if (command != ""):
        command = "lisp " + command
    else:
        command = list(data[0].keys())[0]
    #endif

    #
    # Add, replace, or remove lines from configuration file. Grab config
    # file lock.
    #
    lisp.lisp_ipc_lock.acquire()
    if (bottle.request.method == "DELETE"):
        data = lispconfig.lisp_remove_clause_for_api(data)
    else:
        data = lispconfig.lisp_put_clause_for_api(data)
    #endif
    lisp.lisp_ipc_lock.release()
    return(json.dumps(data))
#enddef

#
# lisp_show_api_doc
#
@bottle.route('/lisp/show/api-doc', method="get")
def lisp_show_api_doc():
    if (os.path.exists("lispapi.py")): os.system("pydoc lispapi > lispapi.txt")
    if (os.path.exists("lispapi.txt") == False): 
        return("lispapi.txt file not found")
    #endif
    return(bottle.static_file("lispapi.txt", root="./"))
#enddef

#
# lisp_show_command_doc
#
@bottle.route('/lisp/show/command-doc', method="get")
def lisp_show_comamnd_doc():
    return(bottle.static_file("lisp.config.example", root="./", 
        mimetype="text/plain"))
#enddef

#
# lisp_show_lisp_xtr
#
# Display the show-xtr file that the go data-plane lisp-xtr writes to.
#
@bottle.route('/lisp/show/lisp-xtr', method="get")
def lisp_show_lisp_xtr():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    #
    # Special case to look for a other data-planes. If it does not exist, check
    # the lispers.net go data-plane.
    #
    if (os.path.exists("./show-ztr")):
        f = open("./show-ztr", "r"); lines = f.read(); f.close()
    else:
        f = open("./show-xtr", "r"); lines = f.read(); f.close()
    #endif

    new = ""
    lines = lines.split("\n")
    for line in lines:
        if (line[0:4] == "    "): new += lisp.lisp_space(4)
        if (line[0:2] == "  "): new += lisp.lisp_space(2)
        new += line + "<br>"
    #endfor
    new = lisp.convert_font(new)
    return(lisp.lisp_print_sans(new))
#enddef

#
# lisp_show_keys
#
# Display LISP crypto-key-list to ITR, ETR, RTR.
#
@bottle.route('/lisp/show/<xtr>/keys', method="get")
def lisp_show_keys(xtr):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    superuser = lispconfig.lisp_is_user_superuser(None)

    if (superuser == False):
        output = "Permission denied"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif

    if (xtr not in ["itr", "etr", "rtr"]):
        output = "Invalid URL"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif
    command = "show {}-keys".format(xtr)
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_geo_map
#
# Use Google Maps API to draw a circle on a geographical map. The html file
# ./lispers.net-geo.html is javascript to call the Google API.
#
@bottle.route('/lisp/geo-map/<geo_prefix>')
def lisp_show_geo_map(geo_prefix):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    geo_prefix = geo_prefix.split("-")
    geo_prefix = "-".join(geo_prefix[0:-1]) + "/" + geo_prefix[-1]
    geo = lisp.lisp_geo("")
    geo.parse_geo_string(geo_prefix)
    lat, lon = geo.dms_to_decimal()
    radius = geo.radius * 1000

    r = open("./lispers.net-geo.html", "r"); html = r.read(); r.close()
    html = html.replace("$LAT", str(lat))
    html = html.replace("$LON", str(lon))
    html = html.replace("$RADIUS", str(radius))
    return(html)
#enddef

#
# lisp_core_login_page
#
# Print to browser landing page.
#
@bottle.route('/lisp/login', method="get")
def lisp_core_login_page():
    return(lispconfig.lisp_login_page())
#enddef

#
# lisp_core_do_login
#
# Get login info entered in forms data. Validate and add to cookie database.
# If valid, take user to landing page. Othereise, go back to login page.
#
@bottle.route('/lisp/login', method="post")
def lisp_core_do_login():
    if (lispconfig.lisp_validate_user()): 
        return(lispconfig.lisp_landing_page())
    #endif
    return(lisp_core_login_page())
#enddef

#
# lisp_core_landing_page
#
# Print to browser landing page.
#
@bottle.route('/lisp')
def lisp_core_landing_page():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_landing_page())
#enddef

#
# lisp_core_traceback_page
#
# Look in log files for Traceback messages.
#
@bottle.route('/lisp/traceback')
def lisp_core_traceback_page():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    clean = True

    #
    # Check explicit lisp-traceback.log.
    #
    if (os.path.exists("./logs/lisp-traceback.log")):
        output = getoutput("cat ./logs/lisp-traceback.log")
        if (output):
            output = output.replace("----------", "<b>----------</b>")
            output = output.replace("\n", "<br>")
            clean = False
        #endif
    #endif

    #
    # Look for Traceback messages in log files.
    #
    if (clean):
        output = ""
        cmd = "egrep --with-filename Traceback ./logs/*.log"
        log_files = getoutput(cmd)
        log_files = log_files.split("\n")
        for lf in log_files:
            if (lf.find(":") == -1): continue
            line = lf.split(":")
            if (line[1] == "0"): continue
            output += "Found Tracebacks in log file {}<br>".format(line[0])
            clean = False
        #endfor
        output = output[0:-4]
    #endif

    if (clean): 
        output = "No Tracebacks found - a stable system is a happy system"
    #endif

    output = lisp.lisp_print_cour(output)
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_core_not_supported
#
# Print to browser landing page.
#
@bottle.route('/lisp/show/not-supported')
def lisp_core_not_supported():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_not_supported())
#enddef

#
# lisp_show_status_command
#
# Show some version and system info.
#
@bottle.route('/lisp/show/status')
def lisp_show_status_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    #
    # Do not print out "show configuration" button or the debug drop-down menu.
    #
    output = ""
    superuser = lispconfig.lisp_is_user_superuser(None)
    if (superuser):
        sc = lisp.lisp_button("show configuration", "/lisp/show/conf")
        dc = lisp.lisp_button("show configuration diff", "/lisp/show/diff")
        ac = lisp.lisp_button("archive configuration", "/lisp/archive/conf")
        cc = lisp.lisp_button("clear configuration", "/lisp/clear/conf/verify")
        lf = lisp.lisp_button("log flows", "/lisp/log/flows")
        ils = lisp.lisp_button("install LISP software", "/lisp/install/image")
        rs = lisp.lisp_button("restart LISP subsystem", "/lisp/restart/verify")

        output = "<center>{}{}{}{}{}{}{}</center><hr>".format(sc, dc, ac, cc,
            lf, ils, rs)
    #endif

    sys_uptime = getoutput("uptime")
    uname = getoutput("uname -pv")
    main_version = lisp.lisp_version.replace("+", "")

    #
    # This is really broken. It returns twice as many CPUs than really on the
    # machine (on MacOS).
    #
    cpu_count = multiprocessing.cpu_count()
    
    i = sys_uptime.find(", load")
    sys_uptime = sys_uptime[0:i]
    elapsed = lisp.lisp_print_elapsed(lisp.lisp_uptime)

    top = "Not available"

    #
    # Get LISP process status.
    #
    ps = "ps auww" if lisp.lisp_is_macos() else "ps aux"
    grep = "egrep 'PID|python lisp|python -O lisp|python3.8 -O lisp'"
    grep += "| egrep -v grep"
    status = getoutput("{} | {}".format(ps, grep))
    status = status.replace(" ", lisp.space(1))
    status = status.replace("\n", "<br>")

    #
    # top on MacOS.
    #
    if (uname.find("Darwin") != -1):
        cpu_count = old_div(cpu_count, 2)
        top = getoutput("top -l 1 | head -50")
        top = top.split("PID")
        top = top[0]
    
        #
        # Massage the 'top' output so we can have one line per information 
        # line.
        #
        i = top.find("Load Avg")
        j = top[0:i].find("threads")
        processes = top[0:j+7]
        top = processes + "<br>" + top[i::]
        i = top.find("CPU usage")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("SharedLibs:")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("MemRegions")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("PhysMem")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("VM:")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("Networks")
        top = top[0:i] + "<br>" + top[i::]
        i = top.find("Disks")
        top = top[0:i] + "<br>" + top[i::]
    else:

        #
        # top on Fedora Linux.
        #
        lines = getoutput("top -b -n 1 | head -50")
        lines = lines.split("PID")
        lines[1] = lines[1].replace(" ", lisp.space(1))
        lines = lines[0] + lines[1]
        top = lines.replace("\n", "<br>")
    #endif

    release_notes = getoutput("cat release-notes.txt")
    release_notes = release_notes.replace("\n", "<br>")

    output += '''
        <br><table align="center" border="1" cellspacing="3x" cellpadding="5x">
        <tr>
        <td width="20%"><i>LISP Subsystem Version:<br>
        LISP Release {} Build Date:</i></td>
        <td width="80%"><font face="Courier New">{}<br>
        {}</font></td>
        </tr>

        <tr>
        <td width="20%"><i>LISP Subsystem Uptime:<br>System Uptime:</i></td>
        <td width="80%"><font face="Courier New">{}<br>
        {}</font></td>
        </tr>

        <tr>
        <td width="20%"><i>System Architecture:<br>
        Number of CPUs:<font face="Courier New">{}{}</font></td>
        <td width="80%"><font face="Courier New">{}</font></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>LISP Process Status:</i></td>
        <td width="80%">
            <div style="height: 100px; overflow: auto">
            <font size="2" face="Courier New">{}</font></div></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>System Resource Utilization:</i></td>
        <td width="80%">
            <div style="height: 200px; overflow: auto">
            <font face="Courier New">{}</font></td>
        </tr>

        <tr>
        <td width="20%" valign="top"><i>Release Notes:</i></td>
        <td width="80%">
            <div style="height: 300px; overflow: auto">
            <font size="2" face="Courier New">{}</font></div></td>
        </tr>

        </table>
        '''.format(main_version, lisp.lisp_version, lisp_build_date, elapsed, 
            sys_uptime, lisp.lisp_space(1), cpu_count, uname, status, top, 
            release_notes)

    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_show_conf_command
#
# Show configuration file.
#
@bottle.route('/lisp/show/conf')
def lisp_show_conf_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(bottle.static_file("lisp.config", root="./", mimetype="text/plain"))
#enddef

#
# lisp_show_diff_command
#
# Show configuration diff file.
#
@bottle.route('/lisp/show/diff')
def lisp_show_diff_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(bottle.static_file("lisp.config.diff", root="./", 
        mimetype="text/plain"))
#enddef

#
# lisp_archive_conf_command
#
# Save a copy of lisp.config in lisp.config.archive.
#
@bottle.route('/lisp/archive/conf')
def lisp_archive_conf_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    lisp.lisp_ipc_lock.acquire()
    os.system("cp ./lisp.config ./lisp.config.archive")
    lisp.lisp_ipc_lock.release()

    output = "Configuration file saved to "
    output = lisp.lisp_print_sans(output)
    output += lisp.lisp_print_cour("./lisp.config.archive")
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_clear_conf_command
#
# Clear contents of the lisp.config file.
#
@bottle.route('/lisp/clear/conf')
def lisp_clear_conf_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    os.system("cp ./lisp.config ./lisp.config.before-clear")
    lisp.lisp_ipc_lock.acquire()
    lisp_core_cp_lisp_config()
    lisp.lisp_ipc_lock.release()

    output = "Configuration cleared, a backup copy is stored in "
    output = lisp.lisp_print_sans(output)
    output += lisp.lisp_print_cour("./lisp.config.before-clear")
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_clear_conf_verify_command
#
# Ask user if they really want to clear the config file.
#
@bottle.route('/lisp/clear/conf/verify')
def lisp_clear_conf_verify_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    output = "<br>Are you sure you want to clear the configuration?"
    output = lisp.lisp_print_sans(output)

    yes = lisp.lisp_button("yes", "/lisp/clear/conf")
    cancel = lisp.lisp_button("cancel", "/lisp")
    output += yes + cancel + "<br>"
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_get_port_on_command_line
#
# Figure out if the lisp-core.pyo process was started with a parameter. If so,
# it is the port number we use for bottle. We want to restart using the same
# parameters.
#
def lisp_get_port_on_command_line():
    port = ""

    for p in ["443", "-8080", "8080"]:
        c = 'ps auxww | egrep "lisp-core.pyo {}" | egrep -v grep'.format(p)
        output = getoutput(c)
        if (output == ""): continue

        output = output.split("\n")[0]
        output = output.split(" ")
        if (output[-2] == "lisp-core.pyo" and output[-1] == p): port = p
        break
    #endfor
    return(port)
#enddef

#
# lisp_restart_command
#
# Restart the LISP subsystem.
#
@bottle.route('/lisp/restart')
def lisp_restart_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    #
    # Check to see if requiretty is in effect. If so, we can't sudo, so tell
    # user.
    #
    line = getoutput("egrep requiretty /etc/sudoers").split(" ")
    if (line[-1] == "requiretty" and line[0] == "Defaults"):
        output = "Need to remove 'requiretty' from /etc/sudoers"
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    lisp.lprint(lisp.bold("LISP subsystem restart request received", False))

    #
    # Check if we should start the process with 443 (or -8080) as the port 
    # number for the lisp-core should run on.
    #
    port = lisp_get_port_on_command_line()

    #
    # Build command and launch it in another process.
    #
    command = "sleep 1; sudo ./RESTART-LISP {}".format(port)
    threading.Thread(target=lisp_restart_lisp, args=[command]).start()

    output = lisp.lisp_print_sans("Restarting LISP subsystem ...")
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_restart_lisp
#
# Have system execute ./RESTART-LISP asynchronously.
#
def lisp_restart_lisp(command):
    os.system(command)
#enddef    

#
# lisp_restart_verify_command
#
# Ask user if they really want to restart the LISP subsystem.
#
@bottle.route('/lisp/restart/verify')
def lisp_restart_verify_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    output = "<br>Are you sure you want to restart the LISP subsystem?"
    output = lisp.lisp_print_sans(output)

    yes = lisp.lisp_button("yes", "/lisp/restart")
    cancel = lisp.lisp_button("cancel", "/lisp")
    output += yes + cancel + "<br>"
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_install_command
#
# Install tgz file user supplied in html form.
#
@bottle.route('/lisp/install', method="post")
def lisp_install_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    image = bottle.request.forms.get("image_url")
    if (image.find("lispers.net") == -1 or image.find(".tgz") == -1):
        string = "Invalid install request for file {}".format(image)
        lisp.lprint(lisp.bold(string, False))
        output = lisp.lisp_print_sans("Invalid lispers.net tarball file name")
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    if (lisp.lisp_is_python2()):
        py = "python -O "
        suffix = "pyo"
    #endif
    if (lisp.lisp_is_python3()):
        py = "python3.8 -O "
        suffix = "pyc"
    #endif
    if (lisp.lisp_is_ubuntu()):
        c = "{} lisp-get-bits.{} {} force 2>&1 > /dev/null". \
            format(py, suffix, image)
    else:
        c = "{} lisp-get-bits.{} {} force >& /dev/null". \
            format(py, suffix, image)
    #endif

    #
    # Issue command.
    #
    status = os.system(c)

    image_file = image.split("/")[-1]

    if (os.path.exists(image_file)):
        release = image.split("release-")[1]
        release = release.split(".tgz")[0]

        output = "Install completed for release {}".format(release)
        output = lisp.lisp_print_sans(output)

        output += "<br><br>" + lisp.lisp_button("restart LISP subsystem", 
            "/lisp/restart/verify") + "<br>"
    else:
        string = lisp.lisp_print_cour(image)
        output = "Install failed for file {}".format(string)
        output = lisp.lisp_print_sans(output)
    #endif

    string = "Install request for file {} {}".format(image,
        "succeeded" if (status == 0) else "failed")
    lisp.lprint(lisp.bold(string, False))
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_install_get_image
#
# Ask user for tgz image to install.
#
@bottle.route('/lisp/install/image')
def lisp_install_get_image():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    string = lisp.lisp_print_sans("<br>Enter lispers.net tarball URL:")
    output = '''
        <form action="/lisp/install" method="post" style="display: inline;">
        {}
        <input type="text" name="image_url" size="75" required/>
        <input type="submit" style="background-color:transparent;border-radius:10px;" value="Submit" />
        </form><br>'''.format(string)

    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_log_flows_command
#
# Touch file ./log-flows so we can have the user request a dump of the memory
# based flow log.
#
@bottle.route('/lisp/log/flows')
def lisp_log_flows_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    os.system("touch ./log-flows")

    output = lisp.lisp_print_sans("Flow data appended to file ")
    out = "<a href='/lisp/show/log/lisp-flow/100'>logs/lisp-flows.log</a>"
    output += lisp.lisp_print_cour(out)
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_search_log_command
#
# Search the <num> tail lines of <name> and display in <hr> separated format
# with search keyword in red.
#
@bottle.route('/lisp/search/log/<name>/<num>/<keyword>')
def lisp_search_log_command(name = "", num = "", keyword = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    command = "tail -n {} logs/{}.log | egrep -B10 -A10 {}".format(num, name, 
        keyword)
    output = getoutput(command)

    if (output):
        occurences = output.count(keyword)
        output = lisp.convert_font(output)
        output = output.replace("--\n--\n", "--\n")
        output = output.replace("\n", "<br>")
        output = output.replace("--<br>", "<hr>")
        output = "Found <b>{}</b> occurences<hr>".format(occurences) + output
    else:
        output = "Keyword {} not found".format(keyword)
    #endif

    #
    # Highlight keyword in blue.
    #
    blue = "<font color='blue'><b>{}</b>".format(keyword)
    output = output.replace(keyword, blue)
    output = output.replace(keyword, keyword + "</font>")

    output = lisp.lisp_print_cour(output)
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_search_log_command_input
#
# Get input form data for keyword to search on.
#
@bottle.post('/lisp/search/log/<name>/<num>')
def lisp_search_log_command_input(name = "", num=""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    keyword = bottle.request.forms.get("keyword")
    return(lisp_search_log_command(name, num, keyword))
#enddef

#
# lisp_show_log_name_command
#
# Show trace log file.
#
@bottle.route('/lisp/show/log/<name>/<num>')
def lisp_show_log_name_command(name = "", num=""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    
    #
    # Deafult to print out last 100 lines and convert to html bold.
    #
    if (num == ""): num = 100

    header = '''
        <form action="/lisp/search/log/{}/{}" method="post">
        <i>Keyword search:</i>
        <input type="text" name="keyword" />
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </form><hr>
    '''.format(name, num)

    if (os.path.exists("logs/{}.log".format(name))):
        output = getoutput("tail -n {} logs/{}.log".format(num, name))
        output = lisp.convert_font(output)
        output = output.replace("\n", "<br>")
        output = header + lisp.lisp_print_cour(output)
    else:
        a = lisp.lisp_print_sans("File")
        aa = lisp.lisp_print_cour("logs/{}.log".format(name))
        aaa = lisp.lisp_print_sans("does not exist")
        output = "{} {} {}".format(a, aa, aaa)
    #endif
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_debug_menu_command
#
# Turn on or off debug.
#
@bottle.route('/lisp/debug/<name>')
def lisp_debug_menu_command(name = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    #
    # Process "disable all" separately.
    #
    if (name == "disable%all"):
        data = lispconfig.lisp_get_clause_for_api("lisp debug")
        if ("lisp debug" in data[0]):
            new = []
            for entry in data[0]["lisp debug"]:
                key = list(entry.keys())[0]
                new.append({ key : "no" })
            #endfor
            new = { "lisp debug" : new }
            lispconfig.lisp_put_clause_for_api(new)
        #endif

        data = lispconfig.lisp_get_clause_for_api("lisp xtr-parameters")
        if ("lisp xtr-parameters" in data[0]):
            new = []
            for entry in data[0]["lisp xtr-parameters"]:
                key = list(entry.keys())[0]
                if (key in ["data-plane-logging", "flow-logging"]): 
                    new.append({ key : "no" })
                else:
                    new.append({ key : entry[key] })
                #endif
            #endfor
            new = { "lisp xtr-parameters" : new }
            lispconfig.lisp_put_clause_for_api(new)
        #endif

        return(lispconfig.lisp_landing_page())
    #endif

    #
    # Process enabling or disable debug logging for a single item.
    #
    name = name.split("%")
    component = name[0]
    yesno = name[1]

    xtr_parms = ["data-plane-logging", "flow-logging"]

    clause_name = "lisp xtr-parameters" if (component in xtr_parms) else \
        "lisp debug"

    data = lispconfig.lisp_get_clause_for_api(clause_name)

    if (clause_name in data[0]):
        new = {}
        for entry in data[0][clause_name]:
            new[list(entry.keys())[0]] = list(entry.values())[0]
            if (component in new): new[component] = yesno
        #endfor
        new = { clause_name: new }
        lispconfig.lisp_put_clause_for_api(new)
    #endif
    return(lispconfig.lisp_landing_page())
#enddef

#
# lisp_clear_referral_command
#
# Send a clear command to a LISP component.
#
@bottle.route('/lisp/clear/<name>')
@bottle.route('/lisp/clear/etr/<etr_name>/<stats_name>')
@bottle.route('/lisp/clear/rtr/<rtr_name>/<stats_name>')
@bottle.route('/lisp/clear/itr/<itr_name>')
@bottle.route('/lisp/clear/rtr/<rtr_name>')
def lisp_clear_command(name = "", itr_name = '', rtr_name = "", etr_name = "",
    stats_name = ""):

    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    #
    # Do various checks.
    #
    if (lispconfig.lisp_is_user_superuser(None) == False):
        output =  lisp.lisp_print_sans("Not authorized")
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    ipc = "clear"
    if (name == "referral"): 
        process = "lisp-mr"
        print_name = "Referral"
    elif (itr_name == "map-cache"): 
        process = "lisp-itr"
        print_name = "ITR <a href='/lisp/show/itr/map-cache'>map-cache</a>"
    elif (rtr_name == "map-cache"): 
        process = "lisp-rtr"
        print_name = "RTR <a href='/lisp/show/rtr/map-cache'>map-cache</a>"
    elif (etr_name == "stats"): 
        process = "lisp-etr"
        print_name = ("ETR '{}' decapsulation <a href='/lisp/show/" + \
            "database'>stats</a>").format(stats_name)
        ipc += "%" + stats_name 
    elif (rtr_name == "stats"): 
        process = "lisp-rtr"
        print_name = ("RTR '{}' decapsulation <a href='/lisp/show/" + \
            "rtr/map-cache'>stats</a>").format(stats_name)
        ipc += "%" + stats_name 
    else:
        output =  lisp.lisp_print_sans("Invalid command")
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    #
    # Send IPC to lisp-mr. Do not wait for a reply.
    #
    ipc = lisp.lisp_command_ipc(ipc, "lisp-core")
    lisp.lisp_ipc(ipc, lisp_ipc_socket, process)

    #
    # Only touch lisp.config file if there are static map-cache entries.
    #
    exist = getoutput("egrep 'lisp map-cache' ./lisp.config")
    if (exist != ""):
        os.system("touch ./lisp.config")
    #endif

    output = lisp.lisp_print_sans("{} cleared".format(print_name))
    return(lispconfig.lisp_show_wrapper(output))
#enddef

#
# lisp_show_map_server_command
#
# Have the lisp-etr process show the map-server configuration.
#
@bottle.route('/lisp/show/map-server')
def lisp_show_map_server_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, 
        "show map-server"))
#enddef

#
# lisp_show_database_command
#
# Have the lisp-etr process show the database-mapping configuration.
#
@bottle.route('/lisp/show/database')
def lisp_show_database_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show database-mapping"))
#enddef

#
# lisp_show_itr_map_cache_command
#
# Have the lisp-itr process show the map-cache.
#
@bottle.route('/lisp/show/itr/map-cache')
def lisp_show_itr_map_cache_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show itr-map-cache"))
#enddef

#
# lisp_show_itr_rloc_probing_command
#
# Have the lisp-itr process show the RLOC-probe list.
#
@bottle.route('/lisp/show/itr/rloc-probing')
def lisp_show_itr_rloc_probing_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show itr-rloc-probing"))
#enddef

#
# lisp_show_itr_map_cache_lookup
#
# Execute longest match lookup and return results.
# 
@bottle.post('/lisp/show/itr/map-cache/lookup')
def lisp_show_itr_map_cache_lookup():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid_str = bottle.request.forms.get("eid")
    if (lispconfig.lisp_validate_input_address_string(eid_str) == False):
        output = "Address '{}' has invalid format".format(eid_str)
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    command = "show itr-map-cache" + "%" + eid_str
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        command))
#enddef

#
# lisp_show_rtr_map_cache_command
#
# Have the lisp-rtr process show the map-cache.
#
@bottle.route('/lisp/show/rtr/map-cache')
@bottle.route('/lisp/show/rtr/map-cache/<dns>')
def lisp_show_rtr_map_cache_command(dns = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    if (dns == "dns"):
        return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
            "show rtr-map-cache-dns"))
    else:
        return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
            "show rtr-map-cache"))
    #endif
#enddef

#
# lisp_show_rtr_rloc_probing_command
#
# Have the lisp-rtr process show the RLOC-probe list.
#
@bottle.route('/lisp/show/rtr/rloc-probing')
def lisp_show_rtr_rloc_probing_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show rtr-rloc-probing"))
#enddef

#
# lisp_show_rtr_map_cache_lookup
#
# Execute longest match lookup and return results.
# 
@bottle.post('/lisp/show/rtr/map-cache/lookup')
def lisp_show_rtr_map_cache_lookup():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid_str = bottle.request.forms.get("eid")
    if (lispconfig.lisp_validate_input_address_string(eid_str) == False):
        output = "Address '{}' has invalid format".format(eid_str)
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    command = "show rtr-map-cache" + "%" + eid_str
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        command))
#enddef

#
# lisp_show_referral_command
#
# Have the lisp-mr show the DDT referral-cache.
#
@bottle.route('/lisp/show/referral')
def lisp_show_referral_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show referral-cache"))
#enddef

#
# lisp_show_referral_cache_lookup
#
# Execute longest match lookup and return results.
# 
@bottle.post('/lisp/show/referral/lookup')
def lisp_show_referral_cache_lookup():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid_str = bottle.request.forms.get("eid")
    if (lispconfig.lisp_validate_input_address_string(eid_str) == False):
        output = "Address '{}' has invalid format".format(eid_str)
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    command = "show referral-cache" + "%" + eid_str
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_delegation_command
#
# Have the lisp-mr show the DDT configured delegation information.
#
@bottle.route('/lisp/show/delegations')
def lisp_show_delegations_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket,
        "show delegations"))
#enddef

#
# lisp_show_delegations_lookup
#
# Execute longest match lookup and return results.
# 
@bottle.post('/lisp/show/delegations/lookup')
def lisp_show_delegations_lookup():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid_str = bottle.request.forms.get("eid")
    if (lispconfig.lisp_validate_input_address_string(eid_str) == False):
        output = "Address '{}' has invalid format".format(eid_str)
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    command = "show delegations" + "%" + eid_str
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_site_command
#
# Have the lisp-ms process show the site registration information. Convert
# eid-prefix from format "<iid>-<eid>-<ml>" to "[<iid>]<eid>/<ml>" internal 
# format. We need to do this because URLs should avoid square brackets.
#
@bottle.route('/lisp/show/site')
@bottle.route('/lisp/show/site/<eid_prefix>')
def lisp_show_site_command(eid_prefix = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    command = "show site"

    if (eid_prefix != ""):
        command = lispconfig.lisp_parse_eid_in_url(command, eid_prefix)
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_itr_dyn_eid_command
#
# Show dynamic-EIDs from the ITR's point of view.
#
@bottle.route('/lisp/show/itr/dynamic-eid/<eid_prefix>')
def lisp_show_itr_dyn_eid_command(eid_prefix = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    command = "show itr-dynamic-eid"

    if (eid_prefix != ""):
        command = lispconfig.lisp_parse_eid_in_url(command, eid_prefix)
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_dyn_eid_command
#
# Show dynamic-EIDs from the ITR's point of view.
#
@bottle.route('/lisp/show/etr/dynamic-eid/<eid_prefix>')
def lisp_show_dyn_eid_command(eid_prefix = ""):
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    command = "show etr-dynamic-eid"

    if (eid_prefix != ""):
        command = lispconfig.lisp_parse_eid_in_url(command, eid_prefix)
    #endif
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_show_site_lookup
#
# Execute longest match lookup and return results.
# 
@bottle.post('/lisp/show/site/lookup')
def lisp_show_site_lookup():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid_str = bottle.request.forms.get("eid")
    if (lispconfig.lisp_validate_input_address_string(eid_str) == False):
        output = "Address '{}' has invalid format".format(eid_str)
        output = lisp.lisp_print_sans(output)
        return(lispconfig.lisp_show_wrapper(output))
    #endif

    command = "show site" + "%" + eid_str + "@lookup" 
    return(lispconfig.lisp_process_show_command(lisp_ipc_socket, command))
#enddef

#
# lisp_lig_command
#
# Do interactive lig.
#
@bottle.post('/lisp/lig')
def lisp_lig_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid = bottle.request.forms.get("eid")
    mr = bottle.request.forms.get("mr")
    count = bottle.request.forms.get("count")
    no_nat = "no-info" if bottle.request.forms.get("no-nat") == "yes" else ""

    #
    # Default map-resolver to localhost.
    #
    if (mr == ""): mr = "localhost"

    #
    # Check for no input. User error.
    #
    if (eid == ""):
        output = "Need to supply EID address"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif

    lig = ""
    if os.path.exists("lisp-lig.pyo"): lig = "python -O lisp-lig.pyo"
    if os.path.exists("lisp-lig.pyc"): lig = "python3.8 -O lisp-lig.pyc"
    if os.path.exists("lisp-lig.py"): lig = "python lisp-lig.py"

    #
    # Something went wrong with the install.
    #
    if (lig == ""): 
        output = "Cannot find lisp-lig.py or lisp-lig.pyo"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif

    if (count != ""): count = "count {}".format(count)

    command = '{} "{}" to {} {} {}'.format(lig, eid, mr, count, no_nat)

    output = getoutput(command)
    output = output.replace("\n", "<br>")
    output = lisp.convert_font(output)

    rloc = lisp.space(2) + "RLOC:"
    output = output.replace("RLOC:", rloc)
    empty = lisp.space(2) + "Empty,"
    output = output.replace("Empty,", empty)
    geo = lisp.space(4) + "geo:"
    output = output.replace("geo:", geo)
    elp = lisp.space(4) + "elp:"
    output = output.replace("elp:", elp)
    rle = lisp.space(4) + "rle:"
    output = output.replace("rle:", rle)
    return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
#enddef

#
# lisp_rig_command
#
# Do interactive rig.
#
@bottle.post('/lisp/rig')
def lisp_rig_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid = bottle.request.forms.get("eid")
    ddt = bottle.request.forms.get("ddt")
    follow_all = "follow-all-referrals" if \
        bottle.request.forms.get("follow") == "yes" else ""

    #
    # Default ddt-node to localhost.
    #
    if (ddt == ""): ddt = "localhost"

    #
    # Check for no input. User error.
    #
    if (eid == ""):
        output = "Need to supply EID address"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif

    rig = ""
    if os.path.exists("lisp-rig.pyo"): rig = "python -O lisp-rig.pyo"
    if os.path.exists("lisp-rig.pyc"): rig = "python3.8 -O lisp-rig.pyo"
    if os.path.exists("lisp-rig.py"): rig = "python lisp-rig.py"

    #
    # Something went wrong with the install.
    #
    if (rig == ""): 
        output = "Cannot find lisp-rig.py or lisp-rig.pyo"
        return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
    #endif

    command = '{} "{}" to {} {}'.format(rig, eid, ddt, follow_all)

    output = getoutput(command)
    output = output.replace("\n", "<br>")
    output = lisp.convert_font(output)

    ref = lisp.space(2) + "Referrals:"
    output = output.replace("Referrals:", ref)
    return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
#enddef

#
# lisp_run_geo_lig
#
# Do lookup on both supplied EIDs passed as input parameters and return
# a geo-point and geo-prefix if they are found in RLOC records.
#
def lisp_run_geo_lig(eid1, eid2):
    lig = None
    if os.path.exists("lisp-lig.pyo"): lig = "python -O lisp-lig.pyo"
    if os.path.exists("lisp-lig.pyc"): lig = "python3.8 -O lisp-lig.pyc"
    if os.path.exists("lisp-lig.py"): lig = "python lisp-lig.py"
    if (lig == None): return([None, None])

    #
    # First get a map-resolver addresss.
    #
    o = getoutput("egrep -A 2 'lisp map-resolver {' ./lisp.config")
    mr = None
    for keyword in ["address = ", "dns-name = "]:
        mr = None
        index = o.find(keyword)
        if (index == -1): continue
        mr = o[index+len(keyword)::]
        index = mr.find("\n")
        if (index == -1): continue
        mr = mr[0:index]
        break
    #endfor
    if (mr == None): return([None, None])

    #
    # Lookup EIDs in loop.
    #
    addr = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    geos = []
    for eid in [eid1, eid2]:
        
        #
        # Don't do lookups for Geo-Coordinates. Only for EIDs that are not
        # in Geo-Coordinate format.
        #
        if (addr.is_geo_string(eid)):
            geos.append(eid)
            continue
        #endif

        command = '{} "{}" to {} count 1'.format(lig, eid, mr)
        for cmd in [command, command + " no-info"]:
            output = getoutput(command)
            index = output.find("geo: ")
            if (index == -1):
                if (cmd != command): geos.append(None)
                continue
            #endif
            output = output[index+len("geo: ")::]
            index = output.find("\n")
            if (index == -1):
                if (cmd != command): geos.append(None)
                continue
            #endif
            geos.append(output[0:index])
            break
        #endfor
    #endfor
    return(geos)
#enddef

#
# lisp_geo_command
#
# Do geo lookups from lisp.lisp_geo() functions.
#
@bottle.post('/lisp/geo')
def lisp_geo_command():
    if (lispconfig.lisp_validate_user() == False): 
        return(lisp_core_login_page())
    #endif

    eid = bottle.request.forms.get("geo-point")
    eid_prefix = bottle.request.forms.get("geo-prefix")
    output = ""

    #
    # If an EID in the form of an IP address or distinguish-name, run a 
    # lig to get record from mapping database to obtain the geo data.
    #
    gs = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    geo_point = lisp.lisp_geo("")
    geo_prefix = lisp.lisp_geo("")
    point, prefix = lisp_run_geo_lig(eid, eid_prefix)

    #
    # Check EID format if geo-coordiante or return geo-point from database
    # lookup.
    #
    if (gs.is_geo_string(eid)):
        if (geo_point.parse_geo_string(eid) == False):
            output = "Could not parse geo-point format"
        #endif
    elif (point == None):
        output = "EID {} lookup could not find geo-point".format( 
            lisp.bold(eid, True))
    elif (geo_point.parse_geo_string(point) == False):
        output = "Could not parse geo-point format returned from lookup"
    #endif

    #
    # Geo-point is good, now check EID-prefix or geo-prefix format retunred
    # from database lookup.
    #
    if (output == ""):
        if (gs.is_geo_string(eid_prefix)):
            if (geo_prefix.parse_geo_string(eid_prefix) == False):
                output = "Could not parse geo-prefix format"
            #endif
        elif (prefix == None):
            output = "EID-prefix {} lookup could not find geo-prefix".format( \
                lisp.bold(eid_prefix, True))
        elif (geo_prefix.parse_geo_string(prefix) == False):
            output = "Could not parse geo-prefix format returned from lookup"
        #endif
    #endif

    #
    # No input errors. Return good results. Otherwise, error response in
    # variable 'output'.
    #
    if (output == ""):
        eid = "" if (eid == point) else ", EID {}".format(eid)
        eid_prefix = "" if (eid_prefix == prefix) else \
            ", EID-prefix {}".format(eid_prefix)

        point_str = geo_point.print_geo_url()
        prefix_str = geo_prefix.print_geo_url()
        km = geo_prefix.radius
        dd_point = geo_point.dms_to_decimal()
        dd_point = (round(dd_point[0], 6), round(dd_point[1], 6))
        dd_prefix = geo_prefix.dms_to_decimal()
        dd_prefix = (round(dd_prefix[0], 6), round(dd_prefix[1], 6))
        distance = round(geo_prefix.get_distance(geo_point), 2)
        inside = "inside" if geo_prefix.point_in_circle(geo_point) else \
            "outside"
    
        spo = lisp.space(2)
        spe = lisp.space(1)
        sd = lisp.space(3)

        output = ("Geo-Point:{}{} {}{}<br>Geo-Prefix:{}{} {}, {} " + \
            "kilometer radius{}<br>").format(spo, point_str, dd_point, eid,
            spe, prefix_str, dd_prefix, km, eid_prefix)
        output += "Distance:{}{} kilometers, point is {} of circle".format(sd,
            distance, lisp.bold(inside, True))
    #endif
    return(lispconfig.lisp_show_wrapper(lisp.lisp_print_cour(output)))
#enddef

#
# lisp_get_info_source
#
# See if this source has sent an Info-Request and we are caching it so we
# can proxy Map-Request for it. Either address OR nonce can be supplied to
# determine if we are doing a lookup based on address or nonce.
#
def lisp_get_info_source(addr_str, port, nonce):
    if (addr_str != None):
        for info_source in list(lisp.lisp_info_sources_by_address.values()):
            info_source_str = info_source.address.print_address_no_iid()
            if (info_source_str == addr_str and info_source.port == port): 
                return(info_source)
            #endif
        #endfor
        return(None)
    #endif

    if (nonce != None):
        if (nonce not in lisp.lisp_info_sources_by_nonce): return(None)
        return(lisp.lisp_info_sources_by_nonce[nonce])
    #endif
    return(None)
#enddef

#
# lisp_nat_proxy_map_request
#
# Grab the nonce from the Map-Request, store it in the info-source data
# structure and modify the ITR-RLOCs field so the Map-Reply comes back to us.
#
def lisp_nat_proxy_map_request(lisp_sockets, info_source, packet):

    #
    # Parse and move packet pointer to beginning of Map-Request.
    #
    ecm = lisp.lisp_ecm(0)
    packet = ecm.decode(packet)
    if (packet == None):
        lisp.lprint("Could not decode ECM packet")
        return(True)
    #endif

    header = lisp.lisp_control_header()
    if (header.decode(packet) == None):
        lisp.lprint("Could not decode control header")
        return(True)
    #endif
    if (header.type != lisp.LISP_MAP_REQUEST): 
        lisp.lprint("Received ECM without Map-Request inside")
        return(True)
    #endif

    #
    # We are at the Map-Request header.
    #
    map_request = lisp.lisp_map_request()
    packet = map_request.decode(packet, None, 0)
    nonce = map_request.nonce
    addr_str = info_source.address.print_address_no_iid()

    #
    # Print Map-Request again to show what has changed.
    #
    map_request.print_map_request()

    lisp.lprint("Process {} from info-source {}, port {}, nonce 0x{}". \
        format(lisp.bold("nat-proxy Map-Request", False), 
        lisp.red(addr_str, False), info_source.port, 
        lisp.lisp_hex_string(nonce)))

    #
    # Store nonce in info-source and cache in dictionary array. We will need
    # to find it based on nonce when the Map-Reply is returned to us.
    #
    info_source.cache_nonce_for_info_source(nonce)

    #
    # Do not timeout Map-Requests that are subscription-requests. Because a
    # Map-Notify can be triggered any time back to the requester.
    #
    info_source.no_timeout = map_request.subscribe_bit

    #
    # Check if we are already in ITR-RLOCs list. If so, this could be looping.
    # Return so the Map-Request can be processed in the regular fashion (that
    # is, send on DDT or to a Map-Resolver.
    #
    for itr_rloc in map_request.itr_rlocs:
        if (itr_rloc.is_local()): return(False)
    #endfor

    #
    # Store new ITR-RLOCs list.
    #
    myself = lisp.lisp_myrlocs[0]
    map_request.itr_rloc_count = 0
    map_request.itr_rlocs = []
    map_request.itr_rlocs.append(myself)

    packet = map_request.encode(None, 0)
    map_request.print_map_request()
    
    deid = map_request.target_eid
    if (deid.is_ipv6()): 
        myself_v6 = lisp.lisp_myrlocs[1]
        if (myself_v6 != None): myself = myself_v6
    #endif

    #
    # Send ECM based Map-Request to Map-Resolver.
    #
    ms = lisp.lisp_is_running("lisp-ms")
    lisp.lisp_send_ecm(lisp_sockets, packet, deid, lisp.LISP_CTRL_PORT, 
        deid, myself, to_ms=ms, ddt=False)
    return(True)
#enddef

#
# lisp_nat_proxy_reply
#
# Grab the nonce from the Map-Request, store it in the info-source data
# structure and modify the ITR-RLOCs field so the Map-Reply/Notify comes 
# back to us.
#
def lisp_nat_proxy_reply(lisp_sockets, info_source, packet, mr_or_mn):
    addr_str = info_source.address.print_address_no_iid()
    port = info_source.port
    nonce = info_source.nonce

    mr_or_mn = "Reply" if mr_or_mn else "Notify"
    mr_or_mn = lisp.bold("nat-proxy Map-{}".format(mr_or_mn), False)
    
    lisp.lprint("Forward {} to info-source {}, port {}, nonce 0x{}".format( \
        mr_or_mn, lisp.red(addr_str, False), port, 
        lisp.lisp_hex_string(nonce)))

    #
    # Send on socket with arguments passed from IPC message.
    #
    dest = lisp.lisp_convert_4to6(addr_str)
    lisp.lisp_send(lisp_sockets, dest, port, packet)
#enddef

#
# lisp_core_dispatch_packet
#
# Look at packet type and decide which process to send it to.
#
def lisp_core_dispatch_packet(lisp_sockets, source, sport, packet):
    global lisp_ipc_socket

    header = lisp.lisp_control_header()
    if (header.decode(packet) == None):
        lisp.lprint("Could not decode control header")
        return
    #endif

    #
    # In the lispers.net implementation any LISP system can process Info-
    # Requests. We'll have the lisp-core process do this. lig/rig and the
    # lisp-etr process sends Info-Requests messages. Since the lisp-core
    # process processes Info-Requests, it responds with Info-Reply messages.
    # And they are sent to the emphemeral port so go straight back to the lig/
    # rig, or etr-processes.
    #
    if (header.type == lisp.LISP_NAT_INFO):
        if (header.info_reply == False):
            lisp.lisp_process_info_request(lisp_sockets, packet, source, sport,
                lisp.lisp_ms_rtr_list)
        #endif            
        return
    #endif

    local_packet = packet
    packet = lisp.lisp_packet_ipc(packet, source, sport)

    #
    # Map-Registers, Echos, and Map-Notify-Acks go to the lisp-ms process.
    #
    if (header.type in (lisp.LISP_MAP_REGISTER, lisp.LISP_MAP_NOTIFY_ACK)):
        lisp.lisp_ipc(packet, lisp_ipc_socket, "lisp-ms")
        return
    #endif

    #
    # Map-Reply messages go to ITRs.
    #
    if (header.type == lisp.LISP_MAP_REPLY):
        map_reply = lisp.lisp_map_reply()
        map_reply.decode(local_packet)

        info_source = lisp_get_info_source(None, 0, map_reply.nonce)
        if (info_source):
            lisp_nat_proxy_reply(lisp_sockets, info_source, local_packet, True)
        else:
            lig = "/tmp/lisp-lig"
            if (os.path.exists(lig)):
                lisp.lisp_ipc(packet, lisp_ipc_socket, lig)
            else:  
                lisp.lisp_ipc(packet, lisp_ipc_socket, "lisp-itr")
            #endif
        #endif
        return
    #endif

    #
    # Map-Notify messages go to ITRs.
    #
    if (header.type == lisp.LISP_MAP_NOTIFY):
        map_notify = lisp.lisp_map_notify(lisp_sockets)
        map_notify.decode(local_packet)

        info_source = lisp_get_info_source(None, 0, map_notify.nonce)
        if (info_source):
            lisp_nat_proxy_reply(lisp_sockets, info_source, local_packet, 
                False)
        else:
            lig = "/tmp/lisp-lig"
            if (os.path.exists(lig)):
                lisp.lisp_ipc(packet, lisp_ipc_socket, lig)
            else:  
                process = "lisp-rtr" if lisp.lisp_is_running("lisp-rtr") else \
                    "lisp-etr"
                lisp.lisp_ipc(packet, lisp_ipc_socket, process)
            #endif
        #endif
        return
    #endif

    #
    # Map-Referral messages go to MRs. But if a rig client is running on
    # this machine, IPC it to the client.
    #
    if (header.type == lisp.LISP_MAP_REFERRAL): 
        rig = "/tmp/lisp-rig"
        if (os.path.exists(rig)):
            lisp.lisp_ipc(packet, lisp_ipc_socket, rig)
        else:  
            lisp.lisp_ipc(packet, lisp_ipc_socket, "lisp-mr")
        #endif
        return
    #endif
        
    #
    # Map-Requests go to ETRs/RTRs when they RLOC-probes or SMR-invoked 
    # requests. And Map-Requests go to ITRs when they are SMRs.
    #
    if (header.type == lisp.LISP_MAP_REQUEST): 
        process = "lisp-itr" if (header.is_smr()) else "lisp-etr"

        #
        # RLOC-probes are received specifically by the process by pcaping
        # on port 4342.
        #
        if (header.rloc_probe): return

        lisp.lisp_ipc(packet, lisp_ipc_socket, process)
        return
    #endif

    #
    # ECMs can go to a lot of places. They are sent ITR->MR, LIG->MR, MR->DDT,
    # MR->MS, and MS->ETR.  If we find an Info-Request source, this core 
    # process will process the Map-Request so it can get the Map-Reply and 
    # forward to the translated address and port of a client behind a NAT.
    #
    if (header.type == lisp.LISP_ECM): 
        info_source = lisp_get_info_source(source, sport, None)
        if (info_source):
            if (lisp_nat_proxy_map_request(lisp_sockets, info_source, 
                local_packet)): return
        #endif
        
        process = "lisp-mr"
        if (header.is_to_etr()): 
            process = "lisp-etr"
        elif (header.is_to_ms()): 
            process = "lisp-ms"
        elif (header.is_ddt()):
            if (lisp.lisp_is_running("lisp-ddt")): 
                process = "lisp-ddt"
            elif (lisp.lisp_is_running("lisp-ms")): 
                process = "lisp-ms"
            #endif
        elif (lisp.lisp_is_running("lisp-mr") == False): 
            process = "lisp-etr"
        #endif
        lisp.lisp_ipc(packet, lisp_ipc_socket, process)
    #endif
    return
#enddef

#
# lisp_ssl_server
#
# Setup cherrypy server that supports SSL connections. This is so we can
# protect passwords that flow over an http connection.
#
# Used the following to create private key and cert:
#
# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
#
class lisp_ssl_server(bottle.ServerAdapter):
    def run(self, hand):
        cert = "./lisp-cert.pem"

        #
        # Use user provided lisp-cert.pem if it exists. Otherwise use the
        # lispers.net default lisp-cert.pem.default file.
        #
        if (os.path.exists(cert) == False):
            os.system("cp ./lisp-cert.pem.default {}".format(cert))
            lisp.lprint(("{} does not exist, creating a copy from lisp-" + \
                "cert.pem.default").format(cert))
        #endif

        server = wsgi_server((self.host, self.port), hand)
        server.ssl_adapter = ssl_adaptor(cert, cert, None)
        try: 
            server.start()  
        finally: 
            server.stop()  
        #endtry
    #enddef
#endclass

#
# lisp_bottle_ipv4_process
#
# Variable bottle_port can take on the following values:
#
# 8080  - run web server on port 8080 using SSL
# 443   - run web server on port 443 using SSL
# -8080 - run web server on port 8080 with no SSL (no secure connection).
#
# Any other port is accepted and used with SSL. If a "-" precedes it, it is
# used with no SSL.
#
def lisp_bottle_ipv4_process(bottle_port):
    lisp.lisp_set_exception()

    #
    # No security. Usually for testing purposes or complexities installing
    # OpenSSL.
    #
    if (bottle_port < 0):
        bottle.run(host="0.0.0.0", port=-bottle_port)
        return
    #endif

    bottle.server_names["lisp-ssl-server"] = lisp_ssl_server

    #
    # If you want to run without SSL, do this and comment out the above call.
    #
    try:
        bottle.run(host="0.0.0.0", port=bottle_port, server="lisp-ssl-server",
            fast=True)
    except:
        lisp.lprint("Could not startup lisp-ssl-server, running insecurely")
        bottle.run(host="0.0.0.0", port=bottle_port)
    #endtry
    return
#enddef

#
# lisp_bottle_ipv6_process
#
# Start HTTP server on port 8080. But bottle does not support IPv6 yet so
# we comment out the call.
#
def lisp_bottle_ipv6_process():
    lisp.lisp_set_exception()
#   run(host="0::0", port=8080)
    return
#enddef

#
# lisp_check_processes
#
# Check to see if any component has gone down when it should be running. And
# if it comes up when it should be running, download the configuration commands
# it is responsible for.
#
def lisp_check_processes(lisp_socket):
    lisp.lisp_set_exception()
    status = {"lisp-itr" : False, "lisp-etr" : False, "lisp-rtr" : False,
              "lisp-mr" : False, "lisp-ms" : False, "lisp-ddt" : False}
 
    while (True):
        time.sleep(1)
        old_status = status
        status = {}

        for process in old_status:
            status[process] = lisp.lisp_is_running(process)
            if (old_status[process] == status[process]): continue

            lisp.lprint("*** Process '{}' has {} ***".format(process,
                "come up" if status[process] else "gone down"))

            #
            # If process has come up, send configuration commands.
            #
            if (status[process] == True):
                lisp.lisp_ipc_lock.acquire()
                lispconfig.lisp_send_commands(lisp_socket, process)
                lisp.lisp_ipc_lock.release()
            #endif
        #endfor
    #endwhile
    return
#enddef

#
# lisp_timeout_info_sources
#
# Timeout info sources from lisp_info_source_list{}.
#
def lisp_timeout_info_sources():
    lisp.lisp_set_exception()
    timeout = 60

    while (True):
        time.sleep(timeout)

        delete_list = []
        now = lisp.lisp_get_timestamp()

        #
        # Find entries that are greater than 1 minute old.
        #
        for key in lisp.lisp_info_sources_by_address:
            info_source = lisp.lisp_info_sources_by_address[key]
            if (info_source.no_timeout): continue
            if (info_source.uptime + timeout < now): continue

            delete_list.append(key)

            nonce = info_source.nonce
            if (nonce == None): continue
            if (nonce in lisp.lisp_info_sources_by_nonce):
                lisp.lisp_info_sources_by_nonce.pop(nonce)
            #endif
        #endfor

        # 
        # Go through delete list to remove from dictionary array.
        #
        for key in delete_list: 
            lisp.lisp_info_sources_by_address.pop(key)
        #endfor
    #endwhile
    return
#enddef

#
# lisp_core_control_packet_process
#
# Listen for IPC messages from LISP componment processes. They want to send
# control packets out on the network from UDP port 4342.
#
def lisp_core_control_packet_process(lisp_ipc_control_socket, lisp_sockets):
    lisp.lisp_set_exception()
    while (True):
        try: packet_data = lisp_ipc_control_socket.recvfrom(9000)
        except: return(["", "", "", ""])
        data = packet_data[0].split(b"@")
        source = packet_data[1]

        opcode = data[0].decode()
        dest = data[1].decode()
        port = int(data[2])
        packet = data[3::]

        #
        # For py3, decode from byte string array to string. Noop for py2.
        #
        if (len(packet) > 1): 
            packet = lisp.lisp_bit_stuff(packet)
        else:
            packet = packet[0]
        #endif

        if (opcode != "control-packet"):
            lisp.lprint(("lisp_core_control_packet_process() received " + \
                "unexpected control-packet, message ignored"))
            continue
        #endif

        lisp.lprint(("{} {} bytes from {}, dest/port: {}/{}, control-" + \
            "packet: {}").format(lisp.bold("Receive", False), len(packet), 
            source, dest, port, lisp.lisp_format_packet(packet)))

        #
        # Check if this is a Map-Reply to a ephem port and we have an
        # Info-Source for the nonce in the Map-Reply. If so, call
        # lisp_core_dispatch_packet().
        #
        header = lisp.lisp_control_header()
        header.decode(packet)
        if (header.type == lisp.LISP_MAP_REPLY):
            map_reply = lisp.lisp_map_reply()
            map_reply.decode(packet)
            if (lisp_get_info_source(None, 0, map_reply.nonce)):
                lisp_core_dispatch_packet(lisp_sockets, source, port, packet)
                continue
            #endif
        #endif

        #
        # This is a Map-Notify that the lisp-etr process received and it
        # has determined it is a (S,G) multicast Map-Notify that the lisp-itr
        # process needs to process to update its map-cache.
        #
        if (header.type == lisp.LISP_MAP_NOTIFY and source == "lisp-etr"):
            ipc = lisp.lisp_packet_ipc(packet, source, port)
            lisp.lisp_ipc(ipc, lisp_ipc_socket, "lisp-itr")
            continue
        #endif

        #
        # We are sending on a udp46 socket, so if the destination is IPv6
        # we have an address format we can use. If destination is IPv4 we
        # need to put the address in a IPv6 IPv4-compatible format.
        #
        addr = lisp.lisp_convert_4to6(dest)
        addr = lisp.lisp_address(lisp.LISP_AFI_IPV6, "", 128, 0)
        if (addr.is_ipv4_string(dest)): dest = "::ffff:" + dest
        addr.store_address(dest)

        #
        # Send on socket with arguments passed from IPC message.
        #
        lisp.lisp_send(lisp_sockets, addr, port, packet)
    #endwhile
    return
#enddef

#
# lisp_cp_lisp_config
#
# The file ./lisp.config does not exist. Copy all commands from file
# lisp.config.example up to the dashed line.
#
def lisp_core_cp_lisp_config():
    f = open("./lisp.config.example", "r"); lines = f.read(); f.close()
    f = open("./lisp.config", "w")
    lines = lines.split("\n")
    for line in lines:
        f.write(line + "\n")
        if (line[0] == "#" and line[-1] == "#" and len(line) >= 4):
            dashes = line[1:-2]
            dash_check = len(dashes) * "-"
            if (dashes == dash_check): break
        #endif
    #endfor
    f.close()
    return
#enddef

#
# lisp_core_startup
#
# Intialize this LISP core process. This function returns a LISP network
# listen socket.
#
def lisp_core_startup(bottle_port):
    global lisp_build_date
    global lisp_control_listen_socket
    global lisp_ipc_socket
    global lisp_ipc_control_socket
    global lisp_sockets
    global lisp_encap_socket

    lisp.lisp_i_am("core")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("core-process starting up")
    lisp.lisp_uptime = lisp.lisp_get_timestamp()
    lisp.lisp_version = getoutput("cat lisp-version.txt")
    lisp_build_date = getoutput("cat lisp-build-date.txt")

    #
    # Get local address for source RLOC for encapsulation.
    #
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Only the core process uses a lock so it can send commands and show
    # output in parallel to the component processes.
    #
    lisp.lisp_ipc_lock = multiprocessing.Lock()

    #
    # If this is a development build, put a plus after the version number.
    # A development build is a build done from a directory that has the
    # lisp.py file. Released builds built from the build directory will build
    # only .pyo files.
    #
    if (os.path.exists("lisp.py")): lisp.lisp_version += "+"

    #
    # Open network socket to listen (and send) on port 4342. We may want
    # a Map-Resolver to respond with a source-address of an anycast address
    # so firewalls and NAT can return responses to ITRs or lig/rig clients.
    #
    address = "0.0.0.0" if lisp.lisp_is_raspbian() else "0::0"
    if (os.getenv("LISP_ANYCAST_MR") == None or lisp.lisp_myrlocs[0] == None):
        lisp_control_listen_socket = lisp.lisp_open_listen_socket(address,
            str(lisp.LISP_CTRL_PORT))
    else:
        address = lisp.lisp_myrlocs[0].print_address_no_iid()
        lisp_control_listen_socket = lisp.lisp_open_listen_socket(address, 
            str(lisp.LISP_CTRL_PORT))
    #endif
    lisp.lprint("Listen on {}, port 4342".format(address))

    #
    # Open datagram socket for 4341. We will not listen on it. We just don't
    # want the kernel to send port unreachables to ITRs and PITRs. If another
    # data-plane is running, it may listen on the data port 4341. Let it.
    #
    if (lisp.lisp_external_data_plane() == False):
        lisp_encap_socket = lisp.lisp_open_listen_socket(address,
            str(lisp.LISP_DATA_PORT))
        lisp.lprint("Listen on {}, port 4341".format(address))
    #endif

    #
    # Open internal socket to send from to LISP components for configuration
    # events.
    #
    lisp_ipc_socket = lisp.lisp_open_send_socket("lisp-core", "")
    lisp_ipc_socket.settimeout(3)

    #
    # Open internal socket 'lisp-core-pkt' so LISP components can send
    # control packets from UDP port 4342 via this lisp-core process.
    #
    lisp_ipc_control_socket = lisp.lisp_open_listen_socket("", "lisp-core-pkt")

    lisp_sockets = [lisp_control_listen_socket, lisp_control_listen_socket, 
                    lisp_ipc_socket]

    #
    # Start a thread to listen for control packet from LISP component 
    # processes.
    #
    threading.Thread(target=lisp_core_control_packet_process,
        args=[lisp_ipc_control_socket, lisp_sockets]).start()

    #
    # Start a new thread to monitor configuration file changes. Do quick check
    # to see if this is a first-time startup for the system. Check to see if
    # lisp.config was not created by user.
    #
    if (os.path.exists("./lisp.config") == False):
        lisp.lprint(("./lisp.config does not exist, creating a copy " + \
            "from lisp.config.example"))
        lisp_core_cp_lisp_config()
    #endif

    #
    # Check if we are a map-server listening on a multicast group. This
    # is a decentralized-push-xtr with a multicast map-server address.
    #
    lisp_check_decent_xtr_multicast(lisp_control_listen_socket)

    threading.Thread(target=lispconfig.lisp_config_process, 
        args=[lisp_ipc_socket]).start()

    #
    # Start a new thread to run bottle for each address-family.
    #
    threading.Thread(target=lisp_bottle_ipv4_process, 
        args=[bottle_port]).start()
    threading.Thread(target=lisp_bottle_ipv6_process, args=[]).start()

    #
    # Start a new thread to run LISP component health check.
    #
    threading.Thread(target=lisp_check_processes, 
        args=[lisp_ipc_socket]).start()

    #
    # Start a new thread to run LISP component health check.
    #
    threading.Thread(target=lisp_timeout_info_sources).start()
    return(True)
#enddef

#
# lisp_core_shutdown
#
# Shutdown process.
#
def lisp_core_shutdown():

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_ipc_socket, "lisp-core")
    lisp.lisp_close_socket(lisp_ipc_control_socket, "lisp-core-pkt")
    lisp.lisp_close_socket(lisp_control_listen_socket, "")
    lisp.lisp_close_socket(lisp_encap_socket, "")
    return
#enddef

#
# lisp_check_decent_xtr_multicast
#
# Check to see if "decentralized-push-xtr = yes" and if any map-server clause
# has a multicast address configured. If so, setsockopt so we can receive
# multicast Map-Register messages.
#
# This function is robust enough for when a user copies lisp.config.example
# into lisp.config. We have to ignore text after "#- ... -#".
#
def lisp_check_decent_xtr_multicast(lisp_socket):

    f = open("./lisp.config", "r"); lines = f.read(); f.close()
    lines = lines.split("\n")

    #
    # Check if "decentralized-push-xtr = yes" is in the "lisp xtr-parameters"
    # command clause.
    #
    decent_xtr = False
    for line in lines:
        if (line[0:1] == "#-" and line[-2:-1] == "-#"): break
        if (line == "" or line[0] == "#"): continue
        if (line.find("decentralized-push-xtr = yes") == -1): continue
        decent_xtr = True
        break
    #endfor
    if (decent_xtr == False): return
    
    #
    # Check if "lisp map-server" command clauses have multicast addresses
    # configured.
    #
    groups = []
    in_clause = False
    for line in lines:
        if (line[0:1] == "#-" and line[-2:-1] == "-#"): break
        if (line == "" or line[0] == "#"): continue
            
        if (line.find("lisp map-server") != -1):
            in_clause = True
            continue
        #endif
        if (line[0] == "}"):
            in_clause = False
            continue
        #endif

        #
        # Parse address. Look at high-order byte.
        #
        if (in_clause and line.find("address = ") != -1):
            group = line.split("address = ")[1]
            ho_byte = int(group.split(".")[0])
            if (ho_byte >= 224 and ho_byte < 240): groups.append(group)
        #endif
    #endfor
    if (group == []): return

    #
    # Find eth0 IP address.
    #
    out = getoutput('ifconfig eth0 | egrep "inet "')
    if (out == ""): return
    intf_addr = out.split()[1]

    #
    # Set socket options on socket.
    #
    i = socket.inet_aton(intf_addr)
    for group in groups:
        lisp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lisp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, i)
        g = socket.inet_aton(group) + i
        lisp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, g)
        lisp.lprint("Setting multicast listen socket for group {}".format( \
            group))
    #endfor
    return
#enddef

#------------------------------------------------------------------------------

bottle_port = int(sys.argv[1]) if (len(sys.argv) > 1) else 8080

#
# Main entry point for process.
#
if (lisp_core_startup(bottle_port) == False):
    lisp.lprint("lisp_core_startup() failed")
    lisp.lisp_print_banner("lisp-core abnormal exit")
    exit(1)
#endif

while (True):

    #
    # Process either commands, an IPC data-packet (for testing), or any
    # protocol message on the IPC listen socket..
    #
    opcode, source, port, packet = \
        lisp.lisp_receive(lisp_control_listen_socket, False)
    if (source == ""): break

    #
    # Process received network packet.
    #
    source = lisp.lisp_convert_6to4(source)
    lisp_core_dispatch_packet(lisp_sockets, source, port, packet)
#endwhile

lisp_core_shutdown()
lisp.lisp_print_banner("lisp-core normal exit")
exit(0)

#------------------------------------------------------------------------------
