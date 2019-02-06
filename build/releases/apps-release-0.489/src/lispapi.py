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
# lispapi.py
#
# This file containse API definitions that users call in their python programs.
# 
# When this file is changed, remote file lispapi.html and click the "API
# Documentation" button on the landing page to build a pydoc lispapi.html
# file.
#
# -----------------------------------------------------------------------------

"""

This python module is called by client network applications that want to
interface with the lispers.net implementation of LISP. For questions, bug
reports, or feature requests, contact support@lispers.net.

Here is a program calling sequence:

>>> import lispapi
>>> att = lispapi.api_init("att.net", "root")
>>> vz = lispapi.api_init("verizon.net", "root")
>>>
>>> att_rtr = att.is_rtr_enabled()
>>> vz_ms = vz.is_ms_enabled()
>>>
>>> print "AT&T has RTR:, att_rtr 
AT&T has RTR: True
>>> print "VZ has MS:", vz_ms
VZ has MS: False
>>>
>>> vz.enable_ms()
>>> print "VZ has MS:", vz.is_ms_enabled()
VZ has MS: True
>>>

"""

#------------------------------------------------------------------------------

import requests
import json
import os

REQ_TIMEOUT = 3

#------------------------------------------------------------------------------

class api_init():
    def __init__(self, host, user, pw=None, port=8080, api_debug=False, 
        do_get=True):
        """ Required to be first call by API user. Returns instance that must
            be stored by caller. If 'pw' is None, then the password will be
            obtained from the environment variable LISPAPI_PW. If you want the
            LISP API to return debug information, pass argument api_debug=True.
            If 'port' is negative, use http versus https.
        """

        self.host = host
        self.user = user
        if (pw == None): pw = os.getenv("LISPAPI_PW_" + host)
        if (pw == None): pw = os.getenv("LISPAPI_PW")
        self.pw = pw

        http = "https://"
        if (port < 0):
            port = -port
            http = http.replace("s", "")
        #endif
        self.url = http + self.host + ":{}/lisp/api/".format(str(port))

        self.enable_status = None
        self.debug_status = None
        self.api_debug = api_debug
        self.enable_status = None
        self.debug_status = None
        self.xtr_parameters = None

        #
        # Test username/password by getting LISP component status. Store it
        # locally so we can do quick gets later or put individual entries.
        #
        if (do_get):
            self.get_enable()
            self.get_debug()
            self.get_xtr_parameters()
        #endif
    #enddef

    def api_print(self):
        """ Print contents of lispapi class. Returns a string. """
        print("url: {}@{}, enable-status: {}, debug-status: {}".format( \
            self.user, self.url, self.enable_status, self.debug_status))
    #enddef

    def api_enable_debug(self):
        """ Enable debug output for this LISP API. """
        self.api_debug = True
    #enddef

    def api_disable_debug(self):
        """ Disable debug output for this LISP API. """
        self.api_debug = False
    #enddef

    def get_enable(self, force_query=False):
        """ Returns "lisp enable" status for system. Returns a dictionary
            array.
        """
        if (force_query == False and self.enable_status != None): 
            return(self.enable_status)
        #endif
        data = self.__get("lisp enable")
        self.enable_status = data
        return(data)
    #enddef

    def get_debug(self):
        """ Returns "lisp debug" status for system. Returns a dictionary
            array.
        """
        if (self.debug_status != None): return(self.debug_status)
        data = self.__get("lisp debug")
        self.debug_status = data
        return(data)
    #enddef

    def get_xtr_parameters(self):
        """ Returns the "lisp xtr-parameters" settings for the system. Returns
            a dictionary array.
        """
        if (self.xtr_parameters != None): return(self.xtr_parameters)
        data = self.__get("lisp xtr-parameters")
        self.xtr_parameters = data
        return(data)
    #enddef

    def is_itr_enabled(self):
        """ Return True if ITR is enabled on system. """
        return(self.enable_status and self.enable_status["itr"] == "yes")
    #enddef

    def is_etr_enabled(self):
        """ Return True if ETR is enabled on system. """
        return(self.enable_status and self.enable_status["etr"] == "yes")
    #enddef

    def is_rtr_enabled(self):
        """ Return True if RTR is enabled on system. """
        return(self.enable_status and self.enable_status["rtr"] == "yes")
    #enddef

    def is_mr_enabled(self):
        """ Return True if MR is enabled on system. """
        return(self.enable_status and 
            self.enable_status["map-resolver"] == "yes")
    #enddef

    def is_ms_enabled(self):
        """ Return True if Map-Server is enabled on system. """
        return(self.enable_status and 
            self.enable_status["map-server"] == "yes")
    #enddef

    def is_ddt_enabled(self):
        """ Return True if DDT-node is enabled on system. """
        return(self.enable_status and self.enable_status["ddt-node"] == "yes")
    #enddef

    def is_itr_debug_enabled(self):
        """ Return True if ITR debug looging is enabled on system. """
        return(self.debug_status and self.debug_status["itr"] == "yes")
    #enddef

    def is_etr_debug_enabled(self):
        """ Return True if ETR debug looging is enabled on system. """
        return(self.debug_status and self.debug_status["etr"] == "yes")
    #enddef

    def is_rtr_debug_enabled(self):
        """ Return True if RTR debug looging is enabled on system. """
        return(self.debug_status and self.debug_status["rtr"] == "yes")
    #enddef

    def is_mr_debug_enabled(self):
        """ Return True if Map-Resolver debug looging is enabled on system. """
        return(self.debug_status and 
            self.debug_status["map-resolver"] == "yes")
    #enddef

    def is_ms_debug_enabled(self):
        """ Return True if Map-Server debug looging is enabled on system. """
        return(self.debug_status and self.debug_status["map-server"] == "yes")
    #enddef

    def is_ddt_debug_enabled(self):
        """ Return True if DDT-node debug looging is enabled on system. """
        return(self.debug_status and self.debug_status["ddt-node"] == "yes")
    #enddef

    def enable_itr(self):
        """ Activate ITR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["itr"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_etr(self):
        """ Activate ETR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["etr"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_rtr(self):
        """ Activate RTR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["rtr"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_mr(self):
        """ Activate Map-Resolver functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["map-resolver"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_ms(self):
        """ Activate Map-Server functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["map-server"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_ddt(self):
        """ Activate DDT-node functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["ddt-node"] = "yes"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_itr(self):
        """ Deactivate ITR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["itr"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_etr(self):
        """ Deactivate ETR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["etr"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_rtr(self):
        """ Deactivate RTR functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["rtr"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_mr(self):
        """ Deactivate Map-Resolver functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["map-resolver"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_ms(self):
        """ Deactivate Map-Server functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["map-server"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def disable_ddt(self):
        """ Deactivate DDT-node functionality on system. """
        if (self.enable_status == None): return

        self.enable_status["ddt-node"] = "no"
        data = self.__put("lisp enable", self.enable_status)
        return(self.__error(data) == False)
    #enddef

    def enable_core_debug(self):
        """ Activate the LISP core process debug logging. """
        if (self.debug_status == None): return

        self.debug_status["core"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_itr_debug(self):
        """ Activate ITR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["itr"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_etr_debug(self):
        """ Activate ETR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["etr"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_rtr_debug(self):
        """ Activate RTR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["rtr"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_mr_debug(self):
        """ Activate Map-Resolver debug logging. """
        if (self.debug_status == None): return

        self.debug_status["map-resolver"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_ms_debug(self):
        """ Activate Map-Server debug logging. """
        if (self.debug_status == None): return

        self.debug_status["map-server"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def enable_ddt_debug(self):
        """ Activate DDT-node debug logging. """
        if (self.debug_status == None): return

        self.debug_status["ddt-node"] = "yes"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_core_debug(self):
        """ Deactivate the LISP core process debug logging. """
        if (self.debug_status == None): return

        self.debug_status["core"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_itr_debug(self):
        """ Deactivate ITR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["itr"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_etr_debug(self):
        """ Deactivate ETR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["etr"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_rtr_debug(self):
        """ Deactivate RTR debug logging. """
        if (self.debug_status == None): return

        self.debug_status["rtr"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_mr_debug(self):
        """ Deactivate Map-Resolver debug logging. """
        if (self.debug_status == None): return

        self.debug_status["map-resolver"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_ms_debug(self):
        """ Deactivate Map-Server debug logging. """
        if (self.debug_status == None): return

        self.debug_status["map-server"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def disable_ddt_debug(self):
        """ Deactivate DDT-node debug logging. """
        if (self.debug_status == None): return

        self.debug_status["ddt-node"] = "no"
        data = self.__put("lisp debug", self.debug_status)
        return(self.__error(data) == False)
    #enddef

    def add_user_account(self, username, password):
        """ Configures a user-account command. Returns True if successful. """
        if (self.enable_status == None): return

        data = self.__put("lisp user-account", 
            { "username" : username, "password" : password})
        return(self.__error(data) == False)
    #enddef

    def delete_user_account(self, username):
        """ Removes a user-account command. Returns True if successful. """
        if (self.enable_status == None): return

        data = self.__delete("lisp user-account", { "username" : username })
        return(self.__error(data) == False)
    #enddef

    def enable_itr_security(self):
        """ Enable AES encryption for packets ITRs or RTRs encapsulate. """
        if (self.enable_status == None): return

        self.xtr_parameters["data-plane-security"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_itr_security(self):
        """ Disable AES encryption for packets ITRs or RTRs encapsulate. """
        if (self.enable_status == None): return

        self.xtr_parameters["data-plane-security"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def enable_xtr_nat_traversal(self):
        """ Enable NAT-traversal functionality on ITR and ETR. Make sure
            your database-mapping configuration contains an interface 
            (versus an address) for an RLOC."""
        if (self.enable_status == None): return

        self.xtr_parameters["nat-traversal"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_xtr_nat_traversal(self):
        """ Disable NAT-traversal functionality in an ITR and ETR."""
        if (self.enable_status == None): return

        self.xtr_parameters["nat-traversal"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def enable_xtr_rloc_probing(self):
        """ Enable RLOC-probing functionality on an ITR or RTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["rloc-probing"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_xtr_rloc_probing(self):
        """ Disable RLOC-probing functionality on an ITR and RTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["rloc-probing"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def enable_xtr_nonce_echoing(self):
        """ Enable Nonce-Echoing functionality on an ITR or RTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["nonce-echoing"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_xtr_nonce_echoing(self):
        """ Disable Nonce-Echoing functionality on an ITR and RTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["nonce-echoing"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def enable_xtr_data_plane_logging(self):
        """ Enable data-plane logging functionality on an xTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["data-plane-logging"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_xtr_data_plane_logging(self):
        """ Disable data-plane logging functionality on an xTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["data-plane-logging"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def enable_xtr_flow_logging(self):
        """ Enable packet flow logging functionality on an xTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["flow-logging"] = "yes"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def disable_xtr_flow_logging(self):
        """ Disable packet flow logging functionality on an xTR."""
        if (self.enable_status == None): return

        self.xtr_parameters["flow-logging"] = "no"
        data = self.__put("lisp xtr-parameters", self.xtr_parameters)
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def add_mr_ddt_root(self, address=""):
        """ Configure the address of a LISP-DDT root node. Variable 'address'
            is an IPv4 or IPv6 address string. Returns error string or "good"
            when successful.
        """
        if (address == ""): return("no address supplied")
        if (self.__check_address_syntax(address) == False): 
            return("bad address syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__put("lisp ddt-root", { "address" : address })
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_mr_ddt_root(self, address=""):
        """ Deconfigure the address of a LISP-DDT root node. Variable 'address'
            is an IPv4 or IPv6 address string. Returns error string or "good"
            when successful.
        """
        if (address == ""): return("no address supplied")
        if (self.__check_address_syntax(address) == False): 
            return("bad address syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__delete("lisp ddt-root", { "address" : address })
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_mr_referral(self, iid="0", prefix="", group="", referral_set=[]):
        """ Configure a referral EID-prefix. First argument is an instance-ID
            value in string format. the second argument is an IPv4, IPv6
            or MAC address prefix string. The third argument is an optional
            group address when an (S,G) entry is being passed where 'prefix'
            is S and 'group" is G. The fourth argument is an array
            of DDT-node IPv4 or IPv6 address strings. Returns error string or 
            "good" when successful.
        """
        if (prefix == ""): return("no prefix supplied")
        if (referral_set == ""): return("no referral-set supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif
        if (self.__check_address_set_syntax(referral_set, False) == False): 
            return("bad address syntax in referral-set")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = [ data ]
        for ref in referral_set:
            data.append({"referral" : {"address" : ref}})
        #endfor
        data = self.__put("lisp referral-cache", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef
       
    def delete_mr_referral(self, iid="0", prefix="", group=""):
        """ Deconfigure a referral EID-prefix. The 'prefix' and 'group' 
            arguments are IPv4, IPv6 or MAC address prefix strings. The 'iid'
            argument is the value of an instance-ID in string format.
            Returns error string or "good" when successful.
        """
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__delete("lisp referral-cache", data)

        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_ddt_delegation(self, iid="0", prefix="", group="", 
        referral_set=[]):
        """ Configure a LISP-DDT delegation EID-prefix with a referral-set. 
            First argument is an instance-ID value in string format. the 
            second argument is an IPv4, IPv6 or MAC address prefix string. 
            The third argument is an optional group address when an (S,G) 
            entry is being passed where 'prefix' is S and 'group" is G. 
            The fourth argument is an array of child DDT-node IPv4 or IPv6
            address strings. Returns error string or "good" when successful.
        """
        if (prefix == ""): return("no prefix supplied")
        if (referral_set == ""): return("no referral-set supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif
        if (self.__check_address_set_syntax(referral_set, False) == False): 
            return("bad address syntax in referral-set")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = [ data ]
        for ref in referral_set:
            data.append({"delegate" : {"address" : ref}})
        #endfor
                                                              
        data = self.__put("lisp delegation", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_ddt_delegation(self, iid="0", prefix="", group=""):
        """ Deconfigure a LISP-DDT delegation EID-prefix. The 'prefix'
            argument is an IPv4, IPv6 or MAC address prefix string. 
            The second argument is an array of child DDT-node IPv4 or IPv6 
            address strings. Returns error string or "good" when successful.
        """
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__delete("lisp delegation", data)

        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_ddt_auth_prefix(self, iid="0", auth_prefix="", group=""):
        """ Configure a LISP-DDT authoritative-prefix for a DDT-node.
            The 'auth_prefix' argument is an IPv4, IPv6 or MAC address prefix 
            string. Returns error string or "good" when successful.
        """
        if (auth_prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(auth_prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, auth_prefix, group)
        data = [ data["prefix"] ]
        data = self.__put("lisp ddt-authoritative-prefix", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_ddt_auth_prefix(self, iid="0", auth_prefix="", group=""):
        """ Deconfigure a LISP-DDT authoritative-prefix for a DDT-node.
            The 'auth_prefix' argument is an IPv4, IPv6 or MAC address prefix 
            string. Returns error string or "good" when successful.
        """
        if (auth_prefix == ""): return("no auth-prefix supplied")
        if (self.__check_prefix_syntax(auth_prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, auth_prefix, group)
        data = self.__delete("lisp ddt-authoritative-prefix", data)

        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_ms_map_server_peer(self, iid="0", prefix="", group="", 
        peer_set=[]):
        """ Configure a Map-Server peer for a given EID-prefix. This allows
            a Map-Server to return all otther Map-Servers in a Map-Referral
            message for this given EID-prefix. First argument is an 
            instance-ID value in string format. the second argument is an 
            IPv4, IPv6 or MAC address prefix string. The third argument is an 
            optional group address when an (S,G) entry is being passed where 
            'prefix' is S and 'group" is G. The fourth argument is an array of
            of all Map-Servers serving this EID-prefix. It should include
            this local Map-Server the API call is to. Each element of the
            array are address strings. Returns error string or "good" when 
            successful.
        """

        if (prefix == ""): return("no prefix supplied")
        if (peer_set == ""): return("no peer-set supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif
        if (self.__check_address_set_syntax(peer_set, False) == False): 
            return("bad address syntax in referral-set")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = [ data ]
        for peer in peer_set:
            data.append({"peer" : {"address" : peer}})
        #endfor
                                                              
        data = self.__put("lisp map-server-peer", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_ms_map_server_peer(self, iid="0", prefix="", group=""):
        """ Deconfigure a Map-Server peer EID-prefix in a Map-Server. The 
            'prefix' argument is an IPv4, IPv6 or MAC address prefix string. 
            The second argument is an array of child DDT-node IPv4 or IPv6 
            address strings. Returns error string or "good" when successful.
        """
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__delete("lisp map-server-peer", data)

        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_ms_site(self, site_name, auth_key, prefix_list, description=""):
        """ Add LISP site with allowed EID-prefix list. Array prefix_list
            must be built by build_ms_site_allowed_prefix() before using this
            call."""
        if (site_name == ""): return("no site-name supplied")
        if (auth_key == ""): return("no auth_key supplied")

        status = self.__check_prefix_list(prefix_list)
        if (status != True): return(status)

        if (self.enable_status == None): return

        data = []
        data.append({ "site-name" : site_name })
        data.append({ "description" : description })
        data.append({ "authentication-key" : auth_key })
        data.append(prefix_list)
        data = self.__put("lisp site", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def build_ms_site_allowed_prefix(self, prefix_list, iid="0", prefix="", 
        group="", ams=False, fpr=False, fnpr=False, pprd=False, pra=""):
        """ Add EID-prefix and attributes to a prefix-list array to be supplied
            with site information when calling add_ms_site(). Caller needs to
            intialize prefix_list to [] for the first call and needs to pass
            the same variable on each subsequent call.
        """

        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        #
        # The prefix-list is an array of dictionary arrays.
        #
        data = self.__build_prefix_tuple(iid, prefix, group, 
            kw="allowed-prefix")
        ap = data["allowed-prefix"]
        if (ams): ap["accept-more-specifics"] = "yes"
        if (fpr): ap["force-proxy-reply"] = "yes"
        if (fnpr): ap["force-nat-proxy-reply"] = "yes"
        if (pprd): ap["pitr-proxy-reply-drop"] = "yes"
        if (pra != ""): ap["proxy-reply-action"] = pra

        prefix_list.append(data)
        return("good")
    #enddef

    def delete_ms_site(self, site_name):
        """ Delete LISP site and all allowed EID-prefixes previously added
            for the site.
        """

        if (site_name == ""): return("no site-name supplied")
        if (self.enable_status == None): return

        data = self.__delete("lisp site", { "site-name" : site_name })
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_etr_database_mapping(self, iid="0", prefix="", group="", 
        rloc_set=[]):
        """ Add database-mapping for LISP site to ETR. The rloc-set can be an 
            array of address strings or an array of dictionaries that has been
            created by making successive calls to build_rloc_record().
        """
        if (prefix == ""): return("no prefix supplied")
        if (rloc_set == ""): return("no rloc-set supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif
        if (self.__check_address_set_syntax(rloc_set, True) == False): 
            return("bad address syntax in rloc-set")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = [ data ]
        for ref in rloc_set:
            if (type(ref) == dict):
                data.append({"rloc" : ref})
                continue
            #endif

            if (ref in ["en0", "en1", "eth0", "eth1"]):
                data.append({"rloc" : {"interface" : ref}})
            else:
                if (self.__is_dist_name(ref)):
                    data.append({"rloc" : {"rloc-record-name" : ref}})
                else:
                    data.append({"rloc" : {"address" : ref}})
                #endif
            #endif
        #endfor

        data = self.__put("lisp database-mapping", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_etr_database_mapping(self, iid="0", prefix="", group=""):
        """ Remove database-mapping for LISP site from ETR."""
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__delete("lisp database-mapping", data)

        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_etr_map_server(self, address="", auth_key=None, 
        address_is_name=False):
        """ Add Map-Server address to ETR at LISP site. If parameter
            address_is_name is set to True then 'address' is a DNS name for
            the Map-Server.
        """
        if (address == ""): return("no address supplied")

        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        if (auth_key == None): return("no auth-key supplied")

        if (self.enable_status == None): return

        data = self.__put("lisp map-server", 
            { name_or_addr : address, "authentication-type" : "sha2",
              "authentication-key" : auth_key })

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def get_etr_map_server(self, address, address_is_name=False):
        """ Get Map-Server info from ETR at LISP site. If parameter
            address_is_name is set to True then 'address' is a DNS name for
            the Map-Resolver.
        """
        if (self.enable_status == None): return

        if (address == ""): return("no address supplied")

        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        data = self.__get_data("lisp map-server", { name_or_addr : address })
        return(data)
    #enddef

    def delete_etr_map_server(self, address, address_is_name=False):
        """ Remove Map-Server address from ETR at LISP site. If parameter
            address_is_name is set to True then 'address' is a DNS name for
            the Map-Server.
        """
        if (address == ""): return("no address supplied")

        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        if (self.enable_status == None): return

        data = self.__delete("lisp map-server", { name_or_addr : address })
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def add_itr_map_resolver(self, address, address_is_name=False):
        """ Add Map-Resolver info to RTR, or ITR at LISP site. If parameter
            address_is_name is set to True then 'address' is a DNS name for
            the Map-Resolver.
        """
        if (address == ""): return("no address supplied")

        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        if (self.enable_status == None): return

        data = self.__put("lisp map-resolver", { name_or_addr : address })
        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def get_itr_map_resolver(self, address, address_is_name=False):
        """ Get Map-Resolver info from RTR, or ITR at LISP site. If parameter
            address_is_name is set to True then 'address' is a DNS name for
            the Map-Resolver.
        """
        if (self.enable_status == None): return

        if (address == ""): return("no address supplied")

        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        data = self.__get_data("lisp map-resolver", { name_or_addr : address })
        return(data)
    #enddef

    def delete_itr_map_resolver(self, address, address_is_name=False):
        """ Remove Map-Resolver address from RTR, or ITR at LISP site. If 
            parameter address_is_name is set to True then 'address' is a DNS 
            name for the Map-Resolver.
        """
        if (address == ""): return("no address supplied")
        
        if (address_is_name == False):
            if (self.__check_address_syntax(address) == False): 
                return("bad address syntax")
            #endif
            name_or_addr = "address"
        else:
            name_or_addr = "dns-name"
        #endif

        if (self.enable_status == None): return

        data = self.__delete("lisp map-resolver", { name_or_addr : address })
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def build_rloc_record(self, rloc_or_int, upriority, uweight, 
        rloc_name=None, mpriority=255, mweight=0, rloc_set=[]):
        """ Build an RLOC record to be passed to add_itr_map_cache() and
            add_etr_database_mapping(). Returns an array of dictionaries.
        """
        rloc_rec = {}
        if (rloc_or_int in ["en0", "en1", "eth0", "eth1"]):
            rloc_rec["interface"] = rloc_or_int
        else:
            rloc_rec["address"] = rloc_or_int
        #endif
        if (rloc_name): rloc_rec["rloc-record-name"] = rloc_name
        rloc_rec["priority"] = upriority
        rloc_rec["weight"] = uweight
#       rloc_rec["mpriority"] = mpriority
#       rloc_rec["meight"] = mweight
        rloc_set.append(rloc_rec)
        return(rloc_set)
    #enddef

    def add_itr_map_cache(self, iid="0", prefix="", group="", rloc_set=[]):
        """ Add map-cache entry to ITR or RTR. The rloc-set can be an array
            of address strings or an array of dictionaries that has been
            created by making successive calls to build_rloc_record().
        """
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif
        if (self.__check_address_set_syntax(rloc_set, False) == False): 
            return("bad address syntax in rloc-set")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = [ data ]
        for ref in rloc_set:
            if (type(ref) == dict):
                data.append({"rloc" : ref})
                continue
            #endif
            data.append({"rloc" : {"address" : ref}})
        #endfor

        data = self.__put("lisp map-cache", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_itr_map_cache(self, iid="0", prefix="", group=""):
        """ Delete map-cache from ITR or RTR."""
        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__delete("lisp map-cache", data)
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    def get_system(self):
        """ Return system information for a lispers.net system. A dictionary
            array of values is returned.
        """
        if (self.enable_status == None): return

        data = self.__get_data("lisp system", "")
        return(data)
    #enddef

    def get_map_cache(self):
        """ Return the entire map-cache from an ITR or RTR. The returned format
            is an array of map-cache entries. Each entry is a dictionary
            array with unicoded keys and string values.
        """
        if (self.enable_status == None): return

        data = self.__get_data("lisp map-cache", "")
        return(data)
    #enddef

    def get_map_cache_entry(self, iid="", prefix="", group=""):
        """ Do a longest match lookup in the map-cache from an ITR or RTR.
            The returned value will be a dictionary array with unicoded keys
            and string values.
        """

        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        if (self.enable_status == None): return

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__get_data("lisp map-cache", data)
        return(data)
    #enddef

    def get_site_cache(self):
        """ Return the entire site-cache from a Map-Server. The returned format
            is an array of site-cache entries. Each entry is a dictionary
            array with unicoded keys and string values.
        """
        if (self.enable_status == None): return

        data = self.__get_data("lisp site-cache", "")
        return(data)
    #enddef

    def get_site_cache_entry(self, iid="", prefix="", group=""):
        """ Do a longest match lookup in the site-cache from a Map-Server.
            The returned value will be a dictionary array with unicoded keys
            and string values.
        """
        if (self.enable_status == None): return

        if (prefix == ""): return("no prefix supplied")
        if (self.__check_prefix_syntax(prefix) == False): 
            return("bad prefix syntax")
        #endif
        if (group != "" and self.__check_prefix_syntax(group) == False): 
            return("bad group syntax")
        #endif

        data = self.__build_prefix_tuple(iid, prefix, group)
        data = self.__get_data("lisp site-cache", data)
        return(data)
    #enddef

    def add_policy(self, policy_name, match_iid="0", match_seid="", 
        match_deid="", match_srloc="", match_drloc="", match_rloc_name="" ,
        match_geo="", match_elp="", match_rle="", match_json="",
        match_datetime_range="", set_action="drop", set_record_ttl="", 
        set_iid="", set_seid="", set_deid="", set_rloc="",  set_rloc_name="",
        set_geo="", set_elp="", set_rle="", set_json=""):
        """ Add a LISP policy. All parameters except policy_name are 
            optional.
        """
        if (self.enable_status == None): return

        sets = { "policy-name" : policy_name }
        if (set_action != "" and set_action != None):
            if (set_action not in ["process", "drop"]):
                return("bad set-action value")
            #endif
            sets["set-action"] = set_action
        #endif
        if (set_record_ttl != "" and set_record_ttl != None):
            if (set_record_ttl.isdigit() == False):
                return("bad set-record-ttl value")
            #endif
            sets["set-record-ttl"] = set_record_ttl
        #endif
        if (set_iid != "" and set_iid != None):
            if (set_iid.isdigit() == False):
                return("bad set-iid value")
            #endif
            sets["set-instance-id"] = set_iid
        #endif
        if (set_seid != "" and set_seid != None):
            if (self.__check_prefix_syntax(set_seid) == False):
                return("bad set-source-eid prefix syntax")
            #endif
            sets["set-source-eid"] = set_seid 
        #endif
        if (set_deid != "" and set_deid != None):
            if (self.__check_prefix_syntax(set_deid) == False):
                return("bad set-destination-eid prefix syntax")
            #endif
            sets["set-destination-eid"] = set_deid 
        #endif
        if (set_rloc != "" and set_rloc != None):
            if (self.__check_address_syntax(set_rloc) == False):
                return("bad set-rloc-address syntax")
            #endif
            sets["set-rloc-address"] = set_rloc  
        #endif
        if (set_rloc_name != "" and set_rloc_name != None):
            sets["set-rloc-record-name"] = set_rloc_name 
        #endif
        if (set_geo != "" and set_geo != None):
            sets["set-geo-name"] = set_geo 
        #endif
        if (set_elp != "" and set_elp != None):
            sets["set-elp-name"] = set_elp 
        #endif
        if (set_rle != "" and set_rle != None):
            sets["set-rle-name"] = set_rle
        #endif
        if (set_json != "" and set_json != None):
            sets["set-json-name"] = set_json
        #endif

        matches = {}
        if (match_iid != "" and match_iid != None):
            if (match_iid.isdigit() == False):
                return("bad instance-id value")
            #endif
            matches["instance-id"] = match_iid
        #endif
        if (match_seid != "" and match_seid != None):
            if (self.__check_prefix_syntax(match_seid) == False):
                return("bad source-eid prefix syntax")
            #endif
            matches["source-eid"] = match_seid
        #endif
        if (match_deid != "" and match_deid != None):
            if (self.__check_prefix_syntax(match_deid) == False):
                return("bad destination-eid prefix syntax")
            #endif
            matches["destination-eid"] = match_deid
        #endif
        if (match_srloc != "" and match_srloc != None):
            if (self.__check_prefix_syntax(match_srloc) == False):
                return("bad source-rloc prefix syntax")
            #endif
            matches["source-rloc"] = match_srloc
        #endif
        if (match_drloc != "" and match_drloc != None):
            if (self.__check_prefix_syntax(match_drloc) == False):
                return("bad destination-rloc prefix syntax")
            #endif
            matches["destination-rloc"] = match_drloc
        #endif
        if (match_rloc_name != "" and match_rloc_name != None):
            matches["rloc-record-name"] = match_rloc_name
        #endif
        if (match_geo != "" and match_geo != None):
            matches["geo-name"] = match_geo
        #endif
        if (match_elp != "" and match_elp != None):
            matches["elp-name"] = match_elp
        #endif
        if (match_rle != "" and match_rle != None):
            matches["rle-name"] = match_rle
        #endif
        if (match_json != "" and match_json != None):
            matches["json-name"] = match_json
        #endif
        if (match_datetime_range != "" and 
            match_datetime_range != None):
            matches["datetime-range"] = match_datetime_range
        #endif
        matches = { "match" : matches }

        data = []
        data.append(sets)
        data.append(matches)

        data = self.__put("lisp policy", data)

        if (self.__error(data)): return("put error")
        return("good")
    #enddef

    def delete_policy(self, policy_name):
        """ Delete a LISP policy. The policy is referenced by policy name."""
        if (self.enable_status == None): return

        data = self.__delete("lisp policy", {"policy-name" : policy_name})
        if (self.__error(data)): return("delete error")
        return("good")
    #enddef

    #
    # All functions below here are private functions.
    #
    def __get(self, command):
        url = self.url + command.split(" ")[1]

        self.__api_debug("get command: {}".format(command))
        try: 
            r = requests.get(url, auth=(self.user, self.pw), verify=False,
                timeout=REQ_TIMEOUT)
        except: 
            return(None)
        #endtry
        if (r == None or r.text == None): return(None)
        self.__api_debug("get returned: {}".format(r.text))
        if (r.text == ""): return(None)

        return(self.__unicode_to_ascii(command, r.text))
    #enddef
 
    def __get_data(self, command, data):
        url = self.url + "data/" + command.split(" ")[1]
        data = self.__ascii_to_unicode(command, data)

        self.__api_debug("get api data: {}".format(data))
        try: 
            r = requests.get(url, data=data, auth=(self.user, self.pw), 
                verify=False, timeout=REQ_TIMEOUT)
        except: 
            return(None)
        #endtry
        if (r == None or r.text == None): return(None)
        self.__api_debug("get returned: {}".format(r.text))
        if (r.text == ""): return(None)

        #
        # Check for server error. That means the data is in html.
        #
        if (r.text.find("<html>") != -1): return(None)

        data = r.text.encode()
        return(json.loads(data))
    #enddef

    def __put(self, command, data):
        url = self.url + command.split(" ")[1]
        data = self.__ascii_to_unicode(command, data)

        self.__api_debug("put data: {}".format(data))
        try:
            r = requests.put(url, data=data, auth=(self.user, self.pw), 
                verify=False, timeout=REQ_TIMEOUT)
        except:
            return(None)
        #endtry
        if (r == None or r.text == None): return(None)
        self.__api_debug("put returned: {}".format(r.text))
        if (r.text == ""): return(None)

        return(self.__unicode_to_ascii(command, r.text))
    #enddef

    def __delete(self, command, data):
        url = self.url + command.split(" ")[1]
        data = self.__ascii_to_unicode(command, data)
            
        self.__api_debug("delete data: {}".format(data))
        try:
            r = requests.delete(url, data=data, auth=(self.user, self.pw), 
                verify=False, timeout=REQ_TIMEOUT)
        except:
            return(None)
        #endtry
        if (r == None or r.text == None): return(None)
        self.__api_debug("delete returned: {}".format(r.text))
        if (r.text == ""): return(None)

        return(self.__unicode_to_ascii(command, r.text))
    #enddef
    
    def __unicode_to_ascii(self, command, rtext):
        
        #
        # Check for server error. That means the data is in html.
        #
        if (rtext.find("<html>") != -1): return(None)

        data = json.loads(rtext)[0]
        key = unicode(command)
        if (data.has_key(key) == False): return(None)

        if (type(data) == dict):
            data = data[key]
            ascii_data = {}
            for array in data:
                for key in array:
                    ascii_data[key.encode()] = array[key].encode()
                #endfor
            #endfor
        else:
            ascii_data = []
            for label in data:
                adata = {}
                a_dict = label.values()[0]
                for key in a_dict: adata[key.encode()] = a_dict[key].encode()
                adata = { label.keys()[0].encode() : adata }
                ascii_data.append(adata)
            #endfor
        #endif
        return(ascii_data)
    #enddef

    def __walk_dict_array(self, udata, u_dict):
        for key in u_dict: 
            value = unicode(u_dict[key])

            #
            # Value field can be another dictionary array. Don't
            # unicode() it or the array will be encoded as a string.
            #
            if (type(u_dict[key]) == dict): 
                vdata = {}
                value = u_dict[key]
                for k in value: vdata[unicode(k)] = unicode(value[k])
                value = vdata
            #endif

            #
            # Store 
            #
            udata[unicode(key)] = value
        #endfor
    #enddef

    def __ascii_to_unicode(self, command, ascii_data):
        was_dict = (type(ascii_data) == dict)
        if (was_dict): ascii_data = [ ascii_data ] 

        udata = {}
        u_array = []
        for label in ascii_data:
            udata = {}

            if (type(label) == dict):
                self.__walk_dict_array(udata, label)
            elif (type(label) == list):
                l_array = []
                for element in label: 
                    ldata = {}
                    self.__walk_dict_array(ldata, element)
                    l_array.append(ldata)
                #endfor
                udata = l_array
            else:
                udata = { unicode(label.keys()[0]) : udata }
            #endif
            u_array.append(udata)
        #endfor
        udata = u_array

        unicode_data = {}
        unicode_data[unicode(command)] = udata[0] if was_dict else udata
        return(json.dumps(unicode_data))
    #enddef

    def __error(self, data):
        if (data == None): return(True)
        if (data.has_key("!")): return(False)
        return(True)
    #enddef

    def __api_debug(self, string):
        if (self.api_debug): print "lispapi[{}@{}]: {}".format(self.user,
            self.host, string)
    #enddef

    def __check_prefix_syntax(self, prefix):

        #
        # Distinguished-Name EID-prefix.
        #
        if (self.__is_dist_name(prefix)): return(True)

        index = prefix.find("/")
        if (index == -1): return(False)
        return(self.__check_address_syntax(prefix[0:index]))
    #enddef

    def __check_prefix_list(self, prefix_list):
        if (type(prefix_list) != list): return("prefix_list must be an array")
        if (len(prefix_list) == 0): 
            return("prefix_list has no array elements supplied")
        #endif
        if (type(prefix_list[0]) != dict):
            return("prefix_list must be array of type dict")
        #endif
        if (prefix_list[0].has_key("allowed-prefix") == False): 
            return("prefix_list is incorrectly formated")
        #endif
        return(True)
    #enddef

    def __check_address_set_syntax(self, address_set, allow_interfaces):
        for addr in address_set:
            if (type(addr) == str):
                addr_str = addr
            else:
                addr_str = addr["address"] if addr.has_key("address") else \
                    addr["interface"] if addr.has_key("interface") else ""
            #endif
            if (allow_interfaces and 
                addr_str in ["en0", "en1", "eth0", "eth1"]): continue
            if (self.__check_address_syntax(addr_str)): continue
            return(False)
        #endfor
        return(True)
    #enddef

    def __is_dist_name(self, addr_str):

        #
        # Distinguished-Name as an eid-prefix orrloc-record-name.
        #
        return(addr_str[0] == "'" and addr_str[-1] == "'")
    #enddef

    def __check_address_syntax(self, address):

        if (self.__is_dist_name(address)): return(True)

        #
        # Check for IPv4.
        #
        addr = address.split(".")
        if (len(addr) > 1):
            if (len(addr) != 4): return(False)
            for i in range(4):
                if (addr[i].isdigit() == False): return(False)
                byte = int(addr[i])
                if (byte < 0 or byte > 255): return(False)
            #endfor
            return(True)
        #endif

        #
        # Check for IPv6.
        #
        addr = address.split(":")
        if (len(addr) > 1):
            if (len(addr) > 8): return(False)
            for hexgroup in addr:
                if (hexgroup == ""): continue
                try: int(hexgroup, 16)
                except: return(False)
            #endfor
            return(True)
        #endif

        #
        # Check for MAC.
        #
        addr = address.split("-")
        if (len(addr) > 1):
            if (len(addr) != 3): return(False)
            for hexgroup in addr:
                try: int(hexgroup, 16)
                except: return(False)
            #endfor
            return(True)
        #endif
        return(False)
    #enddef

    def __build_prefix_tuple(self, iid, eid_prefix, group, kw="prefix"):
        data = {}
        data["instance-id"] = iid
        data["eid-prefix"] = eid_prefix
        if (group != ""): data["group-prefix"] = group
        return({kw : data})
    #enddef
#endclass

#-----------------------------------------------------------------------------
