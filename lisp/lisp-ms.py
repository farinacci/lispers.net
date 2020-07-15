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
# lisp-ms.py
#
# This file performs LISP Map-Server functionality.
#
# -----------------------------------------------------------------------------

import lisp
import lispconfig
import threading
import time
import os
import hmac
import hashlib
import copy

#------------------------------------------------------------------------------

#
# Global variables.
#
lisp_ipc_listen_socket = None
lisp_send_ipv4_socket = None
lisp_send_ipv6_socket = None
lisp_send_sockets = [None, None, None]
lisp_sites_by_name = {}
lisp_sites_by_name_sorted = []
lisp_site_timer = None
lisp_pubsub_timer = None

#
# Inject mode will take value from env variable LISP_MS_INJECT and create
# n site-eid entries in instance-ID 1300.
# 
count = os.getenv("LISP_MS_INJECT")
lisp_inject_mode_count = 0 if count == None else int(count)

#------------------------------------------------------------------------------

#
# lisp_site_command
#
# Process the "lisp site" command.
#
def lisp_site_command(kv_pairs):
    global lisp_sites_by_name
    global lisp_sites_by_name_sorted

    site = lisp.lisp_site()

    allowed_rloc_set = []
    if (kv_pairs.has_key("address")):
        for addr in kv_pairs["address"]:
            rloc = lisp.lisp_rloc()
            allowed_rloc_set.append(rloc)
        #endfor
    #endif
    
    allowed_eid_set = []
    if (kv_pairs.has_key("eid-prefix")):
        for eid in kv_pairs["eid-prefix"]:
            site_eid = lisp.lisp_site_eid(site)
            allowed_eid_set.append(site_eid)
        #endfor
    #endif

    for kw in kv_pairs.keys():
        value = kv_pairs[kw]
        if (kw == "site-name"): site.site_name = value
        if (kw == "description"): site.description = value
        if (kw == "authentication-key"): 
            site.auth_key = lisp.lisp_parse_auth_key(value)
        #endif
        if (kw == "shutdown"): 
            site.shutdown = True if value == "yes" else False
        #endif

        if (kw == "instance-id"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                if (v == "*"): 
                    site_eid.eid.store_iid_range(0, 0)
                else:
                    if (v == ""): v = "0"
                    site_eid.eid.instance_id = int(v)
                    site_eid.group.instance_id = int(v)
                #endif
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                if (v != ""): site_eid.eid.store_prefix(v)
            #endfor
        #endif
        if (kw == "group-prefix"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                if (v != ""): site_eid.group.store_prefix(v)
            #endfor
        #endif
        if (kw == "accept-more-specifics"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.accept_more_specifics = yes_or_no
            #endfor
        #endif
        if (kw == "force-proxy-reply"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.force_proxy_reply = yes_or_no
            #endfor
        #endif
        if (kw == "force-ttl"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                if (v == ""): continue
                site_eid.force_ttl = None if int(v) == 0 else int(v)
            #endfor
        #endif
        if (kw == "echo-nonce-capable"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.echo_nonce_capable = yes_or_no
            #endfor
        #endif
        if (kw == "force-nat-proxy-reply"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.force_nat_proxy_reply = yes_or_no
            #endfor
        #endif
        if (kw == "pitr-proxy-reply-drop"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.pitr_proxy_reply_drop = yes_or_no
            #endfor
        #endif
        if (kw == "proxy-reply-action"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                site_eid.proxy_reply_action = v
            #endfor
        #endif
        if (kw == "require-signature"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.require_signature = yes_or_no
            #endfor
        #endif
        if (kw == "encrypt-json"):
            for i in range(len(allowed_eid_set)):
                rloc = allowed_eid_set[i]
                v = value[i]
                yes_or_no = True if (v == "yes") else False
                site_eid.encrypt_json = yes_or_no
            #endfor
        #endif
        if (kw == "policy-name"):
            for i in range(len(allowed_eid_set)):
                site_eid = allowed_eid_set[i]
                v = value[i]
                site_eid.policy = v
            #endfor
        #endif

        if (kw == "address"):
            for i in range(len(allowed_rloc_set)):
                rloc = allowed_rloc_set[i]
                v = value[i]
                if (v != ""): rloc.rloc.store_address(v)
            #endfor
        #endif
        if (kw == "priority"):
            for i in range(len(allowed_rloc_set)):
                rloc = allowed_rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"):
            for i in range(len(allowed_rloc_set)):
                rloc = allowed_rloc_set[i]
                v = value[i]
                if (v == ""): v = "0"
                rloc.weight = int(v)
            #endfor
        #endif
    #endfor

    #
    # Do not modify existing entries. We can only support adding new sites.
    #
    if (lisp_sites_by_name.has_key(site.site_name)): return

    #
    # Store values in internal data structures. Inside of lisp_site() sort
    # EID-prefixes.
    #
    lisp_sites_by_name[site.site_name] = site
    lisp_sites_by_name_sorted = sorted(lisp_sites_by_name)

    for site_eid in allowed_eid_set: 
        site_eid.add_cache()
        key = site_eid.build_sort_key()
        site.allowed_prefixes[key] = site_eid
    #endfor
    for rloc in allowed_rloc_set:
        key = rloc.rloc.print_address()
        site.allowed_rlocs[key] = rloc
    #endfor

    #
    # Sort the site.allowed_preifxes{} array.
    #
    site.allowed_prefixes_sorted = sorted(site.allowed_prefixes)
    return
#enddef

#
# lisp_ms_auth_prefix_command
#
# Process the "lisp ms-authoritative-prefix" command for the Map-Server.
#
def lisp_ms_auth_prefix_command(kv_pair):
    ddt_entry = lisp.lisp_ddt_entry()

    for kw in kv_pair.keys():
        value = kv_pair[kw]

        if (kw == "instance-id"):
            v = value.split("-")
            if (v[0] == ""): continue

            no_eid = (kv_pair.has_key("eid-prefix") == False or
                kv_pair["eid-prefix"] == "")
            no_group = (kv_pair.has_key("group-prefix") == False or
                kv_pair["group-prefix"] == "")

            if (no_eid and no_group):
                ddt_entry.eid.store_iid_range(int(v[0]), int(v[1]))
            else:
                ddt_entry.eid.instance_id = int(v[0])
                ddt_entry.group.instance_id = int(v[0])
            #endif
        #endif
        if (kw == "eid-prefix"):
            ddt_entry.eid.store_prefix(value)
        #endif
        if (kw == "group-prefix"):
            ddt_entry.group.store_prefix(value)
        #endif
    #endfor

    #
    # Store in ddt-cache data structure.
    #
    ddt_entry.add_cache()
    return
#enddef

#
# lisp_ms_map_server_peer_command
#
# Process the "lisp map-server-peer" command.
#
def lisp_ms_map_server_peer_command(kv_pair):
    prefix_set = []
    for i in range(len(kv_pair["eid-prefix"])):
        ddt_entry = lisp.lisp_ddt_entry()
        prefix_set.append(ddt_entry)
    #endwhile

    peer_set = []

    if (kv_pair.has_key("address")):
        for i in range(len(kv_pair["address"])):
            peer = lisp.lisp_ddt_node()
            peer.map_server_peer = True
            peer_set.append(peer)
        #endfor
    #endif

    for kw in kv_pair.keys():
        value = kv_pair[kw]
        if (kw == "instance-id"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                v = value[index].split("-")
                if (v[0] == ""): continue

                no_eid = (kv_pair["eid-prefix"][index] == "" and
                    kv_pair["group-prefix"][index] == "")

                if (no_eid):
                    ddt_entry.eid.store_iid_range(int(v[0]), int(v[1]))
                else:
                    ddt_entry.eid.instance_id = int(v[0])
                    ddt_entry.group.instance_id = int(v[0])
                #endif
            #endfor
        #endif
        if (kw == "eid-prefix"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                prefix_str = value[index]
                if (prefix_str == ""): continue
                ddt_entry.eid.store_prefix(prefix_str)
            #endfor
        #endif
        if (kw == "group-prefix"):
            for index in range(len(prefix_set)):
                ddt_entry = prefix_set[index]
                prefix_str = value[index]
                if (prefix_str == ""): continue
                ddt_entry.group.store_prefix(prefix_str)
            #endfor
        #endif

        if (kw == "address"):
            for i in range(len(peer_set)):
                peer = peer_set[i]
                v = value[i]
                if (v != ""): peer.delegate_address.store_address(v)
            #endfor
        #endif
        if (kw == "priority"):
            for i in range(len(peer_set)):
                peer = peer_set[i]
                v = value[i]
                if (v == ""): v = "0"
                peer.priority = int(v)
            #endfor
        #endif
        if (kw == "weight"):
            for i in range(len(peer_set)):
                peer = peer_set[i]
                v = value[i]
                if (v == ""): v = "0"
                peer.weight = int(v)
            #endfor
        #endif
    #endfor

    #
    # All the prefixes in the prefix_set are stored and in the lisp_ddt_
    # cache. Now we have to point all of them to each peer set.
    #
    for ddt_entry in prefix_set:
        ddt_entry.add_cache()
        for peer in peer_set:
            ddt_entry.delegation_set.append(peer)
        #endfor
    #endfor
    return
#enddef

#
# lisp_ms_eid_crypto_hash_command
#
# Process the "lisp eid-crypto-hash" command.
#
def lisp_ms_eid_crypto_hash_command(kv_pair):
    address = lisp.lisp_address(lisp.LISP_AFI_IPV6, "", 0, 0)

    for kw in kv_pair.keys():
        value = kv_pair[kw]
        if (kw == "instance-id"): 
            if (value == "*"): value = "-1"
            address.instance_id = int(value)
        #endif
        if (kw == "eid-prefix"): 
            address.store_prefix(value)
            if (address.is_ipv6() == False): return
            if ((address.mask_len % 4) != 0): return
        #endif
    #endfor

    #
    # Add to data structure.
    #
    lisp.lisp_eid_hashes.append(address)
    return
#enddef

#
# lisp_ms_encryption_keys_command
#
# Process the "lisp encryption-keys" command.
#
def lisp_ms_encryption_keys_command(kv_pair):
    for kw in kv_pair.keys():
        value = kv_pair[kw]
        if (kw == "map-register-key"): 
            lisp.lisp_ms_encryption_keys = lisp.lisp_parse_auth_key(value)
        #endif
        if (kw == "json-key"): 
            lisp.lisp_ms_json_keys = lisp.lisp_parse_auth_key(value)
        #endif
    #endfor
    return
#enddef

#
# lisp_ms_show_site_detail_command
#
# Show LISP site information for a particular EID-prefix..
#
def lisp_ms_show_site_detail_command(eid_key, group_key):

    eid = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    if (eid_key): 
        if (eid_key == "[0]/0"): 
            eid.store_iid_range(0, 0)
        else: 
            eid.store_prefix(eid_key)
        #endif
    #endif
    group = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)
    if (group_key): group.store_prefix(group_key)

    eid_str = lisp.lisp_print_eid_tuple(eid, group)
    eid_str = lisp.lisp_print_cour(eid_str)

    #
    # Do longest match lookup. We do this so prefix slashes are not in URLs.
    #
    site_eid = lisp.lisp_site_eid_lookup(eid, group, True)
    if (site_eid == None): 
        output = "Could not find EID {} in site cache".format(eid_str)
        return(output)
    #endif

    indent4 = lisp.space(4)
    indent8 = lisp.space(8)
    indent12 = lisp.space(12)

    yesno = lisp.green("yes", True) if site_eid.registered else \
        lisp.red("no", True)

    output = '<font face="Sans-Serif">'

    sn = lisp.lisp_print_cour(site_eid.site.site_name)
    si = lisp.lisp_print_cour(str(site_eid.site_id))
    xi = "0" if site_eid.xtr_id == 0 else lisp.lisp_hex_string(site_eid.xtr_id)
    xi = lisp.lisp_print_cour("0x" + xi)
    fr = lisp.lisp_print_elapsed(site_eid.first_registered)
    lr = lisp.lisp_print_elapsed(site_eid.last_registered)
    if (time.time() - site_eid.last_registered >= 
        (site_eid.register_ttl / 2) and lr != "never"):
        lr = lisp.red(lr, True)
    #endif
    if (site_eid.last_registerer.afi == lisp.LISP_AFI_NONE): 
        reger = "none"
    else:
        reger = site_eid.last_registerer.print_address()
    #endif
    reger = lisp.lisp_print_cour(reger)
    shutdown = ", " + lisp.lisp_print_cour("site is in admin-shutdown") if \
        site_eid.site.shutdown else ""
    ams = ", accepting more specifics" if site_eid.accept_more_specifics \
        else ""
    if (ams == "" and site_eid.dynamic): ams = ", dynamic"
    output += '''Site name: {}, EID-prefix: {}, registered: {}{}{}
        <br>'''.format(sn, eid_str, yesno, ams, shutdown)

    output += "{}Description: {}<br>".format(indent4, 
        lisp.lisp_print_cour(site_eid.site.description))
    output += "{}Last registerer: {}, xTR-ID: {}, site-ID: {}<br>".format( \
        indent4, reger, xi, si)

    flags = site_eid.print_flags(False)
    flags = lisp.lisp_print_cour(flags)
    auth_type = "none"
    if (site_eid.registered): 
        auth_type = "sha1" if (site_eid.auth_sha1_or_sha2) else "sha2"
    #endif
    output += ("{}First registered: {}, last registered: {}, auth-type: " + \
        "{}, registration flags: {}<br>").format(indent4, 
         lisp.lisp_print_cour(fr), lisp.lisp_print_cour(lr),
         lisp.lisp_print_cour(auth_type), flags)

    ttl = lisp.lisp_print_cour(str(site_eid.register_ttl) + " seconds")
    output += "{}{} registration timeout TTL: {}<br>".format( \
        indent4, "Registered" if site_eid.use_register_ttl_requested else \
        "Default", ttl)

    #
    # First print a policy line, if one is configured for this site-eid.
    #
    if (site_eid.policy):
        p = lisp.lisp_print_cour(site_eid.policy)
        output += "{}Apply policy: '{}'<br>".format(indent4, p)
    #endif

    #
    # Show proxy-reply settings.
    #
    yesno = "yes" if site_eid.force_proxy_reply else "no"
    yesno = lisp.lisp_print_cour(yesno)
    output += "{}Forcing proxy Map-Reply: {}<br>".format(indent4, yesno)

    if (site_eid.force_ttl != None):
        ttl = lisp.lisp_print_cour(str(site_eid.force_ttl) + " seconds")
        output += "{}Forced proxy Map-Reply TTL: {}<br>".format( \
            indent4, ttl)
    #endif

    yesno = "yes" if site_eid.force_nat_proxy_reply else "no"
    yesno = lisp.lisp_print_cour(yesno)
    output += "{}Forcing proxy Map-Reply for xTRs behind NATs: {}<br>". \
        format(indent4, yesno)

    yesno = "yes" if site_eid.pitr_proxy_reply_drop else "no"
    yesno = lisp.lisp_print_cour(yesno)
    output += "{}Send drop-action proxy Map-Reply to PITR: {}<br>".format( \
        indent4, yesno)

    action = "not configured" if site_eid.proxy_reply_action == "" else \
        site_eid.proxy_reply_action
    action = lisp.lisp_print_cour(action)
    output += "{}Proxy Map-Reply action: {}<br>".format(indent4, action)

    if (site_eid.force_proxy_reply and site_eid.echo_nonce_capable):
        yes = lisp.lisp_print_cour("yes")
        output += "{}RLOCs are echo-nonce capable: {}<br>".format(indent4, yes)
    #endif

    yesno = "yes" if site_eid.require_signature else "no"
    yesno = lisp.lisp_print_cour(yesno)
    output += "{}Require signatures: {}<br>".format(indent4, yesno)

    yesno = "yes" if site_eid.encrypt_json else "no"
    yesno = lisp.lisp_print_cour(yesno)
    output += "{}Encrypt JSON RLOC-records: {}<br>".format(indent4, yesno)

    #
    # Print configured allowed RLOC-sets, if any.
    #
    any_rloc = "any" if len(site_eid.site.allowed_rlocs) == 0 else ""
    if (any_rloc != ""): any_rloc = lisp.lisp_print_cour(any_rloc)
    output += "{}Allowed RLOC-set: {}<br>".format(indent4, any_rloc)
    if (any_rloc == ""):                                      
        for rloc in site_eid.site.allowed_rlocs.values():
            a = lisp.lisp_print_cour(rloc.rloc.print_address())
            s = lisp.lisp_print_cour(rloc.print_state())
            up = lisp.lisp_print_cour(str(rloc.priority))
            uw = lisp.lisp_print_cour(str(rloc.weight))
            mp = lisp.lisp_print_cour(str(rloc.mpriority))
            mw = lisp.lisp_print_cour(str(rloc.mweight))
            rn = rloc.print_rloc_name(True)
            if (rn != "") : rn = ", " + rn

            output += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>'''. \
                format(indent8, a, s, up, uw, mp, mw, rn)
        #endfor
    #endif

    none = "none" if len(site_eid.registered_rlocs) == 0 else ""
    if (none != ""): none = lisp.lisp_print_cour(none)
    output += "<br>Registered RLOC-set ({}): {}<br>".format("merge-semantics" \
        if (site_eid.merge_register_requested) else "replacement-semantics", 
        none)
    if (none == ""):
        for rloc in site_eid.registered_rlocs:
            a = lisp.lisp_print_cour(rloc.rloc.print_address())
            s = lisp.lisp_print_cour(rloc.print_state())
            up = lisp.lisp_print_cour(str(rloc.priority))
            uw = lisp.lisp_print_cour(str(rloc.weight))
            mp = lisp.lisp_print_cour(str(rloc.mpriority))
            mw = lisp.lisp_print_cour(str(rloc.mweight))
            rn = rloc.print_rloc_name(True)
            if (rn != "") : rn = ", " + rn

            output += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>'''.\
                format(indent4, a, s, up, uw, mp, mw, rn)
            if (rloc.geo):
                geo = lisp.lisp_print_cour(rloc.geo.print_geo_url())
                output += "{}geo: {}<br>".format(indent12, geo)
            #endif
            if (rloc.elp):
                elp = lisp.lisp_print_cour(rloc.elp.print_elp(False))
                output += "{}elp: {}<br>".format(indent12, elp)
            #endif
            if (rloc.rle):
                rle = lisp.lisp_print_cour(rloc.rle.print_rle(True, True))
                output += "{}rle: {}<br>".format(indent12, rle)
            #endif
            if (rloc.json):
                json = lisp.lisp_print_cour(rloc.json.print_json(True))
                output += "{}json: {}<br>".format(indent12, json)
            #endif
        #endfor
    #endif

    none = "none" if len(site_eid.individual_registrations) == 0 else ""
    if (none == "none"): 
        none = lisp.lisp_print_cour(none)
    elif (site_eid.inconsistent_registration):
        none = lisp.red("inconsistent registrations", True)
        none = lisp.lisp_print_cour(none)
    #endif
    output += "<br>Individual registrations: {}<br>".format(none)

    for site_eid in site_eid.individual_registrations.values():
        yesno = lisp.green("yes", True) if site_eid.registered else \
            lisp.red("no", True)
        auth_type = "sha1" if (site_eid.auth_sha1_or_sha2) else "sha2"
        auth_type = lisp.lisp_print_cour(auth_type)
        flags = site_eid.print_flags(False)
        flags = lisp.lisp_print_cour(flags)
        a = lisp.lisp_print_cour(site_eid.last_registerer.print_address())
        fr = lisp.lisp_print_elapsed(site_eid.first_registered)
        fr = lisp.lisp_print_cour(fr)
        lr = lisp.lisp_print_elapsed(site_eid.last_registered)
        if (time.time() - site_eid.last_registered >= 
            (site_eid.register_ttl / 2) and lr != "never"):
            lr = lisp.red(lr, True)
        #endif
        lr = lisp.lisp_print_cour(lr)
        si = lisp.lisp_print_cour(str(site_eid.site_id))
        xi = lisp.lisp_print_cour(lisp.lisp_hex_string(site_eid.xtr_id))

        output += '''
            {}Registerer: {}, xTR-ID: 0x{}, site-id: {}, registered: {}<br>
            {}First registered: {}, last registered: {}, auth-type: {}, 
            registration flags: {}<br>
        '''.format(indent4, a, xi, si, yesno, indent4, fr, lr, auth_type, 
            flags)

        none = "none" if len(site_eid.registered_rlocs) == 0 else ""
        none = lisp.lisp_print_cour(none)
        output += "{}Registered RLOC-set: {}<br>".format(indent4, none)

        for rloc in site_eid.registered_rlocs:
            a = lisp.lisp_print_cour(rloc.rloc.print_address())
            s = lisp.lisp_print_cour(rloc.print_state())
            up = lisp.lisp_print_cour(str(rloc.priority))
            uw = lisp.lisp_print_cour(str(rloc.weight))
            mp = lisp.lisp_print_cour(str(rloc.mpriority))
            mw = lisp.lisp_print_cour(str(rloc.mweight))
            rn = rloc.print_rloc_name(True)
            if (rn != "") : rn = ", " + rn

            output += '''{}{}, state: {}, up/uw/mp/mw: {}/{}/{}/{}{}<br>'''.\
                format(indent8, a, s, up, uw, mp, mw, rn)
            if (rloc.geo):
                geo = lisp.lisp_print_cour(rloc.geo.print_geo_url())
                output += "{}geo: {}<br>".format(indent12, geo)
            #endif
            if (rloc.elp):
                elp = lisp.lisp_print_cour(rloc.elp.print_elp(False))
                output += "{}elp: {}<br>".format(indent12, elp)
            #endif
            if (rloc.rle):
                rle = lisp.lisp_print_cour(rloc.rle.print_rle(True, True))
                output += "{}rle: {}<br>".format(indent12, rle)
            #endif
            if (rloc.json):
                json = lisp.lisp_print_cour(rloc.json.print_json(True))
                output += "{}json: {}<br>".format(indent12, json)
            #endif
        #endfor
        output += "<br>"
    #endif
    output += "</font>"
    return(output)
#enddef

#
# lisp_ms_display_ddt_cache
#
# Display each entry in the lisp_ddt_cache.
#
def lisp_ms_display_ddt_cache(ddt_entry, output):
    prefix = ddt_entry.print_eid_tuple()
    mrs = ddt_entry.map_referrals_sent

    if (ddt_entry.is_auth_prefix()):
        output += lispconfig.lisp_table_row(prefix, "--", "auth-prefix", "--",
            mrs)                                    
        return([True, output])
    #endif

    for child in ddt_entry.delegation_set:
        addr = child.delegate_address
        pw = str(child.priority) + "/" + str(child.weight)
        output += lispconfig.lisp_table_row(prefix, addr.print_address(),
            child.print_node_type(), pw, mrs)
        if (prefix != ""): 
            prefix = ""
            mrs = ""
        #endif
    #endfor
    return([True, output])
#enddef

#
# lisp_ms_walk_ddt_cache
#
# Walk the entries in the lisp_ddt_cache(). And then subsequently walk the
# entries in lisp_ddt_entry.source_cache().
#
def lisp_ms_walk_ddt_cache(ddt_entry, output):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (ddt_entry.group.is_null()): 
        return(lisp_ms_display_ddt_cache(ddt_entry, output))
    #endif

    if (ddt_entry.source_cache == None): return([True, output])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    output = ddt_entry.source_cache.walk_cache(lisp_ms_display_ddt_cache, 
        output)
    return([True, output])
#enddef

#
# lisp_ms_show_ddt_entries
#
# Walk through the Map-Server's DDT entries and display them before the site
# cache.
#
def lisp_ms_show_ddt_entries():
    hover = "{} entries configured".format(lisp.lisp_ddt_cache.cache_size())
    title = lisp.lisp_span("LISP-MS Configured Map-Server Peers & " + \
        "Authoritative Prefixes:", hover)
    output = lispconfig.lisp_table_header(title, "EID-Prefix or (S,G)",
        "Peer Address", "Delegation Type", "Priority/Weight", 
        "Map-Referrals Sent")

    output = lisp.lisp_ddt_cache.walk_cache(lisp_ms_walk_ddt_cache, output)
    output += lispconfig.lisp_table_footer()
    return(output)
#enddef

#
# lisp_ms_show_site_lookup
#
# Do a Map-Request lookup in the ddt-cache as well as the site cache. Return
# results. If not found, return negative prefix.
#
def lisp_ms_show_site_lookup(input_str):
    eid, eid_exact, group, group_exact = \
        lispconfig.lisp_get_lookup_string(input_str)

    output = "<br>"

    #
    # Do lookup in site-cache first.
    #
    site_eid = lisp.lisp_site_eid_lookup(eid, group, eid_exact)
    if (site_eid and site_eid.is_star_g() == False):
        eid_str = site_eid.print_eid_tuple()
        registered = lisp.green("registered", True) if site_eid.registered \
            else lisp.red("not registered", True)
        output += "{} '{}' {} {} {} {} {} {}".format( \
            lisp.lisp_print_sans("Site"),
            lisp.lisp_print_cour(site_eid.site.site_name),
            lisp.lisp_print_sans("entry"),
            lisp.lisp_print_cour(eid_str),
            lisp.lisp_print_sans("found for EID"),
            lisp.lisp_print_cour(input_str),
            lisp.lisp_print_sans("site EID is"),
            lisp.lisp_print_cour(registered))
        return(output + "<br>")
    #endif

    #
    # Compute negative prefixes.
    #
    neg_prefix, gneg_prefix, action = \
        lisp.lisp_ms_compute_neg_prefix(eid, group)
    if (group.is_null()):
        neg_prefix = lisp.lisp_print_cour(neg_prefix.print_prefix())
    else:
        gneg_prefix = lisp.lisp_print_cour(gneg_prefix.print_prefix())
        neg_prefix = lisp.lisp_print_cour(neg_prefix.print_prefix())
        neg_prefix = "(" + neg_prefix + ", " + gneg_prefix + ")"
    #endif

    if (action == lisp.LISP_DDT_ACTION_NOT_AUTH):
        banner = "Site entry not found for non-authoritative EID" 
        output += "{} {} {} {}".format(lisp.lisp_print_sans(banner), 
            lisp.lisp_print_cour(input_str),
            lisp.lisp_print_sans("<br><br>Computed negative-prefix"),
            neg_prefix)
    #endif

    #
    # Try to find a auth-prefix in the DDT-cache.
    #
    if (action == lisp.LISP_DDT_ACTION_DELEGATION_HOLE):
        ddt_entry = lisp.lisp_ddt_cache_lookup(eid, group, False)
        if (ddt_entry == None or ddt_entry.is_auth_prefix() == False):
            banner = "Could not find Authoritative-prefix entry for"
            output += "{} {} {} {}".format(lisp.lisp_print_sans(banner),
                lisp.lisp_print_cour(input_str),
                lisp.lisp_print_sans("<br><br>Computed negative-prefix"),
                neg_prefix)
        else:
            eid_str = ddt_entry.print_eid_tuple()
            output += "{} {} {} {} {} {}".format( \
                lisp.lisp_print_sans("Authoritative-prefix entry"),
                lisp.lisp_print_cour(eid_str),
                lisp.lisp_print_sans("found for EID"),
                lisp.lisp_print_cour(input_str),
                lisp.lisp_print_sans("<br><br>Computed negative-prefix"),
                neg_prefix)
        #endif
    #endif
    return(output + "<br>")
#enddef

#
# lisp_display_site_eid_entry
#
# Print one row for a site-eid entry.
#
def lisp_display_site_eid_entry(site_eid, site, first, output):

    eid_str = site_eid.print_eid_tuple()
    eid_str = eid_str.replace("no-address/0", "")

    #
    # Create URL format for all of (*,G), (S,G), and an EID-prefix.
    #
    eid = site_eid.eid
    group = site_eid.group
    if (eid.is_null() and group.is_null() == False): 
        url = "{}-*-{}".format(group.instance_id, group.print_prefix_url())
        eid_str = "<a href='/lisp/show/site/{}'>{}</a>".format(url, eid_str)
    #endif
    if (eid.is_null() == False and group.is_null()):
        url = "{}".format(eid.print_prefix_url())

        #
        # Distinguished-Name EIDs have "'"s in them.
        #
        if (url.find("'") != -1):
            url = url.replace("'", "name-", 1)
            url = url.replace("'", "")
        else:

            #
            # E.164 EIDs have "+"s in them.
            #
            url = url.replace("+", "plus-")
        #endif
        eid_str = "<a href='/lisp/show/site/{}'>{}</a>".format(url, eid_str)
    #endif
    if (eid.is_null() == False and group.is_null() == False):
        url = "{}-{}".format(eid.print_prefix_url(), group.print_prefix_url())
        eid_str = "<a href='/lisp/show/site/{}'>{}</a>".format(url, eid_str)
    #endif

    site_name = site.site_name if first else ""
    flags = "--"
    if (site_eid.registered): flags = site_eid.print_flags(True)
    registerer = "--" 
    if (site_eid.last_registerer.afi != lisp.LISP_AFI_NONE): 
        registerer = site_eid.last_registerer.print_address()
    #endif
    registered = lisp.green("yes", True) if site_eid.registered else \
        lisp.red("no", True)
    if (site.shutdown): registered = lisp.red("admin-shutdown", True)

    if (site_eid.dynamic):
        registered += " (dynamic)"
    elif (site_eid.accept_more_specifics):
        registered = "(ams)"
    #endif
            
    lts = lisp.lisp_print_elapsed(site_eid.last_registered)
    if (time.time() - site_eid.last_registered >= 
        (site_eid.register_ttl / 2) and lts != "never"):
        lts = lisp.red(lts, True)
    #endif
    fts = lisp.lisp_print_elapsed(site_eid.first_registered)

    if (site_eid.accept_more_specifics):
        num = len(site_eid.more_specific_registrations)
        hover = "{} EID-prefixes registered".format(num)
        eid_str = lisp.lisp_span(eid_str, hover)
    #endif

    output += lispconfig.lisp_table_row(site_name, eid_str, registered,
        registerer, lts, fts, flags)
    return(output)
#enddef

#
# lisp_ms_show_site_command
#
# Show LISP site information.
#
def lisp_ms_show_site_command(parameter):

    #
    # Do detailed display.
    #
    if (parameter != ""): 
        if (parameter.find("@lookup") != -1):
            parameter = parameter.split("@")
            return(lisp_ms_show_site_lookup(parameter[0]))
        #endif
        eid = parameter.split("%")[0]
        group = parameter.split("%")[1]
        return(lisp_ms_show_site_detail_command(eid, group))
    #endif

    #
    # Top part of display has the form for doing a specific lookup.
    #
    banner = "Enter EID for Site-Cache lookup:"
    input_rectangle = \
        lisp.lisp_eid_help_hover('<input type="text" name="eid" />')
    output = '''
        <form action="/lisp/show/site/lookup" method="post">
        <i><font face="Courier New" size="3">
        {} {}
        <input style="background-color:transparent;border-radius:10px;" type="submit" value="Submit" />
        </font></i></form>
    '''.format(lisp.lisp_print_sans(banner), input_rectangle)

    #
    # First display auth-prefix and map-server-peer configuration, if any.
    #
    if (lisp.lisp_ddt_cache.cache_count != 0): 
        output += lisp_ms_show_ddt_entries()
    #endif

    #
    # Do table display.
    #
    hover = ("{} sites & {} eid-prefixes configured\n{} eid-prefixes " + \
        "registered").format(len(lisp_sites_by_name),
        lisp.lisp_sites_by_eid.cache_size(), lisp.lisp_registered_count)

    title = lisp.lisp_span("LISP-MS Site Information:", hover)
    output += lispconfig.lisp_table_header(title, "Site Name", 
        "EID-Prefix or (S,G)", "Registered", "Last Registerer", 
        "Last Registered", "First Registered", "Registration Flags")

    for site_name in lisp_sites_by_name_sorted:
        site = lisp_sites_by_name[site_name]
        first = True
        for key in site.allowed_prefixes_sorted:
            site_eid = site.allowed_prefixes[key]

            output = lisp_display_site_eid_entry(site_eid, site, first, output)
            if (first): first = False
                      
            for ms_site_eid in site_eid.more_specific_registrations:
                output = lisp_display_site_eid_entry(ms_site_eid, site, first, 
                    output)
            #endfor
        #endfor
    #endfor

    output += lispconfig.lisp_table_footer()

    #
    # Show NAT-traversal lisp_nat_state_info table for an RTR. In the future
    # show this. Problem know is that the lisp-core process will process
    # Info-Requests for the control-plane port 4342.
    #
    # output = lispconfig.lisp_display_nat_info(output, "Control")

    if (lisp.lisp_pubsub_cache == {}): return(output)

    #
    # Display pubsub cache.
    #
    title = "LISP-MS Subscriber Information:"
    output += lispconfig.lisp_table_header(title, "EID-prefix", 
        "Uptime<br>TTL", "Subscriber RLOC", "xTR-ID", "Nonce", 
        "Map-Notifies<br>Sent")

    for e in lisp.lisp_pubsub_cache:
        eid = e
        for pubsub in lisp.lisp_pubsub_cache[e].values():
            rloc_str = pubsub.itr.print_address_no_iid() + ":" + \
                str(pubsub.port)
            ut = lisp.lisp_print_elapsed(pubsub.uptime) + "<br>" + \
                str(pubsub.ttl) + " mins"

            xtr_id = "--"
            if (pubsub.xtr_id != None):
                xtr_id = "0x" + lisp.lisp_hex_string(pubsub.xtr_id)
            #endif
            nonce = "0x" + lisp.lisp_hex_string(pubsub.nonce)
            c = pubsub.map_notify_count
            output += lispconfig.lisp_table_row(eid, ut, rloc_str, xtr_id, 
                nonce, c)
            eid = ""
        #endfor
    #endfor
    output += lispconfig.lisp_table_footer()
    return(output)
#enddef

#
# Map-Server commands processed by this process.
#
lisp_ms_commands = {
    "lisp site" : [lisp_site_command, { 
        "site-name" : [False], 
        "description" : [False], 
        "shutdown" : [False],
        "authentication-key" : [False], 
        "allowed-prefix" : [],
        "instance-id" : [True, 0, 0xffffffff],
        "eid-prefix" : [True],
        "group-prefix" : [True], 
        "policy-name" : [True], 
        "accept-more-specifics" : [True, "yes", "no"],
        "force-proxy-reply" : [True, "yes", "no"],
        "force-nat-proxy-reply" : [True, "yes", "no"],
        "echo-nonce-capable" : [True, "yes", "no"],
        "force-ttl" : [True, 0, 0x7fffffff],
        "pitr-proxy-reply-drop" : [True, "yes", "no"],
        "proxy-reply-action" : [True, "native-forward", "drop"],
        "require-signature" : [True, "yes", "no"],
        "encrypt-json" : [True, "yes", "no"],
        "allowed-rloc" : [],
        "address" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100] }],

    "lisp ms-authoritative-prefix" : [lisp_ms_auth_prefix_command, {
        "instance-id" : [False, 0, 0xffffffff, True],  
        "eid-prefix" : [False],
        "group-prefix" : [False]  }],

    "lisp map-server-peer" : [lisp_ms_map_server_peer_command, {
        "peer" : [], 
        "address" : [True], 
        "priority" : [True, 0, 255], 
        "weight" : [True, 0, 100],
        "prefix" : [], 
        "instance-id" : [True, 0, 0xffffffff, True],  
        "eid-prefix" : [True], 
        "group-prefix" : [True]  }],

    "lisp eid-crypto-hash" : [lisp_ms_eid_crypto_hash_command, {
        "instance-id" : [True, 0, 0xffffffff],  
        "eid-prefix" : [False] }],

    "lisp encryption-keys" : [lisp_ms_encryption_keys_command, {
        "json-key" : [False],
        "map-register-key" : [False] }],

    "lisp geo-coordinates" : [lispconfig.lisp_geo_command, {
        "geo-name" : [False],
        "geo-tag" : [False] }],

    "lisp explicit-locator-path" : [lispconfig.lisp_elp_command, {
        "elp-name" : [False], 
        "elp-node" : [], 
        "address" : [True], 
        "probe" : [True, "yes", "no"],
        "strict" : [True, "yes", "no"],
        "eid" : [True, "yes", "no"] }], 

    "lisp replication-list-entry" : [lispconfig.lisp_rle_command, {
        "rle-name" : [False], 
        "rle-node" : [], 
        "address" : [True], 
        "level" : [True, 0, 255] }], 

    "lisp json" : [lispconfig.lisp_json_command, {
        "json-name" : [False],
        "json-string" : [False] }],

    "show site" : [lisp_ms_show_site_command, { } ]
}

#
# lisp_timeout_site_eid
#
# Look at elapsed time for a parent site-eid or a child site-eid from an
# individual registrations due to merge-semantics.
#
def lisp_timeout_site_eid(site_eid, delete_list):
    now = lisp.lisp_get_timestamp()

    if (site_eid.registered == False): return(delete_list)
    if (site_eid.last_registered + site_eid.register_ttl > now): 
        return(delete_list)
    #endif

    #
    # Timed out.
    #
    m_or_r = "merge" if site_eid.merge_register_requested else "replacement"
    dynamic = "dynamic " if site_eid.dynamic else ""
    site_eid.registered = False
    lisp.lisp_registered_count -= 1
    elapsed = lisp.lisp_print_elapsed(site_eid.first_registered)
    prefix_str = site_eid.print_eid_tuple()
    registerer = site_eid.last_registerer.print_address_no_iid()

    lisp.lprint(("Registration timeout for {}EID-prefix {} site '{}' " + \
        "from {}, was registered for {}, {}-semantics").format(dynamic, 
        lisp.green(prefix_str, False), site_eid.site.site_name, registerer, 
        elapsed, m_or_r))

    if (delete_list == None): return(None)

    #
    # Remove entries from site-cache for dynamic entries. For individual
    # registrations, we put on the delete-list just to tell the caller if
    # anything change so we can recommpute the merged set..
    #
    delete_list.append(site_eid)
    return(delete_list)
#enddef

#
# lisp_timeout_individuals
#
# Time out the individual entries.
#
def lisp_timeout_individuals(parent, rle_list):
    delete_list = []
    for child in parent.individual_registrations.values():
        delete_list = lisp_timeout_site_eid(child, delete_list)
    #endfor

    if (len(delete_list) != 0 and parent.merge_in_site_eid(None)):
        rle_list.append([parent.eid, parent.group])
    #endif
    return(rle_list)
#enddef

#
# lisp_timeout_sites
#
# Time out entries that have not registered within their advertised register-
# ttl.
#
def lisp_timeout_sites():
    global lisp_send_sockets

    lisp.lisp_set_exception()

    rle_list = []
    for site in lisp_sites_by_name.values():
        for site_eid in site.allowed_prefixes.values():
            if (site_eid.merge_register_requested == False):
                lisp_timeout_site_eid(site_eid, None)
            #endif

            parent = site_eid

            #
            # Check if we are merging registrations. If so, look at each child.
            # Individual registrations are not removed from parent.
            #
            rle_list = lisp_timeout_individuals(parent, rle_list)

            #
            # Check if this site-eid has more-specific registrations. We need
            # to check their timers.
            #
            delete_list = []
            for ms in parent.more_specific_registrations:
                rle_list = lisp_timeout_individuals(ms, rle_list)
                delete_list = lisp_timeout_site_eid(ms, delete_list)
            #endfor
            for ms in delete_list: 
                parent.more_specific_registrations.remove(ms)
                ms.delete_cache()
            #endfor
        #endfor
    #endfor

    #
    # Send Map-Noitfy to ITRs if any (S,G) RLE has changed.
    #
    if (len(rle_list) != 0): 
        lisp.lisp_queue_multicast_map_notify(lisp_send_sockets, rle_list)
    #endif
    
    #
    # Restart periodic timer.
    #
    lisp_site_timer = threading.Timer(lisp.LISP_SITE_TIMEOUT_CHECK_INTERVAL, 
        lisp_timeout_sites, [])
    lisp_site_timer.start()
    return
#enddef

#
# lisp_ms_scale_inject
#
# Use env variable LISP_MS_INJECT to add a ton of entries. Use IID 1300.
#
def lisp_ms_scale_inject():
    global lisp_inject_mode_count

    #
    # Only do it once or never.
    #
    if (lisp_inject_mode_count == 0): return
    
    count = lisp_inject_mode_count
    i = lisp.bold("Injecting", False)
    lisp.fprint("{} {} entries into mapping system for scale testing". \
        format(i, count))

    #
    # Create EID-record info.
    #
    iid = 1300
    phone = 9990000000
    eid = lisp.lisp_address(lisp.LISP_AFI_NAME, "ct", 0, iid)
    group = lisp.lisp_address(lisp.LISP_AFI_NONE, "", 0, 0)

    parent_site = lisp.lisp_site_eid_lookup(eid, group, False)
    if (parent_site == None):
        lisp.fprint("No site found for instance-ID {}".format(iid))
        return
    #endif
    if (parent_site.accept_more_specifics == False):
        lisp.fprint("Site must be configured with accept-more-specifics")
        return
    #endif
    
    #
    # Create RLOC-record info.
    #
    rloc = lisp.lisp_rloc()

    gps_record = ' "phone" : "{}", "text-interval" : "10", ' + \
        '"gps" : "(37.623322,-122.384974579)" '

    hs_record = ' "phone" : "{}", "health-state" : "not-tested" '

    #
    # Now loop.
    #
    ts = lisp.lisp_get_timestamp()
    for i in range(1, count + 1):
        site_eid = lisp.lisp_site_eid(parent_site.site)
        site_eid.eid = copy.deepcopy(eid)
        site_eid.eid.address = hmac.new("ct", str(phone),
            hashlib.sha256).hexdigest()

        site_eid.dynamic = True
        site_eid.parent_for_more_specifics = parent_site
        site_eid.add_cache()
        site_eid.inherit_from_ams_parent()
        parent_site.more_specific_registrations.append(site_eid)

        #
        # Add GPS and HS RLOC records for EID entry.
        #
        gr = copy.deepcopy(rloc)
        json_string = "{" + gps_record.format(phone) + "}"
        gr.json = lisp.lisp_json(site_eid.eid.address, json_string)
        hr = copy.deepcopy(rloc)
        json_string = "{" + hs_record.format(phone) + "}"
        hr.json = lisp.lisp_json(site_eid.eid.address, json_string)
        site_eid.registered_rlocs = [gr, hr]

        #
        # Print every 100 added.
        #
        if (i % 100 == 0):
            lisp.fprint("Added {} site-eid entries".format(i))
        #endif

        #
        # Pause after 10000.
        #
        if (i % 10000 == 0 and i != count):
            lisp.fprint("Sleeping for 100ms ...")
            time.sleep(.1)
        #endif
        phone += 1
    #endfor

    #
    # Compute and print elapsed time.
    #
    ts = time.time() - ts
    if (ts < 60):
        lisp.fprint("Finished in {} secs".format(round(ts, 3)))
    else:
        ts = ts / 60
        lisp.fprint("Finished in {} mins".format(round(ts, 1)))
    #endif
    lisp_inject_mode_count = 0
#enddef

#
# lisp_timeout_pubsub
#
# Time out entries in lisp_pubsub_cache.
#
def lisp_timeout_pubsub():
    lisp.lisp_set_exception()

    #
    # Return quickly if inject mode is not enabled.
    #
    lisp_ms_scale_inject()

    now = lisp.lisp_get_timestamp()

    delete_list = []
    for e in lisp.lisp_pubsub_cache:
        for pubsub in lisp.lisp_pubsub_cache[e].values():
            ttl = pubsub.ttl * 60
            if (pubsub.uptime + ttl > now): continue
            delete_list.append([e, pubsub.xtr_id])
        #endfor
    #endfor

    #
    # Remove entries from delete queue.
    #
    for e, xtr_id in delete_list:
        eid = lisp.green(e, False)
        lisp.lprint("Pubsub state {} for xtr-id 0x{} has {}".format(eid,
             lisp.lisp_hex_string(xtr_id), lisp.bold("timed out", False)))

        #
        # Remove entry from dictionary array. And explictly free memory.
        #
        entry = lisp.lisp_pubsub_cache[e][xtr_id]
        lisp.lisp_pubsub_cache[e].pop(xtr_id)
        del(entry)

        #
        # If not more subscriptions for this EID-prefix, remove EID-prefix
        # from parent dictionary array.
        #
        if (len(lisp.lisp_pubsub_cache[e]) == 0): 
            lisp.lisp_pubsub_cache.pop(e)
        #endif
    #endfor

    #
    # Restart periodic timer.
    #
    lisp_pubsub_timer = threading.Timer( \
        lisp.LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL, lisp_timeout_pubsub, [])
    lisp_pubsub_timer.start()
    return
#enddef

#
# lisp_ms_startup
#
# Intialize this LISP MS process. This function returns a LISP network
# listen socket.
#
def lisp_ms_startup():
    global lisp_ipc_listen_socket
    global lisp_send_sockets
    global lisp_site_timer, lisp_pubsub_timer

    lisp.lisp_i_am("ms")
    lisp.lisp_set_exception()
    lisp.lisp_print_banner("Map-Server starting up")

    #
    # Get local address for source RLOC for encapsulation.
    #
    if (lisp.lisp_get_local_addresses() == False): return(False)

    #
    # Open send socket.
    #
    lisp_ipc_listen_socket = lisp.lisp_open_listen_socket("",  "lisp-ms")
    lisp_send_sockets[0] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV4)
    lisp_send_sockets[1] = lisp.lisp_open_send_socket("", lisp.LISP_AFI_IPV6)
    lisp_send_sockets[2] = lisp_ipc_listen_socket

    #
    # Start site-cache timeout timer.
    #
    lisp_site_timer = threading.Timer(lisp.LISP_SITE_TIMEOUT_CHECK_INTERVAL, 
        lisp_timeout_sites, [])
    lisp_site_timer.start()

    #
    # Start pubsub-cache timeout timer.
    #
    timer = lisp.LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL
    if (lisp_inject_mode_count != 0): timer = 5
    lisp_pubsub_timer = threading.Timer(timer, lisp_timeout_pubsub, [])
    lisp_pubsub_timer.start()
    return(True)
#enddef

#
# lisp_ms_shutdown
#
# Shutdown process.
#
def lisp_ms_shutdown():
    global lisp_site_timer

    #
    # Cancel site timeout timer.
    #
    lisp_site_timer.cancel()

    #
    # Close sockets.
    #
    lisp.lisp_close_socket(lisp_send_sockets[0], "")
    lisp.lisp_close_socket(lisp_send_sockets[1], "")
    lisp.lisp_close_socket(lisp_ipc_listen_socket, "lisp-ms")
    return
#enddef

#------------------------------------------------------------------------------

#
# Main entry point for process.
#
if (lisp_ms_startup() == False):
    lisp.lprint("lisp_ms_startup() failed")
    lisp.lisp_print_banner("Map-Server abnormal exit")
    exit(1)
#endif

while (True):
    opcode, source, port, packet = \
        lisp.lisp_receive(lisp_ipc_listen_socket, True)
    if (source == ""): break

    if (opcode == "command"): 
        lispconfig.lisp_process_command(lisp_ipc_listen_socket, opcode, 
            packet, "lisp-ms", [lisp_ms_commands, lisp.lisp_policy_commands])
    elif (opcode == "api"):
        lisp.lisp_process_api("lisp-ms", lisp_ipc_listen_socket, packet)
    else:
        lisp.lisp_parse_packet(lisp_send_sockets, packet, source, port)
    #endif
#endwhile

lisp_ms_shutdown()
lisp.lisp_print_banner("Map-Server normal exit")
exit(0)

#------------------------------------------------------------------------------
