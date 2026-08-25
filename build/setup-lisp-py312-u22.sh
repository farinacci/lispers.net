#!/bin/bash
#
# setup-lisp-py312-u22.sh
#
# Provision Python 3.12 + lispers.net runtime dependencies on Ubuntu 22.04,
# WITHOUT disturbing the system python (apt keeps 3.10) or `python` (python2).
#
#   Run as:  sudo bash setup-lisp-py312-u22.sh
#
# Result:  bare `python3` -> a 3.12 venv that has all lisp deps
#          `python`        -> unchanged (python2)
#          /usr/bin/python3 -> unchanged (3.10, for apt)
#
set -e
export DEBIAN_FRONTEND=noninteractive

echo "== 1. Install Python 3.12 (22.04 default is 3.10) + build tools =="
apt-get update
apt-get install -y software-properties-common
add-apt-repository -y ppa:deadsnakes/ppa
apt-get update
apt-get install -y python3.12 python3.12-dev python3.12-venv build-essential git

echo "== 2. Create isolated venv with fresh pip/setuptools/wheel =="
# The apt setuptools (59.6.0) in /usr/lib/python3/dist-packages is too old to build
# C-extensions on 3.12; a venv gets its own fresh setuptools, sidestepping that.
python3.12 -m venv /opt/lisp-venv
/opt/lisp-venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "== 3. Install lispers.net dependencies into the venv =="
/opt/lisp-venv/bin/python -m pip install \
    future netifaces ecdsa geopy curve25519 distro bottle cheroot \
    requests pcapy-ng pycryptodome cryptography

echo "== 4. Route bare python3 to the venv via a WRAPPER =="
# A symlink to the venv python resolves back to the base interpreter and skips
# venv activation, so use a wrapper that execs the venv python by its venv path.
# `python` is left untouched (stays python2).
rm -f /usr/local/bin/python3
printf '#!/bin/sh\nexec /opt/lisp-venv/bin/python3 "$@"\n' > /usr/local/bin/python3
chmod +x /usr/local/bin/python3

echo "== 5. Verify =="
hash -r 2>/dev/null || true
echo -n "bare python3 -> " ; /usr/local/bin/python3 --version
/usr/local/bin/python3 -c "import future, netifaces, ecdsa, geopy, curve25519, distro, bottle, cheroot, requests, pcapy, Crypto, cryptography; print('all deps OK')"
echo "SUCCESS: python3 = venv 3.12 (all deps); python = python2 (unchanged); /usr/bin/python3 = $(/usr/bin/python3 --version 2>&1)"
echo ""
echo "NOTE (tcsh users): run 'rehash' in your shell so it picks up the new python3."
