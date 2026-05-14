# lispers.net

This directory contains the world's most feature-rich implementation of the Locator/ID Separation Protocol (LISP).

## Overview

Refer to [docs/lisp-runs-on.pdf](https://github.com/farinacci/lispers.net/blob/master/docs/lisp-runs-on.pdf) for a comprehensive list of LISP use-cases. The code in this git repo is an implementation of LISP in Python and Golang to run in a "routing-as-an-application" mode. LISP is an open, scalable overlay architecture and set of protocols developed by hundreds of people dating back to fall 2006.

For more information, visit [lispers.net](https://www.lispers.net).

**Contact:** support@lispers.net

## Supported Platforms

### Operating Systems

- Ubuntu, Debian, CentOS, macOS
- Raspbian, Alpine Linux, Rocky Linux
- Docker (guest-OS: Ubuntu, Debian, CentOS, or Alpine Linux)
- Kubernetes (guest-OS: Ubuntu)

### Cloud Platforms

- AWS, GCP, Azure, Lambda, Linode

### Vendor Platforms

- Arista EOS (Linux Fedora)
- Cisco IOS-XE guestshell (Linux CentOS)
- Nvidia Bluefield-3 DPU

## Getting Started

To run the lispers.net code, simply download and extract the latest tarball for your device or platform:

1. Download the latest release tarball from the [`build/latest-py2`](https://github.com/farinacci/lispers.net/tree/master/build/latest-py2) or [`build/latest-py3`](https://github.com/farinacci/lispers.net/tree/master/build/latest-py3) symlink
2. Extract the tarball on your device or platform
3. Refer to the how-to instructions to load Python dependencies
4. Follow the configuration instructions below

## Configuration

For detailed command syntax and functionality, see:
- [`docs/lisp-config-commands.txt`](https://github.com/farinacci/lispers.net/blob/master/docs/lisp-config-commands.txt)

For instructions on loading Python dependencies, see the how-to documentation.

## Supported RFCs and Internet-Drafts

The lispers.net implementation supports the following IETF LISP Working Group RFCs and Internet-Drafts:

- [RFC 6830](https://www.rfc-editor.org/rfc/rfc6830.html) — The Locator/ID Separation Protocol (LISP)
- [RFC 6831](https://www.rfc-editor.org/rfc/rfc6831.html) — The Locator/ID Separation Protocol (LISP) for Multicast Environments
- [RFC 6832](https://www.rfc-editor.org/rfc/rfc6832.html) — Interworking between Locator/ID Separation Protocol (LISP) and Non-LISP Sites
- [RFC 6833](https://www.rfc-editor.org/rfc/rfc6833.html) — Locator/ID Separation Protocol (LISP) Map-Server Interface
- [RFC 6835](https://www.rfc-editor.org/rfc/rfc6835.html) — The Locator/ID Separation Protocol Internet Groper (LIG)
- [RFC 7954](https://www.rfc-editor.org/rfc/rfc7954.html) — Locator/ID Separation Protocol (LISP) Endpoint Identifier (EID) Block
- [RFC 8060](https://www.rfc-editor.org/rfc/rfc8060.html) — LISP Canonical Address Format (LCAF)
- [RFC 8061](https://www.rfc-editor.org/rfc/rfc8061.html) — Locator/ID Separation Protocol (LISP) Data-Plane Confidentiality
- [RFC 8111](https://www.rfc-editor.org/rfc/rfc8111.html) — Locator/ID Separation Protocol Delegated Database Tree (LISP-DDT)
- [RFC 8112](https://www.rfc-editor.org/rfc/rfc8112.html) — LISP-DDT Referral Internet Groper (RIG)
- [RFC 8378](https://www.rfc-editor.org/rfc/rfc8378.html) — Signal-Free Locator/ID Separation Protocol (LISP) Multicast
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) — ChaCha20 and Poly1305 for IETF Protocols
- [RFC 9299](https://www.rfc-editor.org/rfc/rfc9299.html) — Architectural Introduction to Locator/ID Separation Protocol (LISP)
- [RFC 9300](https://www.rfc-editor.org/rfc/rfc9300.html) — The Locator/ID Separation Protocol (LISP) Proposed Standard
- [RFC 9301](https://www.rfc-editor.org/rfc/rfc9301.html) — Locator/ID Separation Protocol (LISP) Control Plane Proposed Standard
- [RFC 9306](https://www.rfc-editor.org/rfc/rfc9306.html) — LISP Canonical Address Format (LCAF)
- [RFC 9437](https://www.rfc-editor.org/rfc/rfc9437.html) — Publish/Subscribe Functionality for LISP
- [RFC 9735](https://www.rfc-editor.org/rfc/rfc9735.html) — LISP Distinguished Name Encoding
- [RFC 9962](https://www.rfc-editor.org/info/rfc9962.html) — A Decentralized Locator/ID Separation Protocol Mapping System (LISP-Decent)

---    

- [draft-ietf-lisp-8111bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-8111bis/) — Locator/ID Separation Protocol Delegated Database Tree (LISP-DDT)
- [draft-ietf-lisp-ecdsa-auth](https://datatracker.ietf.org/doc/draft-ietf-lisp-ecdsa-auth/) — LISP Control-Plane ECDSA Authentication and Authorization
- [draft-ietf-lisp-eid-anonymity](https://datatracker.ietf.org/doc/draft-ietf-lisp-eid-anonymity/) — LISP EID Anonymity
- [draft-ietf-lisp-eid-mobility](https://datatracker.ietf.org/doc/draft-ietf-lisp-eid-mobility/) — LISP L2/L3 EID Mobility Using a Unified Control Plane
- [draft-ietf-lisp-geo](https://datatracker.ietf.org/doc/draft-ietf-lisp-geo/) — LISP Geo-Coordinate Use-Cases
- [draft-ietf-lisp-mn](https://datatracker.ietf.org/doc/draft-ietf-lisp-mn/) — LISP Mobile Node
- [draft-ietf-lisp-nat-traversal](https://datatracker.ietf.org/doc/draft-ietf-lisp-nat-traversal/) — NAT traversal for LISP
- [draft-ietf-lisp-name-encoding](https://datatracker.ietf.org/doc/draft-ietf-lisp-name-encoding/) — LISP Distinguished Name Encoding
- [draft-ietf-lisp-predictive-rlocs](https://datatracker.ietf.org/doc/draft-ietf-lisp-predictive-rlocs/) — LISP Predictive RLOCs
- [draft-ietf-lisp-pubsub](https://datatracker.ietf.org/doc/draft-ietf-lisp-pubsub/) — Publish/Subscribe Functionality for LISP
- [draft-ietf-lisp-rfc6830bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-rfc6830bis/) — The Locator/ID Separation Protocol (LISP)
- [draft-ietf-lisp-rfc6831bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-rfc6831bis/) — The Locator/ID Separation Protocol (LISP) for Multicast Environments
- [draft-ietf-lisp-rfc6833bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-rfc6833bis/) — Locator/ID Separation Protocol (LISP) Control-Plane
- [draft-ietf-lisp-rfc8060bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-rfc8060bis/) — LISP Canonical Address Format (LCAF)
- [draft-ietf-lisp-rfc8378bis](https://datatracker.ietf.org/doc/draft-ietf-lisp-rfc8378bis) — Signal-Free Locator/ID Separation Protocol (LISP) Multicast
- [draft-ietf-lisp-te](https://datatracker.ietf.org/doc/draft-ietf-lisp-te/) — LISP Traffic Engineering Use-Cases
- [draft-ietf-lisp-vpn](https://datatracker.ietf.org/doc/draft-ietf-lisp-vpn/) — LISP Virtual Private Networks (VPNs)

---

- [draft-ermagan-lisp-nat-traversal](https://datatracker.ietf.org/doc/draft-ermagan-lisp-nat-traversal/) — NAT traversal for LISP
- [draft-farinacci-lisp-decent](https://datatracker.ietf.org/doc/draft-farinacci-lisp-decent/) — A Decent LISP Mapping System (LISP-Decent)
- [draft-farinacci-lisp-lispers-net-nat](https://datatracker.ietf.org/doc/draft-farinacci-lisp-lispers-net-nat/) — Simple NAT traversal for LISP
- [draft-farinacci-lisp-mobile-network](https://datatracker.ietf.org/doc/draft-farinacci-lisp-mobile-network/) — LISP for the Mobile Network
- [draft-farinacci-lisp-satellite-network](https://datatracker.ietf.org/doc/draft-farinacci-lisp-satellite-network/) — LISP for Satellite Networks
- [draft-farinacci-lisp-telemetry](https://datatracker.ietf.org/doc/draft-farinacci-lisp-telemetry/) — LISP Data-Plane Telemetry

---
