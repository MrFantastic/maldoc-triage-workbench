"""Trusted SHA-256 hashes of Didier Stevens' tools at one pinned DidierStevensSuite commit.

setup_vendor.py downloads exactly these files from exactly this commit and refuses any
file whose hash differs, so a tampered or rewritten upstream file is never installed.
The hashes were computed when the pin was made, not at install time, and every change
to this file is a reviewable diff.

How this pin was verified (2026-10-26), before it was committed:
  * git: a clone of github.com/DidierStevens/DidierStevensSuite, hashing the blobs at
    COMMIT (git checks object integrity end to end)
  * raw CDN: the same files fetched from raw.githubusercontent.com/.../COMMIT/ (a
    different GitHub service), hashed independently: all 16 matched
  * REMnux: the 8 tools REMnux ships in /opt/didier-stevens/bin (pdfid, its 3 plugins,
    pdf-parser, zipdump, rtfdump, oledump) are identical to these apart from the first
    line, which REMnux rewrites to its own interpreter (#!/opt/didier-stevens/bin/python3).
    REMnux doesn't ship the oledump plugins, so those rest on the two GitHub routes.

To move the pin, run  python setup_vendor.py --update-pin <commit>  (it fetches every
file from two GitHub services and writes this file only if they agree), then review
the diff before committing.
"""

REPO = "DidierStevens/DidierStevensSuite"
COMMIT = "471ccab728d0e4345c70165fb93c990008b2514b"
COMMIT_DATE = "2026-04-19"

# vendor-relative path -> SHA-256 of the file at COMMIT (upstream name = last path part)
FILES = {
    "pdfid.py": "e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f",
    "plugin_triage.py": "c6e6145f6cf9b28594d85d11d1681cd9c7db9a8d85938ba78f4905396ca9f85c",
    "plugin_embeddedfile.py": "af5bf0c5fb44612d9e8f75af24791f7403b5b3847ed8eb58448fb3a58aef6cd7",
    "plugin_nameobfuscation.py": "3097f900eaca41669f551fd43c99be1e17666db1aac1ec8f0e04d1796795d61e",
    "pdf-parser.py": "a9fa2faa25e88ab0293543d14aa168ff21fc9fd25a0a8ad657b0dad3171214ac",
    "zipdump.py": "8b73c1529e6a1facbf239b19354dc49894f7305656c1a83763e5420e220c31f0",
    "rtfdump.py": "3c57fa8192bc0d3179ae750b8d79240173ec6c68fcb50df7a29762e03cac875d",
    "oledump/oledump.py": "9a18a2b5ab877be8d86d218b8933933ce2be9dfd3cdcb1d971da5e27765b73eb",
    "oledump/plugin_vba_summary.py": "d3b2b804a5992de17935dc43bd38c4cf371789c90c81f359eb61495b208ec071",
    "oledump/plugin_biff.py": "4073d1edbff47cb33fed7bdd7bb104b5f1729bd6f28a2f2b10165a9c77857230",
    "oledump/plugin_http_heuristics.py": "d750895bec1d57bc786db545b767f5c5064412ab86848ae744e8c60b4648aa15",
    "oledump/plugin_dridex.py": "abcdd7d762d083e381c8cc8f9b6ab30499fbd87430c4acb4a9805a14d7b91fdd",
    "oledump/plugin_msg.py": "1985f3c62d798e113ea3ddfb5abf1e52031fa6a3035cfdbe77cda41158f4c095",
    "oledump/plugin_stream_o.py": "76a8c36e232fd6246ea28a792ad48f6b99377276553f4cef8e866715174b1309",
    "oledump/plugin_vba_routines.py": "766e89a98c22207a9c10892525d42b2577edc50040152da073ce3964c4064d8f",
    "oledump/plugin_vba_dco.py": "0c31fb48a51da8d712e55f8d8f115e5e257c90107c51c8ded421e6da3316d5f7",
}

# independent sources that agreed with FILES when the pin was made
VERIFIED_WITH = ("git clone (object integrity)", "raw.githubusercontent.com",
                 "REMnux /opt/didier-stevens/bin (8 tools, code identical apart from the #! line)")
