#!/usr/bin/env python3
"""Guard OpenSSL-only WINSOCK blocks with HAVE_SSL (unbound --without-ssl on MinGW)."""
from pathlib import Path

def patch_file(path: Path, replacements):
    text = path.read_text()
    original = text
    for old, new in replacements:
        if old not in text:
            raise SystemExit(f"{path}: missing expected snippet:\n{old!r}")
        text = text.replace(old, new, 1)
    if text == original:
        raise SystemExit(f"{path}: no changes applied")
    path.write_text(text)
    print(f"patched {path}")

# net_help.c: wrap add_WIN_cacerts_to_openssl_store
patch_file(Path("util/net_help.c"), [
(
"""#ifdef USE_WINSOCK
/* For windows, the CA trust store is not read by openssl.
   Add code to open the trust store using wincrypt API and add
   the root certs into openssl trust store */
static int
add_WIN_cacerts_to_openssl_store(SSL_CTX* tls_ctx)
""",
"""#if defined(USE_WINSOCK) && defined(HAVE_SSL)
/* For windows, the CA trust store is not read by openssl.
   Add code to open the trust store using wincrypt API and add
   the root certs into openssl trust store */
static int
add_WIN_cacerts_to_openssl_store(SSL_CTX* tls_ctx)
""",
),
(
"""\tverbose(VERB_ALGO, "Completed adding Windows certificates to CA store successfully");
\treturn 1;
}
#endif /* USE_WINSOCK */

void* connect_sslctx_create(char* key, char* pem, char* verifypem, int wincert)
""",
"""\tverbose(VERB_ALGO, "Completed adding Windows certificates to CA store successfully");
\treturn 1;
}
#endif /* USE_WINSOCK && HAVE_SSL */

void* connect_sslctx_create(char* key, char* pem, char* verifypem, int wincert)
""",
),
])

# netevent.c: wrap win_bio_cb + definition + one call site
netevent = Path("util/netevent.c").read_text()
old_bio = """#ifdef USE_WINSOCK
static long win_bio_cb(BIO *b, int oper, const char* ATTR_UNUSED(argp),"""
new_bio = """#if defined(USE_WINSOCK) && defined(HAVE_SSL)
static long win_bio_cb(BIO *b, int oper, const char* ATTR_UNUSED(argp),"""
if old_bio not in netevent:
    raise SystemExit("util/netevent.c: missing win_bio_cb ifdef")
netevent = netevent.replace(old_bio, new_bio, 1)
# Close the block after comm_point_tcp_win_bio_cb function — find the unique endif after BIO_set_callback
# Upstream ends the block with `#endif` right after the function; locate via marker.
marker = "BIO_set_callback(SSL_get_wbio(ssl), &win_bio_cb);\n#endif\n\n#ifdef HAVE_NGHTTP2"
marker_alt = "BIO_set_callback(SSL_get_wbio(ssl), &win_bio_cb);\n#endif\n"
# Try to find end of win_bio block more carefully
import re
# After replacing opening ifdef, close with annotated endif before next major section
# Find the function end: look for pattern after win_bio_cb function
pat = re.compile(
    r"(comm_point_tcp_win_bio_cb\(struct comm_point\* c, void\* thessl\)\s*\{.*?\n\})\n#endif",
    re.S,
)
m = pat.search(netevent)
if not m:
    raise SystemExit("util/netevent.c: could not find end of win_bio block")
netevent = netevent[: m.end() - len("#endif")] + "#endif /* USE_WINSOCK && HAVE_SSL */" + netevent[m.end():]

# call site in netevent.c
old_call = """#ifdef USE_WINSOCK
\t\tcomm_point_tcp_win_bio_cb(c_hdl, c_hdl->ssl);
#endif"""
new_call = """#if defined(USE_WINSOCK) && defined(HAVE_SSL)
\t\tcomm_point_tcp_win_bio_cb(c_hdl, c_hdl->ssl);
#endif"""
if old_call not in netevent:
    raise SystemExit("util/netevent.c: missing win_bio call site")
netevent = netevent.replace(old_call, new_call, 1)
Path("util/netevent.c").write_text(netevent)
print("patched util/netevent.c")

# netevent.h
patch_file(Path("util/netevent.h"), [
(
"""#ifdef USE_WINSOCK
/**
 * Callback for openssl BIO to on windows detect WSAEWOULDBLOCK and notify
 * the winsock_event of this for proper TCP nonblocking implementation.
""",
"""#if defined(USE_WINSOCK) && defined(HAVE_SSL)
/**
 * Callback for openssl BIO to on windows detect WSAEWOULDBLOCK and notify
 * the winsock_event of this for proper TCP nonblocking implementation.
""",
),
])
# fix closing endif in header — find declaration
h = Path("util/netevent.h").read_text()
# After our change, still need to close properly. Find declaration + endif
if "void comm_point_tcp_win_bio_cb(struct comm_point* c, void* ssl);" not in h:
    raise SystemExit("util/netevent.h: missing declaration")
# Replace the first remaining `#endif` after the declaration that closed USE_WINSOCK
idx = h.find("void comm_point_tcp_win_bio_cb(struct comm_point* c, void* ssl);")
rest = h[idx:]
endif_idx = rest.find("#endif")
if endif_idx < 0:
    raise SystemExit("util/netevent.h: missing endif after declaration")
# only annotate if not already
chunk = rest[endif_idx:endif_idx+40]
if "HAVE_SSL" not in chunk:
    h = h[:idx] + rest[:endif_idx] + "#endif /* USE_WINSOCK && HAVE_SSL */" + rest[endif_idx+len("#endif"):]
    Path("util/netevent.h").write_text(h)
    print("annotated util/netevent.h endif")

# outside_network.c — two call sites
out = Path("services/outside_network.c").read_text()
for old, new in [
(
"""#ifdef USE_WINSOCK
\t\tcomm_point_tcp_win_bio_cb(pend->c, pend->c->ssl);
#endif""",
"""#if defined(USE_WINSOCK) && defined(HAVE_SSL)
\t\tcomm_point_tcp_win_bio_cb(pend->c, pend->c->ssl);
#endif""",
),
(
"""#ifdef USE_WINSOCK
\tcomm_point_tcp_win_bio_cb(cp, cp->ssl);
#endif""",
"""#if defined(USE_WINSOCK) && defined(HAVE_SSL)
\tcomm_point_tcp_win_bio_cb(cp, cp->ssl);
#endif""",
),
]:
    if old not in out:
        raise SystemExit(f"services/outside_network.c: missing snippet:\n{old!r}")
    out = out.replace(old, new, 1)
Path("services/outside_network.c").write_text(out)
print("patched services/outside_network.c")
print("unbound windows-without-ssl patch applied")
