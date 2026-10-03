"""Code shared by the broker and its paired daemons (hostd, sandboxd).

Daemons import this package and nothing server-side: it depends only on the
stdlib, `cryptography`, `httpx` and `websockets`.
"""
