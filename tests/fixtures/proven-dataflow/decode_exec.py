# A PROVEN decode-and-execute path: a base64 blob is decoded into `code`, and that
# exact value flows into exec(). Intra-file taint links source -> sink, so the
# dataflow pass must upgrade BP-OBFEXEC from co-occurrence (0.6) to proven (0.85).
import base64

blob = "cHJpbnQoJ2hpJyk="
code = base64.b64decode(blob).decode()
exec(code)
