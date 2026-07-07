// NEGATIVE control (mirrors the obf-js corpus fixture): the decode goes through a
// user-defined helper, not a recognized decode primitive, so intra-file taint
// cannot prove decode -> exec. BP-OBFEXEC must STAY at co-occurrence confidence.
// This guards against the dataflow pass over-proving and drifting the oracle.
const payload = "ZWNobyBoaQ==";
function base64_decode(s) { return Buffer.from(s, "base64").toString(); }
const code = base64_decode(payload);
eval(code);
