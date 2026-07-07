const payload = "ZWNobyBoaQ==";
function base64_decode(s) { return Buffer.from(s, "base64").toString(); }
const code = base64_decode(payload);
eval(code);
