function slugify(s) { return String(s).trim().toLowerCase().replace(/\s+/g, "-"); }
function titleCase(s) { return String(s).replace(/\b\w/g, c => c.toUpperCase()); }
module.exports = { slugify, titleCase };
