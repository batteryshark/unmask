import json
def load(path):
    with open(path) as f:
        return json.load(f)
def dumps(obj):
    return json.dumps(obj, indent=2, sort_keys=True)
