"""Independent canonical-byte/digest checks for the packet's restricted JSON values."""
import hashlib
import json
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate property')
        result[key] = value
    return result


def canonical(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda x: x.encode('utf-16-be'))
        return '{' + ','.join(canonical(k) + ':' + canonical(value[k]) for k in keys) + '}'
    if isinstance(value, list):
        return '[' + ','.join(map(canonical, value)) + ']'
    if isinstance(value, float):
        raise ValueError('fixture profile uses only integers')
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 9007199254740991:
        raise ValueError('unsafe JSON number')
    if isinstance(value, str):
        value.encode('utf-8', errors='strict')
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


vectors = json.loads(Path(__file__).with_name('vectors.json').read_text(), object_pairs_hook=unique_object)
for case in vectors['canonical']:
    encoded = canonical(case['body'])
    assert encoded == case['canonical'], case['name']
    preimage = ('BRC-OUTPUT/1/' + case['type']).encode() + b'\x00' + encoded.encode()
    assert hashlib.sha256(preimage).hexdigest() == case['digest'], case['name']
try:
    json.loads('{"version":1,"version":2}', object_pairs_hook=unique_object)
except ValueError:
    pass
else:
    raise AssertionError('duplicate keys accepted')
print(json.dumps({'canonical_vectors': len(vectors['canonical']), 'duplicate_keys_rejected': True}))
