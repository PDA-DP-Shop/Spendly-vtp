
import json, random, subprocess, sys
from protocol_test import encode, decode
for i in range(1000):
    payload=bytes(random.randrange(256) for _ in range(random.randrange(1,220)))
    raw,cells=encode(payload)
    assert len(raw)==14+len(payload)
    assert decode(raw,cells)==payload
for n in [1,10,50,100,150,200,220]:
    payload=bytes((x*37+n)%256 for x in range(n))
    raw,cells=encode(payload)
    assert decode(raw,cells)==payload
print("1000 random round-trips: PASS")
print("boundary payload tests: PASS")
print("capacity bytes:", sum(1 for r in range(48) for c in range(48) if not ((r<9 and c<9) or (r<9 and c>=39) or (r>=39 and c<9) or (r>=39 and c>=39)))//8)
