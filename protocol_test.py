
GRID=48
def reserved(r,c):
    return (r<9 and c<9) or (r<9 and c>=GRID-9) or (r>=GRID-9 and c<9) or (r>=GRID-9 and c>=GRID-9)
def crc32(a):
    import zlib
    return zlib.crc32(bytes(a)) & 0xffffffff
def encode(payload):
    out=bytearray([83,86,84,80,1,1,(len(payload)>>8)&255,len(payload)&255])
    c=crc32(payload); out += bytes([(c>>24)&255,(c>>16)&255,(c>>8)&255,c&255,0xA7,0x31])
    out += payload
    bits=[]
    for b in out:
        bits += [(b>>i)&1 for i in range(7,-1,-1)]
    cells=[]
    for r in range(GRID):
        for c in range(GRID):
            if not reserved(r,c): cells.append(bits[len(cells)] if len(cells)<len(bits) else 0)
    return out,cells
def decode(out,cells):
    bits=cells
    raw=bytearray()
    for i in range(0,len(bits)-7,8):
        b=0
        for x in bits[i:i+8]: b=(b<<1)|x
        raw.append(b)
    assert raw[:6]==bytes([83,86,84,80,1,1])
    n=(raw[6]<<8)|raw[7]
    d=raw[14:14+n]
    assert crc32(d)==int.from_bytes(raw[8:12],'big')
    assert raw[12:14]==bytes([0xA7,0x31])
    return d
