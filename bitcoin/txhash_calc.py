#!/usr/bin/python3
import json
from hashlib import sha256
from binascii import hexlify, unhexlify

#segwit tx
# txid = "06f84a508b0f83a92847b92c18c7e98258f9e2c73bda0b6b6ab253938807f3fe"
# txhash = "eb3417e7d6dc1c153c6b67d5587494235f2febaf4c700af2967e9339bea99d1c"
# rawtx = "0200000000010170878ded40048035dececcd732ccedc8140fcf44723504d27e06ca995a39ed090f00000000ffffffff01b106dd000000000017a914b1962ee0f907260bda0d0de9385e5303e8153d6c870247304402203a2736d25bfec77a26da3771bc7cc6f7699a7ee4e056d140fbc5df629431242802200c1e936c1fc0180d679cfb9a7512404638c87574fb3c0f60c363492885506f4d01210391e10e73ec5c1cc6dcad411641d19499b296467d81ad4945659dd8199c4b69a700000000"

# legacy tx (version 2)
# txid = "747a2d3e24b2cd93bdf1e16e391564030cba9c3563b7288b273abee609e4546b"
# txhash = "747a2d3e24b2cd93bdf1e16e391564030cba9c3563b7288b273abee609e4546b"
# rawtx = "02000000017552798911bddf2f53688cdba3d743ecc43b708bacb54a1b31a36e70496168750b0000006a4730440220233b5e06774289d01fc3e11dba97d5d6afad65096195e0d6d064a45819acdfdd022068e24d9d449f425156570f20b15afca93b3512254beb4a829cfba3b56bbd1961012103ca9ed917350b9b246f81109934d78afd65fd2003573f2003259cef787eb17d7ffdffffff019cf30600000000001976a914cfe50dfdfe988a6f477167f235d9243d3f1feaf188ac00000000"

# legacy tx (version 1)
txid = "1700190f68bac2266166207a040debb0bd68a50afc53f1fd0a6bdde762f7d93c"
txhash = "1700190f68bac2266166207a040debb0bd68a50afc53f1fd0a6bdde762f7d93c"
rawtx = "01000000017fc256ccbd94d67bd5d87043664c5ff1ce6431a4f1f3d3b80b643d30382c3f6700000000fdfd0000473044022067bed352f562ae65fed75711793e074c50e9760d34eb71bc9abb480627b8f42402204391360d339ac8e9ba0e69cbfc9f65a148334b2af73276a51fa774e41404e2d101483045022100ca2508dc2d87942b157d8e2d0d0133f88a8002d653579280c8161bc128df62ff0220675f74dd614fdf163a1d3d198d1846e2c9375de1ee55e22bb222351ad088b31a014c69522103c70ddd874026bf2d2574af5381fa6a59c28aaa26c1e725894a7088c7f81dca1321026d6f7d8a6717734551c3c5e97e12bfdb70fd3816b09ddc6318d14e1e8d27b48d21025b0cd1c68a72a962077c97b026f12dc1611ae439cb027ebb02298385824f24d053aeffffffff0f3105170000000000225120adb2e81951452aaea69b444c0632910119f081d821d38e1650d057d2415a069f64555802000000001976a91434556ff91cc6f61c62445060c2308668a78d3b0188ac385b0b55000000001976a914a404e7d3e253bd82b28d6a14e98def9c1f40446888acc80617000000000022512046c965575fcc1d0deef3d2f91e850f1de295975b27410711e99ea1f1f971f1a376f20900000000001600143400717ee3334f3d23950c1820420825a47537d8c0e1e400000000001976a914a8a9a0c3536cb4652d126912ebfd18a0a676486a88ac9e30150000000000225120d62d48f1939db96e060c320163e423a2ea6973fae8cf2d84a34d705f0f390cfc804f120000000000225120c2df84f5b1801f3dafc371241f92c350e186955bcf110472ad5316ba8114d70a7426a4010000000017a914e98f2438cf6b6c676f263d3e8a5be26adc20f45a87e1bb040000000000225120964b083fd7cad84f473fafd18035e0ae597f9fa2772fbb44c87924141361e39b400d0300000000002251200246fa37d1fbf4fd1e0f7b8a8d59902ffd18b155ffcc81a6a245b08bc006cd35c892030000000000225120cbd20d86cdff050e0db6c677eeed0400e1feee2303a8488aac561b4da7b1e7e6b844350000000000225120f4dd50c844d09ede6dadf48d6784f482cbbe4c7b3e8d8cae981d917bb55d20afe91113000000000022512009f7a4a269abb0968b01276de816cecb6d54685df2b825bfb1bc00cf04ed2ddce16b931c00000000220020e5c7c00d174631d2d1e365d6347b016fb87b6a0c08902d8e443989cb771fa7ec00000000"

def hash(msg):
    return sha256(sha256(unhexlify(msg)).digest()).hexdigest()

def to_little(h):
    return ''.join(h[i-2:i] for i in range(len(h), 0, -2))

def to_big(h):
    return ''.join(h[i-2:i] for i in range(len(h), 0, -2))

def byteshift(s, bytes):
    return s[bytes*2:]

def parse_bytes_endian(nbytes):
    global rawtx
    nibbles = nbytes * 2
    return_value = to_big(rawtx[:nibbles])
    rawtx = byteshift(rawtx, nbytes)
    return return_value
    
def parse_bytes(nbytes):
    global rawtx
    nibbles = nbytes * 2
    return_value = rawtx[:nibbles]
    rawtx = byteshift(rawtx, nbytes)
    return return_value
    
def parse_compact_size():
    global rawtx
    first_byte = parse_bytes(1)

    if(first_byte == 'fd'):
        nbytes = 2
        res = parse_bytes_endian(nbytes)
    elif(first_byte == 'fe'):
        nbytes = 4
        res = parse_bytes_endian(nbytes)
    elif(first_byte == 'ff'):
        nbytes = 8
        res = parse_bytes_endian(nbytes)
    else:
        return first_byte
    
    return res
        
def encode_compact_size(s):
    prefix = ''
    if(s < 253):
        prefix = '' + '{:02x}'.format(s)
    elif(s < 65536):
        prefix = 'fd' + to_little('{:04x}'.format(s))
    elif(s < 4294967296):
        prefix = 'fe' + to_little('{:08x}'.format(s))
    else:
        prefix = 'ff' + to_little('{:016x}'.format(s))
        
    return prefix
    
def gen_txid(tx):
    inp = ''
    for i in range(len(tx['inputs'])):
        obj = tx['inputs'][i]
        inp = inp + to_little(obj['txid']) + to_little(obj['outputindex']) + encode_compact_size(int(obj['scriptsize'],16)) + obj['script'] + to_little(obj['sequence'])
    
    outp = ''
    for i in range(len(tx['outputs'])):
        obj = tx['outputs'][i]
        outp = outp + to_little(obj['amount']) + encode_compact_size(int(obj['scriptpubkeysize'],16)) + obj['scriptpubkey']
    
    concat = to_little(tx['version']) + encode_compact_size(int(tx['inputcount'],16)) + inp + encode_compact_size(int(tx['outputcount'],16)) + outp + to_little(tx['locktime'])
    
    return to_big(hash(concat))
    
def gen_txhash(tx):
    inp = ''
    for i in range(len(tx['inputs'])):
        obj = tx['inputs'][i]
        inp = inp + to_little(obj['txid']) + to_little(obj['outputindex']) + obj['scriptsize'] + obj['script'] + to_little(obj['sequence'])
    
    outp = ''
    for i in range(len(tx['outputs'])):
        obj = tx['outputs'][i]
        outp = outp + to_little(obj['amount']) + obj['scriptpubkeysize'] + obj['scriptpubkey']
        
    witness = ''
    for i in range(len(tx['witness'])):
        obj = tx['witness'][i]
        witness = witness + encode_compact_size(int(obj['size'],16)) + obj['item']
    
    concat = to_little(tx['version']) + tx['marker'] + tx['flag'] + encode_compact_size(int(tx['inputcount'],16)) + inp + encode_compact_size(int(tx['outputcount'],16)) + outp + encode_compact_size(int(tx['stackitems'],16))+ witness + to_little(tx['locktime'])

    return to_big(hash(concat))

def decode_tx():
    global rawtx
    
    tx = {}
    tx['version'] = parse_bytes_endian(4)

    if(int(tx['version'],16) >= 2):
        if(rawtx[:2] == '00'):
            return {**tx, **decode_segwit_tx()}
    return {**tx, **decode_legacy_tx()}

def decode_legacy_tx():
    tx = {}
    tx['inputcount'] = parse_compact_size()

    tx['inputs'] = []
    for i in range(0, int(tx['inputcount'],16)):
        inp = {}

        inp['txid'] = parse_bytes_endian(32)
        inp['outputindex'] = parse_bytes_endian(4)
        inp['scriptsize'] = parse_compact_size()
        inp['script'] = parse_bytes(int(inp['scriptsize'],16))
        inp['sequence'] = parse_bytes_endian(4)
        
        tx['inputs'].append(inp)
    
    tx['outputcount'] = parse_compact_size()
    tx['outputs'] = []
    for i in range(0, int(tx['outputcount'],16)):
        outp = {}
        
        outp['amount'] = parse_bytes_endian(8)
        outp['scriptpubkeysize'] = parse_compact_size()
        outp['scriptpubkey'] = parse_bytes(int(outp['scriptpubkeysize'], 16))

        tx['outputs'].append(outp)
        
    tx['locktime'] = parse_bytes(4)

    return tx

def decode_segwit_tx():
    tx = {}
    tx['marker'] = parse_bytes_endian(1)
    tx['flag'] = parse_bytes_endian(1)
    tx['inputcount'] = parse_compact_size()

    tx['inputs'] = []
    for i in range(0, int(tx['inputcount'],16)):
        inp = {}

        inp['txid'] = parse_bytes_endian(32)
        inp['outputindex'] = parse_bytes_endian(4)
        inp['scriptsize'] = parse_compact_size()
        inp['script'] = parse_bytes(int(inp['scriptsize'],16))
        inp['sequence'] = parse_bytes_endian(4)

        tx['inputs'].append(inp)
    
    tx['outputcount'] = parse_bytes_endian(1)

    tx['outputs'] = []
    for i in range(0, int(tx['outputcount'],16)):
        outp = {}
        
        outp['amount'] = parse_bytes_endian(8)
        outp['scriptpubkeysize'] = parse_bytes_endian(1)
        outp['scriptpubkey'] = parse_bytes(int(outp['scriptpubkeysize'], 16))

        tx['outputs'].append(outp)
        
    tx['stackitems'] = parse_compact_size()

    tx['witness'] = []
    for i in range(0, int(tx['stackitems'], 16)):
        stack = {}
        
        stack['size'] = parse_compact_size()
        stack['item'] = parse_bytes(int(stack['size'],16))

        tx['witness'].append(stack)

    tx['locktime'] = parse_bytes(4)

    return tx
    
tx = decode_tx()
print('decoded:', json.dumps(tx))
print('reference txid:', txid)
print('generated txid:', gen_txid(tx))
if('witness' in tx):
    print('reference txhash:', txhash)
    print('generated txhash:', gen_txhash(tx))
