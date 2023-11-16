"""
  exec(open('codes.py').read())

"""

from hashlib import sha256
import coincurve
import re


n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663


def cleanup_tx(hmn_read_tx):
    """ Given a block of text, strip out everything except 
        the hex strings
    """
    ret_val = []
    lines = hmn_read_tx.split('\n')
    for line in lines:
        substr = line.split(':')[-1]  # suggested-by @chrisguida + @macaki
        ret_val += re.findall(r'[0-9a-fA-F]{2}', substr)
    return ''.join(ret_val)


# FIXME: move these to common/utils lib
def parse_compact_size(data):
  first = int.from_bytes(data[0:1], 'big')
  if first < 253:
    return first, 1
  if first < 254:
    val = int.from_bytes(data[1:3], 'little')
    return val, 3
  if first < 255:
    val = int.from_bytes(data[1:5], 'little')
    return val, 5

  val = int.from_bytes(data[1:9], 'little')
  return val, 9

def size_compact_size(size):
  if size < 253:
    return (size).to_bytes(1, 'little')
  if size < 0xffff:
    return bytes([0xfd]) + (size).to_bytes(2, 'little')
  if size < 0xffffffff:
    return bytes([0xfe]) + (size).to_bytes(4, 'little')

  return bytes([0xff]) + (size).to_bytes(8, 'little')


def parse_input_bytes(tx_bytes):
  inputx = {}
  inputx['txid'] = tx_bytes[:32]
  ptr = 32
  inputx['vout'] = tx_bytes[ptr:ptr+4]
  ptr += 4

  count, size = parse_compact_size(tx_bytes[ptr:])
  ptr += size
  inputx['scriptSig'] = tx_bytes[ptr:ptr+count]
  ptr += count
  inputx['sequence'] = tx_bytes[ptr:ptr+4]
  return inputx, ptr+4


def parse_output_bytes(tx_bytes):
  outputx = {}
  ptr = 8
  outputx['amount'] = tx_bytes[:ptr]
  count, size = parse_compact_size(tx_bytes[ptr:])
  ptr += size
  outputx['scriptPubKey'] = tx_bytes[ptr:ptr+count]
  return outputx, ptr+count


def parse_tx_bytes(tx_hex):
  tx_bytes = bytes.fromhex(tx_hex)

  tx = {}
  ptr = 0
  tx['version'] = tx_bytes[0:4]
  ptr += 4

  if tx_bytes[ptr] == 0x00:
    assert tx_bytes[ptr+1] == 0x01
    tx['marker_flag'] = bytes([0x00, 0x01])
    ptr += 2

  count, size = parse_compact_size(tx_bytes[ptr:])
  ptr += size
  tx['inputs'] = []
  for _ in range(0, count):
    inputx, size = parse_input_bytes(tx_bytes[ptr:])
    ptr += size
    tx['inputs'].append(inputx)

  count, size = parse_compact_size(tx_bytes[ptr:])
  ptr += size
  tx['outputs'] = []
  for _ in range(0, count):
    outputx, size = parse_output_bytes(tx_bytes[ptr:])
    ptr += size
    tx['outputs'].append(outputx)

  if 'marker_flag' in tx:
    # todo, this
    assert False

  tx['locktime'] = tx_bytes[ptr:]
  return tx


def hashtag(tag, data):
    t = sha256(tag).digest()
    return sha256(t + t + data).digest()


def good_nonce(pk, pubkey, msg, ext_rand):
    # FIXME: Implement this
    # t = byte-wise xor of bytes(pk) and hashBIP0340/aux(ext_rand)
    # rand = hashBIP0340/nonce(t || bytes(pubkey) || m)
    # return int.from_bytes(rand) % n
    pass


def has_even_y_ok(pubkey):
    return pubkey.point()[1] % 2 == 0


def make_sig(r, s, sighash_flag):
    sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    if sighash_flag and sighash_flag > 0x00:
        sig += sighash_flag.to_bytes(1, 'big')
    return sig


def lift_x_ok(pubkey_x):
    assert pubkey_x < p
    c = (pubkey_x ** 3 + 7) % p
    y = pow(c, (p+1)//4, p)
    assert c == (y ** 2 % p)
    if y % 2 != 0:
        print('lifting y')
        y = p - y
    return coincurve.PublicKey.from_point(pubkey_x, y)


def invert_point(pubkey):
    x, y = pubkey.point()
    yneg = p - y
    return coincurve.PublicKey.from_point(x, yneg)


def schnorr_verify_ok(pubkey_x, digest_bytes, sig_bytes):
    assert len(sig_bytes) >= 64
    P = lift_x_ok(pubkey_x)
    r = int.from_bytes(sig_bytes[0:32], 'big')
    assert r < p
    s = int.from_bytes(sig_bytes[32:64], 'big')
    assert s < n
    tag = b'BIP0340/challenge'
    data = sig_bytes[0:32] + P.point()[0].to_bytes(32, 'big') + digest_bytes
    e_data = hashtag(tag, data)
    e = int.from_bytes(e_data, 'big') % n
    S = coincurve.PrivateKey.from_int(s).public_key
    E = P.multiply(e.to_bytes(32, 'big'))
    Eneg = invert_point(E)
    R = coincurve.PublicKey.combine_keys([S, Eneg])
    if not has_even_y_ok(R):
        return False
    return R.point()[0] == r


def schnorr_sign(digest_bytes, privkey_int, r_int):
    assert privkey_int > 0 and privkey_int < n
    P = coincurve.PrivateKey.from_int(privkey_int).public_key
    pk = privkey_int
    # if odd, pick opposite privkey
    if not has_even_y_ok(P):
        print('picking opposite privkey')
        pk = n - privkey_int
    # BIP340 gives us a 'good nonce' algo. we skip it.
    # r_int = good_nonce(pk, P, digest_bytes, None)
    assert r_int > 0 and r_int < n
    R = coincurve.PrivateKey.from_int(r_int).public_key
    k = r_int
    if not has_even_y_ok(R):
        print('picking opp k')
        k = n - r_int
    tag = b'BIP0340/challenge'
    data = R.point()[0].to_bytes(32, 'big') + P.point()[0].to_bytes(32, 'big') + digest_bytes
    e_data = hashtag(tag, data)
    e = int.from_bytes(e_data, 'big') % n
    s = (k + e * pk) % n
    r = R.point()[0]
    return r, s


def sighash(sigmsg, ext_hex):
    # sighash epoch, forever zero
    sighash_epoch = (0x00).to_bytes(1, 'little')
    data = sighash_epoch + sigmsg
    if ext_hex:
        data += bytes.fromhex(ext_hex)
    return hashtag(b'TapSighash', data)


def compute_sigmsg_ok(tx_hex, sighash_flag, input_index, scriptpubkey_list_hex, amounts_list_hex, extension_flag, annex_hex):
    tx = parse_tx_bytes(tx_hex)
    assert sighash_flag in [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]
    assert input_index < len(tx['inputs'])

    is_anyonecanpay = 0x80 & sighash_flag > 0
    is_none = sighash_flag in [0x02, 0x82]
    is_single = sighash_flag in [0x03, 0x83]

    data = sighash_flag.to_bytes(1, 'little')
    data += tx['version']
    data += tx['locktime']

    if not is_anyonecanpay:
        prevouts = b''
        for prevout in [inp['txid'] + inp['vout'] for inp in tx['inputs']]:
            prevouts += prevout
        data += sha256(prevouts).digest()

        amts = b''
        for amt in amounts_list_hex:
            amts += bytes.fromhex(amt)
        data += sha256(amts).digest()

        spks = b''
        for spk in scriptpubkey_list_hex:
            spk = bytes.fromhex(spk)
            spks += size_compact_size(len(spk)) + spk
        data += sha256(spks).digest()

        seqs = b''
        for seq in [inp['sequence'] for inp in tx['inputs']]:
            seqs += seq
        data += sha256(seqs).digest()

    if not is_none and not is_single:
        outputs = b''
        for outp in tx['outputs']:
            outputs += outp['amount'] + size_compact_size(len(outp['scriptPubKey'])) + outp['scriptPubKey']
        data += sha256(outputs).digest()

    spend_type = extension_flag * 2 + (len(annex_hex) > 0)
    data += spend_type.to_bytes(1, 'little')

    if is_anyonecanpay:
        inpt = tx['inputs'][input_index]
        # outpoint
        data += inpt['txid'] + inpt['vout']
        # amount
        data += bytes.fromhex(amounts_list_hex[input_index])
        # scriptPubKey
        spk = bytes.fromhex(scriptpubkey_list_hex[input_index])
        data += size_compact_size(len(spk)) + spk
        # nSequence
        data += inpt['sequence']
    else:
        # input_index
        data += input_index.to_bytes(4, 'little')

    if annex_hex:
        annex_bytes = bytes.fromhex(annex_hex)
        assert annex_bytes[0] == 0x50
        annex = size_compact_size(len(annex_bytes)) + annex_bytes
        data += sha256(annex).digest()

    if is_single:
        # sha_single_output
        outp = tx['outputs'][input_index]
        output = outp['amount'] + size_compact_size(len(outp['scriptPubKey'])) + outp['scriptPubKey']
        data += sha256(output).digest()

    # The total length of SigMsg() is at most 206 bytes
    assert len(data) <= 206

    return data


def make_leaf(script):
    leaf_version = 0xc0
    data = bytes([leaf_version]) + size_compact_size(len(script)) + script
    return hashtag(b'TapLeaf', data)


# pass in a tree of scripts
# [x, [x, [x, x]]] for example
def taptree_builder(script_lists):
    if isinstance(script_lists, bytes):
        return make_leaf(script_lists)

    left_hash = taptree_builder(script_lists[0])
    right_hash = taptree_builder(script_lists[1])

    if left_hash > right_hash:
        left_hash, right_hash = right_hash, left_hash

    return hashtag(b'TapBranch', left_hash + right_hash)


def make_tweak_pubkey(pubkey_bytes, h0):
    tweak_data = hashtag(b'TapTweak', pubkey_bytes + h0)
    tweak = int.from_bytes(tweak_data, 'big')
    assert tweak < n
    return coincurve.PrivateKey.from_int(tweak).public_key


def make_external_pubkey(pubkey_bytes, T):
    P = lift_x_ok(int.from_bytes(pubkey_bytes, 'big'))
    return coincurve.PublicKey.combine_keys([P, T])

# we define the nums point as
# H(G) -> sha256(uncompressedg)
def nums_point():
    Gx, Gy = coincurve.PrivateKey.from_int(1).public_key.point()
    data = bytes([0x04]) + Gx.to_bytes(32, 'big') + Gy.to_bytes(32, 'big')
    h = sha256(data).digest()
    h_int = int.from_bytes(h, 'big')
    return lift_x_ok(h_int)
