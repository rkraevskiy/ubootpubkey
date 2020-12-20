#!/usr/bin/env python


#
# A script to convert RSA pubkey to u-boot dts format.
#
# Copyright (c) 2020, Roman Kraevskiy <rkraevskiy@gmail.com>
# All rights reserved.
#
# This software is dual licensed and available under the MPL-2.0
# or under the GPL-2.0-or-later.
#




"""
A script to convert RSA public key to uboot dts format.
2020 Roman Kraievskyi <rkraevskiy@gmail.com>
"""




from __future__ import print_function

from Crypto.PublicKey import RSA


VERSION = "1.0a"
NAME = "ubpubkey"



def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q,r = b//a,b%a;
        m,n = x-u*q,y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    return b, x, y

# reciprocal 
def inverse(v,mod):
    g,x,y = egcd(v,mod)
    if x<0:
        x+=mod
    return x

def bytelen(x):
    return (x.bit_length() + 7) // 8


def int_to_hex(x,bits):
    h = hex(x)[2:].rstrip('L')
    lreq = ((bits+7)//8)*2

    if len(h)<lreq:
        h = "0"*(lreq-len(h)) + h

    return h

def nsplit(l,size):
    n = max(1, size)
    r = list(l[i:i+n] for i in range(len(l)-n,-n,-n))
    r.reverse()
    return r


def int_to_str(x):
    res = []
    while x > 0:
        res.append(chr(x&0xff))
        x = x>>8
    res.reverse()
    return ''.join(res)

def int_to_hexlist(x,nbits,nbytes):
    h = int_to_hex(x,nbits)
    l = [ "0x"+(i.lstrip('0') if i.lstrip('0') else '00') for i in nsplit(h,nbytes*2)]
    return l

class UbootKeyData:
    def __init__(self,rsakey):
        self.rsa_modulus = rsakey.n
        self.rsa_exponent = rsakey.e
        self.rsa_num_bits = rsakey.n.bit_length()
        self.rsa_r_squared = ((2 ** self.rsa_num_bits) ** 2) % self.rsa_modulus
        mod32 = 2**32
        modmask = mod32-1
        self.rsa_n0_inverse = (mod32 - inverse(self.rsa_modulus&modmask,mod32))%mod32



def uboot_hex(x,nbits,nbytes):
    res = ["<"]
    res.append(" ".join(int_to_hexlist(x,nbits,nbytes)))
    res.append(">")
    return "".join(res)


def get_uboot_properties(keydata):
    res = {}
    res["rsa,modulus"] = uboot_hex(keydata.rsa_modulus,keydata.rsa_num_bits,4)
    res["rsa,exponent"] = uboot_hex(keydata.rsa_exponent,64,4)
    res["rsa,num-bits"] = uboot_hex(keydata.rsa_num_bits,32,4)
    res["rsa,r-squared"] = uboot_hex(keydata.rsa_r_squared,keydata.rsa_r_squared.bit_length(),4)
    res["rsa,n0-inverse"] = uboot_hex(keydata.rsa_n0_inverse,32,4)
    return res


if __name__ == "__main__":
    import time
    import sys
    import datetime
    import ssl
    from Crypto.Util.asn1 import DerSequence
    import hashlib
    import os
    import argparse


    def eprint(*args,**kwargs):
        print(*args, file=sys.stderr, **kwargs)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=__doc__)
    parser.add_argument("infile", type=str, help="the input file")
    parser.add_argument("outfile", type=str, help="the output file",nargs='?')
    parser.add_argument('--version', action='version', version="%s %s"%(NAME,VERSION))
    args = parser.parse_args()

    ifname = args.infile
    try:
        f = open(ifname,"r")
        key_data = f.read()
    except:
        eprint("Failed to open file '%s'"%ifname)
        sys.exit(1)


    ifsrc = os.path.basename(ifname)
    try:
        # try to import as public key
        key = RSA.importKey(key_data)
        src = "pubk"
    except:
        # certificate?
        try:
            der_data = ssl.PEM_cert_to_DER_cert(str(key_data))
            cert = DerSequence()
            cert.decode(der_data)
            tbsCertificate = DerSequence()
            tbsCertificate.decode(cert[0])
            cert = tbsCertificate[6]
            key = RSA.importKey(cert)
            src = "cert"
        except:
            eprint("Failed to import key from '%s'"%ifname)
            sys.exit(1)

    try:
        der_data = key.exportKey('DER')
        x = UbootKeyData(key)
        props = get_uboot_properties(x)

        if args.outfile:
            ofname = args.outfile
            try:
                of = open(ofname,"w")
            except:
                eprint("Failed to open output file '%s'"%ofname);
                sys.exit(1)
        else:
            of = sys.stdout

        for k in sorted(props.keys()):
            v = props[k]
            print("%s = %s;"%(k,v), file=of)
        print('k-gen = "%s/%s/%s";'%(NAME,VERSION,int(time.mktime(datetime.datetime.now().timetuple()))), file=of)

        h = hashlib.sha256()
        h.update(der_data)
        print('k-sha256-fp = "%s";'%(h.hexdigest()[:64]), file=of)
        print('k-src = "%s/%s";'%(src,ifsrc), file=of)
        print("Done")
    except:
        eprint("Failed to generate a public key information")
        sys.exit(1)
    else:
        sys.exit(0)

