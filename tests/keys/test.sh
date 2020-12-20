#!/bin/sh

BASEDIR=$(dirname "$0")

OUTDIR=$BASEDIR/output/dynamic


mkdir -p $OUTDIR
echo "==[generate]=================================="
python2 $BASEDIR/../../ubpubkey.py $BASEDIR/uboot_public_key.crt $OUTDIR/crt2
python2 $BASEDIR/../../ubpubkey.py $BASEDIR/uboot_public_key.pem $OUTDIR/pem2
python3 $BASEDIR/../../ubpubkey.py $BASEDIR/uboot_public_key.crt $OUTDIR/crt3
python3 $BASEDIR/../../ubpubkey.py $BASEDIR/uboot_public_key.pem $OUTDIR/pem3

echo "==[diff]======================================"
diff $OUTDIR/crt2 $OUTDIR/pem2
diff $OUTDIR/crt3 $OUTDIR/pem3
diff $OUTDIR/crt3 $OUTDIR/crt2

