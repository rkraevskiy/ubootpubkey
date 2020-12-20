#!/bin/sh

BASEDIR=$(dirname "$0")

OUTDIR=$BASEDIR/output/dynamic
KEYS=$OUTDIR/keys


rm -r $OUTDIR
mkdir -p $KEYS

echo "=[Generate key info]=================================="
openssl genrsa -out $KEYS/uboot_sign_key.key 4096
openssl req -batch -new -x509 -key $KEYS/uboot_sign_key.key -out $KEYS/uboot_sign_key.crt
$BASEDIR/../../ubpubkey.py $KEYS/uboot_sign_key.crt $OUTDIR/u-boot-pubkey.dtsi
cpp -P -x assembler-with-cpp -I$BASEDIR/uboot -I$OUTDIR -nostdinc -undef -D__DTS__ $BASEDIR/uboot/u-boot.dts  -o $OUTDIR/u-boot.dts

echo "=[Create FIT]========================================="
mkimage -f $BASEDIR/uboot/fitImage.its -r $OUTDIR/fitImage

echo "=[Sign FIT]==========================================="
mkimage -F -k $KEYS/ -r $OUTDIR/fitImage


echo "=[Check FIT]=========================================="
dtc -I dts $OUTDIR/u-boot.dts -O dtb -o $OUTDIR/u-boot.dtb
fit_check_sign -f $OUTDIR/fitImage -k $OUTDIR/u-boot.dtb


