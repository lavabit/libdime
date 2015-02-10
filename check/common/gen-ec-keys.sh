#!/bin/sh

CURVE_NAME=secp384r1

for i in `seq 1 5`; do
	PRIVKEY=ec-key-$i-priv.pem
	PUBKEY=ec-key-$i-pub.pem
	openssl ecparam -genkey -name $CURVE_NAME -noout -out $PRIVKEY
	openssl ec -in $PRIVKEY -pubout -out $PUBKEY
	
done
