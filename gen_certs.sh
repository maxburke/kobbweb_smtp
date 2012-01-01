#!/bin/sh
openssl genrsa -des3 -out kobbweb_smtp.key 1024
openssl req -new -key kobbweb_smtp.key -out kobbweb_smtp.csr
cp kobbweb_smtp.key kobbweb_smtp.key.org
openssl rsa -in kobbweb_smtp.key.org -out kobbweb_smtp.key
openssl x509 -req -days 365 -in kobbweb_smtp.csr -signkey kobbweb_smtp.key -out kobbweb_smtp.crt
