# Network Security
# Programming Assignment # 2
# Syed Ayaz Mahmud (u1174473)
# April 08, 2020

Must need to install:
$ pip install openssl

The certificates are created by following the instruction on below link:
https://websiteforstudents.com/self-signed-certificates-ubuntu-17-04-17-10/
https://terryoy.github.io/2015/02/create-ssl-ca-root-and-self-sign.html


rootCA
-------
openssl genrsa -out rootCA.key 1024
openssl req -x509 -new -nodes -key rootCA.key -days 3650 -out rootCA.pem

Alice
------
openssl genrsa -out Alice.key 1024
openssl req -new -key Alice.key -out Alice.csr
openssl x509 -req -in Alice.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out Alice.crt -days 365

Bob
----
openssl genrsa -out Bob.key 1024
openssl req -new -key Bob.key -out Bob.csr
openssl x509 -req -in Bob.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out Bob.crt -days 365