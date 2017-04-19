# CA signing using OpenSSL C API

## Generate the initial CA (using openssl command line)

(For reference only; this will be automatically performed when invoking `make`)

```
$ openssl req -config openssl.conf -x509 -sha256 -nodes -extensions v3_ca -days 3650 -subj '/CN=OpenSSL CA/O=Example Company/C=SE' -newkey rsa:4096 -keyout ca.key -out ca.pem
```

## Manually verifying that a certificate is signed by a CA

```
$ openssl verify -CAfile ca.pem cert.crt
cert.crt: OK
```

If an error occurs, expect some other output such as `self signed certificate` etc.

## Manually signing the certificate with the CA key

(For reference only; this is what we'll do with C code instead)

```
$ openssl x509 -req -days 365 -in vnf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out vnf.crt
```

## Converting to Java Key Store-format

(For reference only; some can also be done in the Makefile, but will not be performed automatically)


The following command will import a private/public keypair (in `.p12` PKCS12-format) into a keystore, for example for a server.

```
$ keytool -importkeystore -deststorepass asdf123 -destkeystore keystore.jks -srckeystore nginx.p12 -srcstoretype PKCS12 -srcstorepass asdf123 -alias floodlight
```

The following command will import a CA certificate to a truststore.

```
$ keytool -import -file ca.pem -alias CA -keystore keystore.jks -storepass asdf123
```

This last command can be performed by issuing `make keystore.jks`
