# CA signing using OpenSSL C API

This example code demonstrates how to use the OpenSSL C API to perform
the actions by a CA. In short, it does the following:

1. First it generates (using the `openssl` command-line application) a CA
   certificate, and stores the certificate and key in `ca.pem` and `ca.key`
   respectively. This is done in the `Makefile`, if you want to see the
   used commands.
2. Then, in the actual C program in `main.c`, the OpenSSL C API is used to:
   - Generate a private RSA key.
   - Generate a certificate request.
   - Sign this certificate request using the CA certificate.
   - Generate and output the final (signed) certificate.
3. The program will then output (to stdout) the generated private key and
   signed certificate in PEM format.

## How-to

1. Depending on your OpenSSL version, `cd` into either `openssl1.0` or `openssl1.1`
2. Run `make` which will generate a new CA, and compile the application.
3. Run `./cert ca.key ca.pem` which will generate a certificate signed by the CA.
4. (Optional). Run `make clean` to remove compiled applications.
5. (Optional). Run `make caclean` to remove the generated CA certificate and key.

## License

```
Copyright (c) 2017, 2018, 2019 Linus Karlsson

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

## Reference

This contains various notes of related actions which may be of interest, but
is not required to run the application.

### Generate the initial CA (using openssl command line)

For reference only; this will be automatically performed when invoking `make`.

```
$ openssl req -config openssl.conf -x509 -sha256 -nodes -extensions v3_ca -days 3650 -subj '/CN=OpenSSL CA/O=Example Company/C=SE' -newkey rsa:4096 -keyout ca.key -out ca.pem
```

## Manually verifying that a certificate is signed by a CA

For reference only; if you want to check that the generated certificate is indeed
signed by the CA. You must first place the certificate output of `./cert` into
`cert.crt`.

```
$ openssl verify -CAfile ca.pem cert.crt
cert.crt: OK
```

If an error occurs, expect some other output such as `self signed certificate` etc.

## Manually signing the certificate with the CA key

For reference only; this is what we'll do with C code instead.

```
$ openssl x509 -req -days 365 -in vnf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out vnf.crt
```

## Converting to Java Key Store-format

For reference only; some can also be done in the Makefile, but will not be performed automatically.

The following command will import a private/public keypair (in `.p12` PKCS12-format) into a keystore, for example for a server.

```
$ keytool -importkeystore -deststorepass asdf123 -destkeystore keystore.jks -srckeystore cert.p12 -srcstoretype PKCS12 -srcstorepass asdf123 -alias server
```

The following command will import a CA certificate to a truststore.

```
$ keytool -import -file ca.pem -alias CA -keystore keystore.jks -storepass asdf123
```

This last command can be performed by issuing `make keystore.jks`
