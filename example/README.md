# Verifying that everything works for Client Authentication

## Launching a server

First we need to generate a simple, self-signed, server certificate.

```
$ openssl req -x509 -sha256 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 -nodes
```

Then launch the server.

```
$ openssl s_server -accept 12345 -cert server.pem -key server.key -CAfile ca.pem -Verify 1
```

## Launching a client

Use e.g. curl, assuming the client certificates (signed by the CA) is in `vnf.key` and `vnf.pem`.

```
$ curl -v -v -k https://localhost:12345 --key vnf.key --cert vnf.pem
```

You should see how the HTTP headers are being sent, but you will of course don't get any response. On the server side, you will see output similar to

```
ACCEPT
depth=1 CN = OpenSSL CA, O = Example Company, C = SE
verify return:1
depth=0 C = SE, L = Lund, O = Example Company, CN = VNF Application
verify return:1
```

Which tells us that the validation passed. If you get any lines starting with `error` the client certificate was invalid.
