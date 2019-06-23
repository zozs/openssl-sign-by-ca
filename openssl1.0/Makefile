CC=clang
CFLAGS=-std=c11 -O0 -g -ggdb -Wall -pedantic
LDFLAGS=-O0 -lcrypto -g -ggdb -Wall -pedantic
KEYSTOREPASS=asdf123

all: cert ca.pem

cert: main.o
	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	rm -f cert *.o
	@echo "CA certificate not removed. Issue make caclean if you want this."

caclean:
	rm -f ca.key ca.pem

ca.pem:
ifneq (,$(wildcard ca.pem))
	$(error ca.pem does already exist. Issue make caclean if you want to remove it!)
endif
ifneq (,$(wildcard ca.key))
	$(error ca.key does already exist. Issue make caclean if you want to remove it!)
endif
	openssl req -config openssl.conf -x509 -sha256 -nodes -extensions v3_ca -days 3650 -subj '/CN=OpenSSL CA/O=Example Company/C=SE' -newkey rsa:4096 -keyout ca.key -out ca.pem

keystore.jks: ca.pem
	keytool -import -file ca.pem -alias CA -keystore keystore.jks -noprompt -storepass $(KEYSTOREPASS)
