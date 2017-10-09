openssl genrsa 2048 > server.key # private key
openssl req -new -key server.key > server.csr # certificate signing request 
openssl x509 -days 365000 -req -signkey server.key < server.csr > oreore.crt # oreore certificate