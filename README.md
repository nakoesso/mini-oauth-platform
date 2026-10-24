# mini-oauth-platform

Two Spring Boot microservices demonstrating JWT issuance and validation with RSA keys and key rotation via `kid`.

## Structure

- `authorization-server`: issues signed JWTs
- `resource-server`: validates JWTs and protects resources

## RSA keys setup

This application expects RSA key files to be available locally at:

- src/main/resources/keys/private.pem
- src/main/resources/keys/public.pem

These files are ignored by Git and must be generated locally before starting the application.

### Generate RSA keys with OpenSSL

Create the `src/main/resources/keys` directory if it does not already exist, then run:

openssl genpkey -algorithm RSA -out src/main/resources/keys/private.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -pubout -in src/main/resources/keys/private.pem -out src/main/resources/keys/public.pem

### Expected key formats

The application expects:

- a private key in PKCS#8 PEM format (`BEGIN PRIVATE KEY`)
- a public key in X.509 PEM format (`BEGIN PUBLIC KEY`)

### Verify the setup

After generating the keys:

- start the application
- confirm that the application starts successfully
- confirm that no key parsing error is thrown
