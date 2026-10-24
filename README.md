# mini-oauth-platform

Two Spring Boot microservices demonstrating JWT issuance and validation with RSA keys and key rotation via `kid`.

## Structure

- `authorization-server`: issues signed JWTs
- `resource-server`: validates JWTs and protects resources
