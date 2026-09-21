# TLS deployment directory

Place development TLS material here only on the deployment host. Certificate and private-key file types in this directory are ignored by Git.

The secure development compose file expects:

- server.crt - PEM server certificate
- server.key - PEM server private key
- optional client-ca.crt - PEM CA bundle when direct mTLS is enabled

Do not commit private keys, enrollment tokens, administrative tokens, token peppers, device credentials, or production certificates to this repository.

For direct mTLS set MIRA_TLS_REQUIRE_CLIENT_CERT=true and set MIRA_TLS_CLIENT_CA_FILE=/run/mira/tls/client-ca.crt before starting the secure development stack.
