# Instillation

1. make sure `node >= 12.13.0` and `yarn` is installed.
1. `yarn install`
1. `yarn start`

# Flows

1. Derives KeyEncryptionKey (KEK) from master password
1. Generates RSA public/private pair
1. Generates vault key

## Encryption

1. Encrypt app password using vault key
1. Encrypt vault key using public key
1. Encrypt private key using KEK

## Decryption

1. Derives KeyEncryptionKey (KEK) from master password
1. Decrypt private key
1. Decrypt vault key
1. Decrypt app password

# Notes

1. data size after `RSA-OAEP` encryption is increased a lot.
   - `modulusLength: 1024`
1. what's max input size per RSA key size?
   - 1024 -> 62
   - 2048 -> ??
1. salt for creating derived key must be shared.
1. can IV, which used by AES encryption, be store together with encrypted string?
   - e.g. `encryptePrivateKeyStr = encryptedPrivateKey + IV`
   - e.g. `encrypteVaultItemStr = encryptedVaultItem + IV`

# Reference

1. https://getstream.io/blog/web-crypto-api-chat/
1. https://bradyjoslin.com/blog/encryption-webcrypto/
1. https://mdn.github.io/dom-examples/web-crypto/derive-key/index.html
1. https://mdn.github.io/dom-examples/web-crypto/encrypt-decrypt/index.html
