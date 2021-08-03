# Instillation

1. make sure `node >= 12.13.0` and `yarn` is installed.
1. `yarn install`
1. `yarn start`

# Notes

1. data size after `RSA-OAEP` encryption is increased a lot.
   - `modulusLength: 1024`
1. what's max input size per RSA key size?
   - 1024 -> 62
   - 2048 -> ??
1. salt and iv for creating derived key must be shared.

# Reference

1. https://getstream.io/blog/web-crypto-api-chat/
1. https://bradyjoslin.com/blog/encryption-webcrypto/
1. https://mdn.github.io/dom-examples/web-crypto/derive-key/index.html
1. https://github.com/hw-hello-world/web-crypto/blob/main/main.js
