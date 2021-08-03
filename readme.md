# Notes

1. data size after `RSA-OAEP` encryption is increased a lot.
   - `modulusLength: 1024`
1. what's max input size per RSA key size?
   - 1024 -> 62
   - 2048 -> ??
1. salt and iv for creating derived key must be shared.

# Reference

1. https://getstream.io/blog/web-crypto-api-chat/
2. https://mdn.github.io/dom-examples/web-crypto/derive-key/index.html
3. https://github.com/hw-hello-world/web-crypto/blob/main/main.js
