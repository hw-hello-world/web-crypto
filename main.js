const enc = new TextEncoder("utf-8");
const bufferToStr = (cryptoBuffer) => {
  const xs = new Uint8Array(cryptoBuffer);
  return String.fromCharCode.apply(null, xs);
}

const strToIntArrayBuffer = (str) => {
  return new Uint8Array(str.split('').map(c => c.charCodeAt(0)));
}

// create a derived key from master password
const importMasterKey = (masterPassword) => {
  return window.crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
};

// derived an AES-GCM key
const createKeyEncryptionKey = (passwordDerivedKey, salt, usage) => {
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 10000,
      hash: "SHA-256",
    },
    passwordDerivedKey,
    { name: "AES-GCM", length: 256 },
    false,
    usage,
  );
};

/*
type Cache = {
  importMasterKey: String,
  -- salt and iv has be shared in order to derived same key (KEK: key for encrypt/decrypt private key)
  kekSalt: Uint8Array,
  kekIV: Uint8Array,
};
*/

let cache = null;

if (!cache) {
  masterPassword = window.prompt("Enter your password");
  cache = {};
}

importMasterKey(masterPassword)
  .then(function(importMasterKey) {
    cache.importMasterKey = importMasterKey;

    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    cache.kekSalt = salt;

    // 1. generate pub/private pair
    // 2. derived master unlock key (Key encryption key)
    Promise.all([
      window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 1024,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
      ),
      createKeyEncryptionKey(importMasterKey, salt, ["encrypt", "decrypt"]),
    ])
      .then(function(result) {
        const keys = result[0];
        const kek = result[1];
        const pair = {};
        // 3. export public key in JWK format
        return crypto
          .subtle.exportKey("jwk", keys.publicKey)
          .then(function(publicKey) {
            pair.public = publicKey;
            // 4. export public key in JWK format
            return crypto.subtle.exportKey("jwk", keys.privateKey);
          })
          .then(function(privateKeyJwk) {
            const privateKeyJson = JSON.stringify(privateKeyJwk);
            // 5. encrypt private key (JSON.stringified JWK key)
            const iv = window.crypto.getRandomValues(new Uint8Array(16));
            cache.kekIV = iv;
            return window.crypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              kek,
              enc.encode(privateKeyJson),
            );
          })
          .then(function(encryptedPrivateKey) {
            // Suppose to save to DB.
            // But use session storage as temporary storage instead of DB.
            sessionStorage.setItem('my_pub_key', JSON.stringify(pair.public));
            sessionStorage.setItem('my_private_encrypted_key', bufferToStr(encryptedPrivateKey));
          });
      })
      .then(function() {
        var publicKeyJwk = sessionStorage.getItem('my_pub_key');
        if (publicKeyJwk) {
          publicKeyJwk = JSON.parse(publicKeyJwk);
          // 6. import the public
          // mimic the behavior fetch public key from DB and import in client side
          window.crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            {
              name: "RSA-OAEP",
              hash: "SHA-256"
            },
            "false",
            ["encrypt"])
            .then(function(publicKey) {
              // 7. use the public key encrypt App password
              const AppPlainText = "abc--123";
              const iv = window.crypto.getRandomValues(new Uint8Array(16));
              return window.crypto.subtle.encrypt(
                {
                  name: "RSA-OAEP",
                  iv
                },
                publicKey,
                enc.encode(AppPlainText)
              ).then(function(ciphertext) {
                let cipherBuffer = new Uint8Array(ciphertext);
                let cipherStr = String.fromCharCode.apply(null, cipherBuffer);
                console.group('Encryption');
                console.log('public key:', publicKey);
                console.log('cipher text:', ciphertext);
                console.log('plainText:', AppPlainText);
                console.log('encrypted buffer:', cipherBuffer);
                console.log('encrypted string:', cipherStr);
                console.groupEnd();

                // 8. use private key to decrypt the App encrypted password
                // 8.1 fetch encrypted private key
                // 8.2 decrypt it
                // 8.3 import as key
                // 8.4 decrypt App encrypted password

                // 8.1
                var encryptedPrivateKey = sessionStorage.getItem('my_private_encrypted_key');
                return createKeyEncryptionKey(cache.importMasterKey, cache.kekSalt, ["encrypt", "decrypt"])
                  .then(kek => {
                    // 8.2
                    return window.crypto.subtle.decrypt(
                      { name: "AES-GCM", iv: cache.kekIV },
                      kek,
                      strToIntArrayBuffer(encryptedPrivateKey),
                    )
                      .then(myPrivateKeyStr => {
                        // 8.3
                        const myPrivateJwk = JSON.parse(bufferToStr(myPrivateKeyStr));
                        window.crypto.subtle.importKey(
                          'jwk',
                          myPrivateJwk,
                          {
                            name: "RSA-OAEP",
                            hash: "SHA-256"
                          },
                          "false",
                          ["decrypt"])
                          .then(function(privateKey) {
                            let bufferForDecrypt = strToIntArrayBuffer(cipherStr)
                            console.group('Decryption');
                            console.log('buffer for decryption:', bufferForDecrypt);
                            console.log('both buffer shall be equal:', _.isEqual(cipherBuffer, bufferForDecrypt));

                            // 8.4
                            return window.crypto.subtle.decrypt(
                              {
                                name: "RSA-OAEP",
                                // TODO: Turns out IV doesn't have to be same for asymmetric decyption?!?
                                iv: window.crypto.getRandomValues(new Uint8Array(16)),
                              },
                              privateKey,
                              bufferForDecrypt
                            ).then(function(decryptedText) {
                              console.log('plain text:', new TextDecoder().decode(decryptedText))
                              console.groupEnd();
                            });
                          });
                      })

                  })
              })

            })
        }
      })
  });
