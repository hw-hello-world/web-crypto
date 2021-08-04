const enc = new TextEncoder("utf-8");

const bufferToBase64 = (cryptoBuffer) => {
  const str = bufferToStr(cryptoBuffer);
  return btoa(str);
}
const base64ToBuffer = (base64Str) => {
  const str = atob(base64Str);
  return strToBuffer(str);

}
const bufferToStr = (cryptoBuffer) => {
  const xs = new Uint8Array(cryptoBuffer);
  const ys = String.fromCharCode.apply(null, xs);

  return ys;
}

const strToBuffer = (str) => {
  const xs = new Uint8Array(str.split('').map(c => c.charCodeAt(0)));
  return xs;
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

const rsaAlg = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  // TODO: what is `publicExponent`
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256"
};

const getRandomInt = function(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const getRandStr = () => {
  const i = getRandomInt(33, 122);
  return String.fromCharCode(i);
};


/*
-- salt and iv has to be shared in order to derived same key (KEK: key for encrypt/decrypt private key)
type Cache = {
  // salt for creating master unlock key
  kekSalt: Uint8Array,
  // IV for encrypt private key using MUK
  kekIV: Uint8Array,
  // IV for encrypt vault items
  vaultIV: Uint8Array
};
*/

const cache = {};
const dbSession = {};

const encrypt = () => {
  document.getElementById('assertion').textContent = '';
  document.getElementById('app_encrypted_password').textContent = '';
  document.getElementById('app_decrypted_password').textContent = '';
  document.getElementById('app_decrypted_password').removeAttribute('class');
  const masterPassword = document.getElementById('master_key').value;

  importMasterKey(masterPassword)
    .then(function(derivedMasterKey) {

      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      cache.kekSalt = salt;

      // NOTE: dont need to generate pub/private key and vault key when exists already.
      // but for demo purpose and simplicity, let's generate every time doing encryption.
      //
      Promise.all([
        // 1. generate pub/private pair
        window.crypto.subtle.generateKey(
          rsaAlg,
          true,
          ["encrypt", "decrypt"]
        ),
        window.crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        ),
        // 2. derived master unlock key (Key encryption key)
        createKeyEncryptionKey(derivedMasterKey, salt, ["encrypt", "decrypt"]),
      ])
        .then(function(result) {
          const rsaKeys = result[0];
          const vaultKey = result[1];
          const kek = result[2];
          dbSession.vaultKey = vaultKey;

          // 3. export public key in JWK format
          return crypto
            .subtle.exportKey("jwk", rsaKeys.publicKey)
            .then(function(publicKeyJwk) {
              dbSession.publicKeyJwk = publicKeyJwk;
            })
            .then(function() {
              // 4. export private key in JWK format
              return crypto.subtle.exportKey("jwk", rsaKeys.privateKey)
                .then(function(privateKeyJwk) {
                  dbSession.privateKeyJwk = privateKeyJwk;
                });
            })
            .then(function() {
              // 5. encrypt private key (JSON.stringified JWK key)
              const privateKeyJson = JSON.stringify(dbSession.privateKeyJwk);
              const iv = window.crypto.getRandomValues(new Uint8Array(12));
              cache.kekIV = iv;
              return window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                kek,
                enc.encode(privateKeyJson),
              )
                .then(function(encryptedPrivateKey) {
                  dbSession.encryptedPrivateKey = encryptedPrivateKey;
                })
            })
            .then(function() {
              // 6. export vault key in JWK format
              return crypto.subtle.exportKey("jwk", vaultKey)
            })
            .then(function(vaultKeyJwk) {
              dbSession.vaultKeyJwk = vaultKeyJwk;
              const vaultKeyJson = JSON.stringify(vaultKeyJwk);
              return window.crypto.subtle.importKey(
                'jwk',
                dbSession.publicKeyJwk,
                rsaAlg,
                "false",
                ["encrypt"])
                .then(function(publicKey) {
                  return window.crypto.subtle.encrypt(
                    rsaAlg,
                    publicKey,
                    enc.encode(vaultKeyJson),
                  )
                })
            })
            .then(function(encryptedVaultKey) {
              dbSession.encryptedVaultKey = encryptedVaultKey;
            })
            .then(function() {
              // Suppose to save to DB.
              // But use session storage as temporary storage instead of DB.
              sessionStorage.setItem('my_pub_key', JSON.stringify(dbSession.publicKeyJwk));
              sessionStorage.setItem('my_private_encrypted_key', bufferToBase64(dbSession.encryptedPrivateKey));
              sessionStorage.setItem('my_vault_encrypted_key', bufferToBase64(dbSession.encryptedVaultKey));
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
              rsaAlg,
              "false",
              ["encrypt"])
              .then(function(publicKey) {
                // 7. use the public key encrypt App password
                const appPassword = document.getElementById('app_password').value;

                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                cache.vaultIv = iv;
                return window.crypto.subtle.encrypt(
                  { name: "AES-GCM", iv, },
                  dbSession.vaultKey,
                  enc.encode(appPassword)
                ).then(function(ciphertext) {
                  let cipherBuffer = new Uint8Array(ciphertext);
                  let cipherStrBase64 = bufferToBase64(cipherBuffer);
                  console.group('Encryption');
                  console.log('public key:', publicKey);
                  console.log('plainText:', appPassword);
                  console.log('plainText length:', appPassword.length);
                  console.log('encrypted buffer size:', cipherBuffer.byteLength);
                  console.log('encrypted string:', bufferToStr(cipherBuffer));
                  console.log('encrypted string size:', bufferToStr(cipherBuffer).length);
                  console.log('encrypted base64 string:', cipherStrBase64);
                  console.log('encrypted base64 string size:', cipherStrBase64.length);
                  console.groupEnd();

                  document.getElementById('app_encrypted_password').textContent = cipherStrBase64;

                });
              });
          }
        });
    });
};

const decrypt = () => {
  document.getElementById('assertion').textContent = '';
  document.getElementById('app_decrypted_password').textContent = '';
  document.getElementById('app_decrypted_password').removeAttribute('class');

  const cipherStr = document.getElementById('app_encrypted_password').textContent;
  const masterPassword = document.getElementById('master_key').value;
  const encryptedPrivateKey = sessionStorage.getItem('my_private_encrypted_key');

  importMasterKey(masterPassword)
    .then(function(derivedMasterKey) {
      return createKeyEncryptionKey(derivedMasterKey, cache.kekSalt, ["encrypt", "decrypt"])
        .then(function(kek) {
          return window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: cache.kekIV },
            kek,
            base64ToBuffer(encryptedPrivateKey),
          )
        })
        .then(myPrivateKeyStr => {
          // 8.3
          const myPrivateJwk = JSON.parse(bufferToStr(myPrivateKeyStr));
          return window.crypto.subtle.importKey(
            'jwk',
            myPrivateJwk,
            rsaAlg,
            "false",
            ["decrypt"])
        })
        .then(function(privateKey) {
          const encryptedVaultKey = sessionStorage.getItem('my_vault_encrypted_key');
          return window.crypto.subtle.decrypt(
            rsaAlg,
            privateKey,
            base64ToBuffer(encryptedVaultKey),
          )
        })
        .then(function(vaultKeyJwkStr) {
          const vaultKeyJwk = JSON.parse(bufferToStr(vaultKeyJwkStr));
          return window.crypto.subtle.importKey(
            'jwk',
            vaultKeyJwk,
            { name: 'AES-GCM' },
            "false",
            ["decrypt"])
        })
        .then(function(vaultKey) {
          let bufferForDecrypt = base64ToBuffer(cipherStr)
          console.group('Decryption');
          console.log('buffer for decryption:', bufferForDecrypt);

          // 8.4
          return window.crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: cache.vaultIv,
            },
            vaultKey,
            bufferForDecrypt
          )
        })
        .then(function(decryptedBuffer) {
          const decryptedStr = bufferToStr(decryptedBuffer);
          console.log('plain text:', decryptedStr);
          console.groupEnd();
          document.getElementById('app_decrypted_password').textContent = decryptedStr;
          const originalPassword = document.getElementById('app_password').value;
          document.getElementById('assertion').textContent = decryptedStr === originalPassword;
        })
    });
};

document.getElementById('encrypt').onclick = encrypt;
document.getElementById('decrypt').onclick = decrypt;
document.getElementById('password_range').onchange = (e) => {
  var result = '';
  for (var i = 1; i <= e.target.value; i++) {
    result += getRandStr();
  }
  document.getElementById('app_password').value = result;
}
