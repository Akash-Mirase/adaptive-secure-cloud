import { bufferToBase64, base64ToBuffer } from './encoding.js';

const RSA_PARAMS = { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };

// Generated ONCE per user, alongside the Master Key, at registration. Needed
// because the owner's Master Key can never be handed to a recipient — the
// only way to let someone else unwrap a copy of a file's FEK is to wrap it
// under something only THEY hold the private half of.
export async function generateSharingKeyPair() {
  return window.crypto.subtle.generateKey(RSA_PARAMS, true, ['wrapKey', 'unwrapKey']);
}

export async function exportPublicKey(publicKey) {
  return bufferToBase64(await window.crypto.subtle.exportKey('spki', publicKey));
}

export async function importPublicKey(base64) {
  return window.crypto.subtle.importKey('spki', base64ToBuffer(base64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']);
}

// Wrapped under the MASTER KEY, not the KEK — so a password change or
// recovery (which only re-wraps the Master Key) never needs to touch this.
export async function wrapPrivateKey(privateKey, masterKey, iv) {
  const wrapped = await window.crypto.subtle.wrapKey('pkcs8', privateKey, masterKey, { name: 'AES-GCM', iv, tagLength: 128 });
  return bufferToBase64(wrapped);
}

export async function unwrapPrivateKey(wrappedBase64, masterKey, ivBase64) {
  try {
    return await window.crypto.subtle.unwrapKey(
      'pkcs8', base64ToBuffer(wrappedBase64), masterKey,
      { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(ivBase64)), tagLength: 128 },
      { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['unwrapKey']
    );
  } catch {
    throw new Error('Could not unlock your sharing key.');
  }
}

// Wraps a FEK under a RECIPIENT's PUBLIC key. RSA-OAEP needs no IV — it is
// not a mode of a block cipher, it's a padding scheme over direct RSA encryption.
export async function wrapFekForRecipient(fek, recipientPublicKey) {
  const wrapped = await window.crypto.subtle.wrapKey('raw', fek, recipientPublicKey, { name: 'RSA-OAEP' });
  return bufferToBase64(wrapped);
}

export async function unwrapFekFromOwner(wrappedFekBase64, myPrivateKey) {
  try {
    return await window.crypto.subtle.unwrapKey(
      'raw', base64ToBuffer(wrappedFekBase64), myPrivateKey,
      { name: 'RSA-OAEP' }, { name: 'AES-GCM', length: 256 }, true, ['decrypt']
    );
  } catch {
    throw new Error('Could not unlock this shared file\'s key.');
  }
}