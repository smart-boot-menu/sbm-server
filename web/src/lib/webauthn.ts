function bytesToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): ArrayBuffer {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

function prepare(options: { publicKey: Record<string, unknown> }, kind: 'create' | 'get') {
  const publicKey = options.publicKey;
  publicKey.challenge = base64UrlToBytes(String(publicKey.challenge));
  if (kind === 'create') {
    const user = publicKey.user as { id: string };
    user.id = base64UrlToBytes(user.id) as unknown as string;
    const excluded = publicKey.excludeCredentials as { id: string }[] | undefined;
    if (excluded) {
      for (const credential of excluded) credential.id = base64UrlToBytes(credential.id) as unknown as string;
    }
  } else {
    const allowed = publicKey.allowCredentials as { id: string }[] | undefined;
    if (allowed) {
      for (const credential of allowed) credential.id = base64UrlToBytes(credential.id) as unknown as string;
    }
  }
  return options;
}

function credentialJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  if ('attestationObject' in response) {
    return {
      id: credential.id,
      rawId: bytesToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bytesToBase64Url(response.attestationObject),
        clientDataJSON: bytesToBase64Url(response.clientDataJSON),
        transports: response.getTransports?.()
      },
      extensions: credential.getClientExtensionResults()
    };
  }
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null
    },
    extensions: credential.getClientExtensionResults()
  };
}

export async function registerPasskey(username: string, displayName: string) {
  const options = await request('/v1/auth/passkey/register/options', { username, display_name: displayName });
  const credential = (await navigator.credentials.create(
    prepare(options, 'create') as CredentialCreationOptions
  )) as PublicKeyCredential | null;
  if (!credential) throw new Error('The authenticator did not return a passkey');
  await request('/v1/auth/passkey/register/finish', { credential: credentialJson(credential) });
}

export async function loginPasskey(username: string) {
  const options = await request('/v1/auth/passkey/login/options', { username });
  const credential = (await navigator.credentials.get(
    prepare(options, 'get') as CredentialRequestOptions
  )) as PublicKeyCredential | null;
  if (!credential) throw new Error('The authenticator did not return a passkey');
  await request('/v1/auth/passkey/login/finish', { credential: credentialJson(credential) });
}

async function request(path: string, payload: unknown) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(body?.error?.message ?? 'Passkey request failed');
  }
  return body;
}
