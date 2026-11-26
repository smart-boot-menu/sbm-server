export type Operator = {
  id: string;
  username: string;
  display_name: string;
  roles: string[];
};

export class ApiFailure extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function csrfToken(): string | null {
  const row = document.cookie.split('; ').find((part) => part.startsWith('sbm_csrf='));
  if (!row) return null;
  return decodeURIComponent(row.slice('sbm_csrf='.length));
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has('accept')) headers.set('accept', 'application/json');
  const method = (init.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    const token = csrfToken();
    if (token) headers.set('x-csrf-token', token);
    if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  }
  const response = await fetch(path, { ...init, headers, credentials: 'include' });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = body?.error ?? {};
    throw new ApiFailure(response.status, error.code ?? 'error', error.message ?? response.statusText);
  }
  return body as T;
}

export function post<T>(path: string, payload: unknown): Promise<T> {
  return api<T>(path, { method: 'POST', body: JSON.stringify(payload) });
}
