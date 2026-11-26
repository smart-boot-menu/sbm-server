<script lang="ts">
  import { setContext } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { api, type Operator } from '#lib/api';
  import '../app.css';

  let { children } = $props();
  const session = $state<{ operator: Operator | null }>({ operator: null });
  setContext('session', session);
  let ready = $state(false);

  $effect(() => {
    const path = page.url.pathname;
    if (!ready) return;
    if (!session.operator && path !== '/login') goto('/login');
    if (session.operator && path === '/login') goto('/');
  });

  load();

  async function load() {
    try {
      session.operator = await api<Operator>('/v1/auth/me');
    } catch {
      session.operator = null;
    }
    ready = true;
  }

  async function logout() {
    await api('/v1/auth/logout', { method: 'POST' });
    session.operator = null;
    goto('/login');
  }

  function current(path: string) {
    if (path === '/') return page.url.pathname === '/';
    return page.url.pathname === path || page.url.pathname.startsWith(`${path}/`);
  }
</script>

{#if !ready}
  <p class="boot muted">Opening the console…</p>
{:else if page.url.pathname === '/login'}
  {@render children()}
{:else}
  <div class="shell">
    <aside>
      <div class="mark">
        <strong>SBM</strong>
        <span>Optional console. Local boot does not use this server.</span>
      </div>
      <nav>
        <a href="/" aria-current={current('/') ? 'page' : undefined}>Devices</a>
        <a href="/enroll" aria-current={current('/enroll') ? 'page' : undefined}>Enroll</a>
        <a href="/audit" aria-current={current('/audit') ? 'page' : undefined}>Audit</a>
        <a href="/security" aria-current={current('/security') ? 'page' : undefined}>Security</a>
      </nav>
      <div class="who">
        <span>{session.operator?.display_name}</span>
        <span class="mono">{session.operator?.roles.join(', ')}</span>
        <button class="ghost" type="button" onclick={logout}>Sign out</button>
      </div>
    </aside>
    <main>
      {@render children()}
    </main>
  </div>
{/if}
