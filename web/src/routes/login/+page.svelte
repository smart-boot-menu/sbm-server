<script lang="ts">
  import { api, post } from '#lib/api';
  import { loginPasskey, registerPasskey } from '#lib/webauthn';

  let secret = $state('');
  let username = $state('');
  let displayName = $state('');
  let error = $state('');
  let busy = $state(false);
  let devBootstrap = $state(false);

  loadMeta();

  async function loadMeta() {
    const meta = await api<{ dev_bootstrap: boolean }>('/v1/meta');
    devBootstrap = meta.dev_bootstrap;
  }

  async function run(action: () => Promise<void>) {
    error = '';
    busy = true;
    try {
      await action();
      window.location.assign('/');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Sign-in failed';
    } finally {
      busy = false;
    }
  }
</script>

<div class="gate">
  <form class="card" onsubmit={(event) => event.preventDefault()}>
    <p class="kicker">Smart Boot Menu</p>
    <h1>Console</h1>
    <p class="muted">
      Passkeys are the operator login. The first registration becomes the admin. A dev bootstrap, when enabled, is a lab
      shortcut and is not a production authenticator.
    </p>

    {#if devBootstrap}
      <label>
        Lab bootstrap secret
        <input type="password" autocomplete="current-password" bind:value={secret} />
      </label>
      <button type="button" disabled={busy || secret.length < 16} onclick={() => run(() => post('/v1/auth/dev-login', { secret }))}>
        Sign in for the lab
      </button>
    {/if}

    <label>
      Username
      <input autocomplete="username" bind:value={username} />
    </label>
    <label>
      Display name
      <input bind:value={displayName} />
    </label>
    <div class="row">
      <button
        type="button"
        disabled={busy || !username || !displayName}
        onclick={() => run(() => registerPasskey(username, displayName))}
      >
        Register passkey
      </button>
      <button class="ghost" type="button" disabled={busy || !username} onclick={() => run(() => loginPasskey(username))}>
        Sign in with passkey
      </button>
    </div>
    {#if error}<p class="error">{error}</p>{/if}
  </form>
</div>
