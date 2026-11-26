<script lang="ts">
  import { onMount } from 'svelte';
  import { api, post } from '#lib/api';

  type Issued = {
    id: string;
    token: string;
    expires_at_unix: number;
    ca_fingerprint_sha256: string;
    ca_pem: string;
    server: string;
    shown_once: boolean;
  };
  type Listed = {
    id: string;
    created_at: number;
    expires_at: number;
    used_at: number | null;
    used_by_device: string | null;
    note: string;
  };

  let note = $state('');
  let hostname = $state('lab-vm');
  let issued = $state<Issued | null>(null);
  let tokens = $state<Listed[]>([]);
  let error = $state('');

  onMount(load);

  async function load() {
    try {
      const body = await api<{ tokens: Listed[] }>('/v1/enrollment-tokens');
      tokens = body.tokens;
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not list tokens';
    }
  }

  async function create() {
    error = '';
    try {
      issued = await post<Issued>('/v1/enrollment-tokens', { note });
      await load();
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not create a token';
    }
  }

  const command = $derived(
    issued
      ? `sbm-sim enroll --server ${location.origin} --token ${issued.token} --ca-pem ./ca.cert.pem --fingerprint ${issued.ca_fingerprint_sha256} --hostname ${hostname} --state device.sim.json`
      : ''
  );
</script>

<p class="kicker">Enrollment</p>
<h1>One-time token</h1>
<p class="muted">
  The token is shown once, expires in minutes, and is bound to this server's CA fingerprint. The device keeps its own
  Ed25519 key. The server never learns a MAC address.
</p>
<label>
  Note
  <input bind:value={note} maxlength="200" placeholder="bench vm" />
</label>
<label>
  Hostname the simulator should claim
  <input bind:value={hostname} />
</label>
<div><button type="button" onclick={create}>Create token</button></div>
{#if error}<p class="error">{error}</p>{/if}
{#if issued}
  <section class="panel">
    <h2>Copy this now</h2>
    <p class="mono">Token {issued.token}</p>
    <p class="mono faint">Fingerprint {issued.ca_fingerprint_sha256}</p>
    <p class="faint">Expires {new Date(issued.expires_at_unix * 1000).toLocaleString()}. Public origin on the token is {issued.server}. Enroll against the origin you opened.</p>
    <pre>{command}</pre>
    <pre>{issued.ca_pem}</pre>
  </section>
{/if}
<section class="panel">
  <h2>Earlier tokens</h2>
  {#if tokens.length === 0}
    <p class="muted">None yet. Secrets from earlier tokens are not stored.</p>
  {:else}
    <div class="commands">
      {#each tokens as token (token.id)}
        <article class="command">
          <div class="split">
            <span class="mono">{token.id}</span>
            <span class="pill {token.used_at ? 'executed' : 'requested'}">{token.used_at ? 'used' : 'unused'}</span>
          </div>
          <span class="faint">{token.note || 'No note'} · {token.used_by_device ?? 'not consumed'}</span>
        </article>
      {/each}
    </div>
  {/if}
</section>
