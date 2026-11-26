<script lang="ts">
  import { onMount } from 'svelte';
  import { api, post } from '#lib/api';

  type Security = {
    operator: { username: string; roles: string[] };
    ca_fingerprint_sha256: string;
    issuer_key_id: string;
    command_verify_key_ed25519_hex: string;
    storage_destructive_enabled: boolean;
    os_install_enabled: boolean;
    session_ttl_seconds: number;
    boot_command_ttl_seconds: number;
    enrollment_ttl_seconds: number;
    uefi_remote_scopes: string[];
    notes: string[];
  };

  let info = $state<Security | null>(null);
  let confirm = $state('');
  let error = $state('');
  let notice = $state('');

  onMount(async () => {
    try {
      info = await api<Security>('/v1/security');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not load security status';
    }
  });

  async function rotate() {
    error = '';
    notice = '';
    try {
      const body = await post<{ note: string }>('/v1/security/rotate-command-key', { confirm });
      notice = body.note;
      info = await api<Security>('/v1/security');
      confirm = '';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Rotation failed';
    }
  }
</script>

<p class="kicker">Boundary</p>
<h1>Security</h1>
{#if error}<p class="error">{error}</p>{/if}
{#if notice}<p>{notice}</p>{/if}
{#if info}
  <section class="panel">
    {#each info.notes as note, index (index)}
      <p>{note}</p>
    {/each}
    <p class="mono faint">CA {info.ca_fingerprint_sha256}</p>
    <p class="mono faint">Command key {info.issuer_key_id}</p>
    <p class="mono faint">{info.command_verify_key_ed25519_hex}</p>
    <p class="muted">
      UEFI will accept signed commands only for {info.uefi_remote_scopes.join(' and ')}. Recovery launch is a separate
      scope and is not delivered on the UEFI boot-policy poll. Destructive storage is
      {info.storage_destructive_enabled ? 'enabled' : 'off'}. OS install is {info.os_install_enabled ? 'enabled' : 'off'}.
    </p>
    <p class="faint">
      Sessions last {info.session_ttl_seconds} seconds. Boot commands last {info.boot_command_ttl_seconds} seconds.
      Enrollment tokens last {info.enrollment_ttl_seconds} seconds.
    </p>
  </section>
  {#if info.operator.roles.includes('admin')}
    <section class="panel">
      <h2>Rotate the command key</h2>
      <p class="muted">Type rotate. Enrolled devices keep the previous verify key and reject new commands until they enroll again.</p>
      <label>
        Confirmation
        <input bind:value={confirm} autocomplete="off" />
      </label>
      <div><button class="ghost" type="button" disabled={confirm !== 'rotate'} onclick={rotate}>Rotate command key</button></div>
    </section>
  {/if}
{/if}
