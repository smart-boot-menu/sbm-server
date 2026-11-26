<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '#lib/api';

  type Device = {
    id: string;
    hostname: string;
    status: string;
    simulated: boolean;
    online: boolean;
    mode: string | null;
    component: string | null;
    software_version: string | null;
  };

  let devices = $state<Device[]>([]);
  let error = $state('');

  onMount(refresh);

  async function refresh() {
    try {
      const body = await api<{ devices: Device[] }>('/v1/devices');
      devices = body.devices;
      error = '';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not load devices';
    }
  }
</script>

<div class="split">
  <div>
    <p class="kicker">Fleet</p>
    <h1>Devices</h1>
  </div>
  <button class="ghost" type="button" onclick={refresh}>Refresh</button>
</div>
<p class="muted">A device appears here after it enrolls with a one-time token. A MAC address is not an identity.</p>
{#if error}<p class="error">{error}</p>{/if}
{#if devices.length === 0}
  <div class="panel">
    <p>No enrolled devices yet.</p>
    <a href="/enroll">Create an enrollment token</a>
  </div>
{:else}
  <div class="devices">
    {#each devices as device (device.id)}
      <a class="device" href={`/devices/${device.id}`}>
        <div class="split">
          <strong>{device.hostname}</strong>
          <span class="pill {device.status}">{device.status}</span>
        </div>
        <span class="muted">
          {device.online ? 'Seen in the last 30 seconds' : 'Not recently seen'}
          {#if device.simulated} · simulator{/if}
          {#if device.mode} · {device.mode}{/if}
        </span>
        <span class="mono faint">{device.id}</span>
      </a>
    {/each}
  </div>
{/if}
