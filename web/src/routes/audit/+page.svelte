<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '#lib/api';

  type Entry = {
    id: number;
    at_unix: number;
    actor_type: string;
    actor_id: string;
    action: string;
    device_id: string | null;
    detail: unknown;
  };

  let entries = $state<Entry[]>([]);
  let error = $state('');

  onMount(async () => {
    try {
      const body = await api<{ entries: Entry[] }>('/v1/audit?limit=80');
      entries = body.entries;
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not read the audit log';
    }
  });
</script>

<p class="kicker">Record</p>
<h1>Audit</h1>
<p class="muted">Rows are insert-only. The database rejects updates and deletes.</p>
{#if error}<p class="error">{error}</p>{/if}
<div class="commands">
  {#each entries as entry (entry.id)}
    <article class="command">
      <div class="split">
        <strong class="mono">{entry.action}</strong>
        <span class="faint">{new Date(entry.at_unix * 1000).toLocaleString()}</span>
      </div>
      <span class="mono faint">{entry.actor_type} {entry.actor_id}{entry.device_id ? ` · ${entry.device_id}` : ''}</span>
    </article>
  {/each}
</div>
