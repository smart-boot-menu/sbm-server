<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { getContext } from 'svelte';
  import { api, post, type Operator } from '#lib/api';
  import { QUEUED, SIM_EXECUTED } from '#lib/copy';

  type Target = { id: string; display_name: string; os_family: string; kind: string; efi_path?: string };
  type Command = {
    command_id: string;
    sequence: number;
    state: string;
    required_scope: string;
    payload: { action?: string; target_id?: string; one_shot?: boolean };
    result_code: string | null;
    result_message: string | null;
  };
  type Detail = {
    device: { id: string; hostname: string; status: string; simulated: boolean; online: boolean; mode: string | null };
    simulated: boolean;
    targets: Target[];
    policy: {
      policy_revision?: number;
      default_target?: string;
      one_shot?: { target_id?: string; consumed?: boolean } | null;
      allow_remote_boot_select?: boolean;
    } | null;
    commands: Command[];
  };

  const session = getContext<{ operator: Operator | null }>('session');
  const admin = $derived(session.operator?.roles.includes('admin') ?? false);
  let detail = $state<Detail | null>(null);
  let error = $state('');
  let notice = $state('');
  let oneShot = $state(true);
  let reason = $state('operator revoked the enrollment');
  let timer = 0;

  const id = $derived(page.params.id ?? '');

  onMount(() => {
    refresh();
    timer = window.setInterval(refresh, 4000);
    return () => window.clearInterval(timer);
  });

  async function refresh() {
    if (!id) return;
    try {
      detail = await api<Detail>(`/v1/devices/${id}`);
      error = '';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Could not load the device';
    }
  }

  async function queue(targetId: string) {
    notice = '';
    error = '';
    try {
      const body = await post<{ state: string; note: string }>(`/v1/devices/${id}/commands`, {
        command: { action: 'boot_target', target_id: targetId, one_shot: oneShot }
      });
      notice = body.note;
      await refresh();
    } catch (err) {
      error = err instanceof Error ? err.message : 'The command was not accepted';
    }
  }

  async function other(action: string) {
    if (!confirm(`Queue ${action}? The device has not rebooted until it reports a result.`)) return;
    try {
      const body = await post<{ note: string }>(`/v1/devices/${id}/commands`, { command: { action } });
      notice = body.note;
      await refresh();
    } catch (err) {
      error = err instanceof Error ? err.message : 'The command was not accepted';
    }
  }

  async function recovery() {
    try {
      const body = await post<{ id: string }>(`/v1/recovery-sessions`, { device_id: id });
      window.location.assign(`/recovery/${body.id}`);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Recovery was not authorized';
    }
  }

  async function revoke() {
    try {
      await post(`/v1/devices/${id}/revoke`, { reason });
      notice = 'Revocation is queued as a signed command. The device is marked revoked.';
      await refresh();
    } catch (err) {
      error = err instanceof Error ? err.message : 'Revoke failed';
    }
  }

  function label(command: Command) {
    const payload = command.payload ?? {};
    if (payload.action === 'boot_target') {
      return `Next boot ${payload.target_id}${payload.one_shot ? ', one shot' : ''}`;
    }
    return payload.action ?? command.required_scope;
  }
</script>

{#if detail}
  <div class="split">
    <div>
      <p class="kicker">{detail.device.online ? 'Recently seen' : 'Quiet'}</p>
      <h1>{detail.device.hostname}</h1>
    </div>
    <span class="pill {detail.device.status}">{detail.device.status}</span>
  </div>
  <p class="mono faint">{detail.device.id}{detail.device.mode ? ` · ${detail.device.mode}` : ''}</p>

  <div class="note">
    <p>{QUEUED}</p>
  </div>
  {#if detail.simulated}
    <div class="note quiet">
      <p>This record is the simulator. {SIM_EXECUTED}</p>
    </div>
  {/if}
  {#if notice}<p>{notice}</p>{/if}
  {#if error}<p class="error">{error}</p>{/if}

  <section class="panel">
    <h2>Reported targets</h2>
    <p class="muted">Choosing a target queues a signed boot selection. It does not reboot anything by itself.</p>
    <label class="check">
      <input type="checkbox" bind:checked={oneShot} />
      One shot. Leave the standing default alone.
    </label>
    {#if detail.targets.length === 0}
      <p class="muted">The device has not reported targets yet.</p>
    {:else}
      <div class="targets">
        {#each detail.targets as target (target.id)}
          <div class="target">
            <div class="split">
              <strong>{target.display_name}</strong>
              <span class="mono faint">{target.os_family} · {target.kind}</span>
            </div>
            <span class="mono faint">{target.id}{target.efi_path ? ` · ${target.efi_path}` : ''}</span>
            <div>
              <button type="button" disabled={detail.device.status !== 'enrolled'} onclick={() => queue(target.id)}>
                Queue next boot
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
    <div class="row">
      <button class="ghost" type="button" onclick={() => other('reboot')}>Queue reboot</button>
      <button class="ghost" type="button" onclick={() => other('shutdown')}>Queue shutdown</button>
      <button class="ghost" type="button" onclick={() => other('reboot_to_firmware_setup')}>Queue firmware setup</button>
      <button class="ghost" type="button" onclick={recovery}>Authorize recovery view</button>
    </div>
  </section>

  <section class="panel">
    <h2>Policy the device last accepted</h2>
    {#if detail.policy}
      <p>Revision {detail.policy.policy_revision}. Remote boot select is {detail.policy.allow_remote_boot_select ? 'allowed' : 'off'}.</p>
      <p class="mono">
        One shot: {detail.policy.one_shot?.target_id ?? 'none'}
        {detail.policy.one_shot?.consumed ? '(consumed)' : ''}
        · Default: {detail.policy.default_target ?? 'none'}
      </p>
      <p class="faint">Unsigned policy is advisory. Only a signed command changes the next boot.</p>
    {:else}
      <p class="muted">No policy stored yet.</p>
    {/if}
  </section>

  <section class="panel">
    <h2>Command history</h2>
    <p class="muted">Requested means queued. Executed means the device reported a result. Those are different states.</p>
    {#if detail.commands.length === 0}
      <p class="muted">No commands yet.</p>
    {:else}
      <div class="commands">
        {#each detail.commands as command (command.command_id)}
          <article class="command">
            <div class="split">
              <strong>{label(command)}</strong>
              <span class="pill {command.state}">{command.state}</span>
            </div>
            <span class="mono faint">#{command.sequence} · {command.required_scope} · {command.command_id}</span>
            {#if command.state === 'requested' || command.state === 'delivered'}
              <span>{QUEUED}</span>
            {/if}
            {#if command.result_message}<span>{command.result_message}</span>{/if}
          </article>
        {/each}
      </div>
    {/if}
  </section>

  {#if admin && detail.device.status === 'enrolled'}
    <section class="panel">
      <h2>Revoke</h2>
      <label>
        Reason
        <input bind:value={reason} />
      </label>
      <div><button class="ghost" type="button" onclick={revoke}>Revoke enrollment</button></div>
    </section>
  {/if}
{:else if error}
  <p class="error">{error}</p>
{:else}
  <p class="muted">Loading the device…</p>
{/if}
