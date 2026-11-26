<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import { api, post } from '#lib/api';
  import '@xterm/xterm/css/xterm.css';

  type Status = { id: string; device_id: string; state: string; expires_at: number };

  let status = $state<Status | null>(null);
  let error = $state('');
  let vncHost: HTMLDivElement | undefined = $state();
  let termHost: HTMLDivElement | undefined = $state();

  const id = $derived(page.params.id ?? '');

  onMount(() => {
    let rfb: { disconnect: () => void } | null = null;
    let term: { dispose: () => void } | null = null;
    let socket: WebSocket | null = null;
    let stopped = false;

    (async () => {
      try {
        status = await api<Status>(`/v1/recovery-sessions/${id}`);
      } catch (err) {
        error = err instanceof Error ? err.message : 'Recovery session was not found';
        return;
      }
      if (stopped || !vncHost || !termHost) return;
      const RFB = (await import('@novnc/novnc')).default;
      const { Terminal } = await import('@xterm/xterm');
      const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
      rfb = new RFB(vncHost, `${scheme}//${location.host}/v1/recovery-sessions/${id}/vnc`, { shared: false });
      rfb.scaleViewport = true;
      term = new Terminal({
        fontFamily: 'IBM Plex Mono, ui-monospace, monospace',
        fontSize: 14,
        theme: { background: '#161311', foreground: '#f4efe6', cursor: '#d7b36a' }
      });
      term.open(termHost);
      socket = new WebSocket(`${scheme}//${location.host}/v1/recovery-sessions/${id}/terminal`);
      socket.binaryType = 'arraybuffer';
      socket.onmessage = (event) => {
        const text = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
        term?.write(text);
      };
      term.onData((data) => {
        if (socket?.readyState === WebSocket.OPEN) socket.send(data);
      });
    })();

    return () => {
      stopped = true;
      rfb?.disconnect();
      socket?.close();
      term?.dispose();
    };
  });

  async function closeSession() {
    await post(`/v1/recovery-sessions/${id}/close`, {});
    window.location.assign(status ? `/devices/${status.device_id}` : '/');
  }
</script>

<p class="kicker">Recovery</p>
<h1>Remote view</h1>
<p class="note">
  This is not a public VNC port. The browser attaches to a session the device dials. A simulator picture is not a
  hardware desktop, and the text pane is not a real PTY.
</p>
{#if status}
  <p class="mono faint">Session {status.id} · {status.state} · device {status.device_id}</p>
{/if}
{#if error}<p class="error">{error}</p>{/if}
<section class="panel">
  <h2>Framebuffer</h2>
  <div class="screen" bind:this={vncHost}></div>
</section>
<section class="panel">
  <h2>Text</h2>
  <div class="term" bind:this={termHost}></div>
</section>
<div><button class="ghost" type="button" onclick={closeSession}>Close session</button></div>
