use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

struct Link {
    to_browser_tx: UnboundedSender<Vec<u8>>,
    to_browser_rx: Option<UnboundedReceiver<Vec<u8>>>,
    to_device_tx: UnboundedSender<Vec<u8>>,
    to_device_rx: Option<UnboundedReceiver<Vec<u8>>>,
}

pub type PipeEnd = (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>);

#[derive(Clone, Default)]
pub struct Hub {
    inner: Arc<Mutex<HashMap<String, Link>>>,
}

impl Hub {
    pub fn open(&self, id: &str) {
        let (to_browser_tx, to_browser_rx) = mpsc::unbounded_channel();
        let (to_device_tx, to_device_rx) = mpsc::unbounded_channel();
        let mut guard = self.inner.lock().expect("recovery hub");
        guard.insert(
            id.to_string(),
            Link {
                to_browser_tx,
                to_browser_rx: Some(to_browser_rx),
                to_device_tx,
                to_device_rx: Some(to_device_rx),
            },
        );
    }

    pub fn close(&self, id: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(id);
        }
    }

    /// Bytes the device task should write to the browser, and the channel that
    /// receives bytes from the browser.
    pub fn take_device_end(&self, id: &str) -> Option<PipeEnd> {
        let mut guard = self.inner.lock().ok()?;
        let link = guard.get_mut(id)?;
        let rx = link.to_device_rx.take()?;
        Some((link.to_browser_tx.clone(), rx))
    }

    pub fn take_browser_end(&self, id: &str) -> Option<PipeEnd> {
        let mut guard = self.inner.lock().ok()?;
        let link = guard.get_mut(id)?;
        let rx = link.to_browser_rx.take()?;
        Some((link.to_device_tx.clone(), rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_moves_bytes_from_device_to_browser() {
        let hub = Hub::default();
        hub.open("s1");
        let (to_browser, mut device_rx) = hub.take_device_end("s1").expect("device end");
        let (_to_device, mut browser_rx) = hub.take_browser_end("s1").expect("browser end");
        to_browser.send(b"frame".to_vec()).unwrap();
        assert_eq!(browser_rx.try_recv().unwrap(), b"frame");
        assert!(device_rx.try_recv().is_err());
    }
}
