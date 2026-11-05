use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::ssh::ForwardTransport;

use super::RemoteBridge;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardPortRequest {
    pub host: String,
    pub remote_port: u16,
    pub local_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseForwardRequest {
    pub forward_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortForward {
    pub forward_id: String,
    pub host: String,
    pub remote_port: u16,
    pub remote_address: &'static str,
    pub local_port: u16,
    pub listen_address: &'static str,
    pub listen_scope: &'static str,
    pub bridge_host: Option<String>,
    pub state: &'static str,
    /// Starting a listener does not prove the remote application is running.
    pub target_reachable: Option<bool>,
}

struct Entry {
    info: PortForward,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

#[derive(Default)]
pub(super) struct ForwardManager {
    entries: Mutex<BTreeMap<String, Entry>>,
    sequence: AtomicU64,
}

impl ForwardManager {
    pub(super) async fn shutdown(&self) {
        let entries = std::mem::take(&mut *self.entries.lock().expect("forward registry poisoned"));
        for (_, mut entry) in entries {
            entry.cancel.cancel();
            let _ = (&mut entry.task).await;
        }
    }
}

impl RemoteBridge {
    pub async fn forward_port(
        &self,
        request: ForwardPortRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<PortForward> {
        self.runner
            .config()
            .require_discovered_alias(&request.host)?;
        if request.remote_port == 0 || request.local_port == Some(0) {
            return Err(BridgeError::invalid_argument(
                "port must be between 1 and 65535",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, request.local_port.unwrap_or(0)))
            .await
            .map_err(BridgeError::io)?;
        let local_port = listener.local_addr().map_err(BridgeError::io)?.port();
        let transport = self
            .runner
            .prepare_forward_transport(&request.host, &cancel)
            .await?;
        if cancel.is_cancelled() {
            return Err(BridgeError::new(
                ErrorCode::Cancelled,
                "port forwarding cancelled",
                false,
            ));
        }
        let forward_id = format!(
            "forward-{}",
            self.forwards.sequence.fetch_add(1, Ordering::Relaxed) + 1
        );
        let info = PortForward {
            forward_id: forward_id.clone(),
            host: request.host,
            remote_port: request.remote_port,
            remote_address: "127.0.0.1",
            local_port,
            listen_address: "127.0.0.1",
            listen_scope: "bridge_host",
            bridge_host: bridge_hostname(),
            state: "listening",
            target_reachable: None,
        };
        // A finished tools/call must not cancel the long-lived listener. Its
        // own token is cancelled by close, shutdown, or registry destruction.
        let lifetime = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            transport,
            request.remote_port,
            lifetime.clone(),
        ));
        self.forwards
            .entries
            .lock()
            .expect("forward registry poisoned")
            .insert(
                forward_id,
                Entry {
                    info: info.clone(),
                    cancel: lifetime,
                    task,
                },
            );
        Ok(info)
    }

    pub fn list_forwards(&self) -> Vec<PortForward> {
        self.forwards
            .entries
            .lock()
            .expect("forward registry poisoned")
            .values()
            .map(|entry| {
                let mut info = entry.info.clone();
                if entry.task.is_finished() {
                    info.state = "stopped";
                }
                info
            })
            .collect()
    }

    pub async fn close_forward(&self, request: CloseForwardRequest) -> bool {
        let entry = self
            .forwards
            .entries
            .lock()
            .expect("forward registry poisoned")
            .remove(&request.forward_id);
        if let Some(mut entry) = entry {
            entry.cancel.cancel();
            let _ = (&mut entry.task).await;
            true
        } else {
            false
        }
    }
}

async fn serve(
    listener: TcpListener,
    transport: ForwardTransport,
    port: u16,
    cancel: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((socket, _)) = accepted else { break; };
                let Ok(child) = transport.spawn(port) else { continue; };
                connections.spawn(relay(socket, child, cancel.clone()));
            }
        }
    }
    // Close existing browser streams as well as the listener. Joining lets
    // each relay kill and reap its SSH channel process before shutdown returns.
    cancel.cancel();
    while connections.join_next().await.is_some() {}
}

fn bridge_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut name = [0_u8; 256];
        // SAFETY: name is writable for the supplied length; no pointer escapes.
        if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
            return None;
        }
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        Some(String::from_utf8_lossy(&name[..end]).into_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

async fn relay(socket: TcpStream, mut child: tokio::process::Child, cancel: CancellationToken) {
    let mut stdin = child.stdin.take().expect("SSH forwarding stdin piped");
    let mut stdout = child.stdout.take().expect("SSH forwarding stdout piped");
    let (mut reader, mut writer) = socket.into_split();
    let transfer = async {
        tokio::try_join!(
            async {
                copy(&mut reader, &mut stdin).await?;
                stdin.shutdown().await
            },
            async {
                copy(&mut stdout, &mut writer).await?;
                writer.shutdown().await
            },
        )
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => {},
        _ = transfer => {},
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}
