use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use portable_pty::{CommandBuilder, PtySize};
use rand::Rng;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write as IoWrite};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info};

const MAX_PACKET: usize = 1200;
const SESSION_TTL: u64 = 300;
const NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Proto {
    AuthReq { rsa_pub: Vec<u8> },
    AuthOk { chacha_key: Vec<u8> },
    AuthFail { reason: String },
    ShellReq { cols: u16, rows: u16 },
    ShellData { data: Vec<u8> },
    ShellResize { cols: u16, rows: u16 },
    ShellClose,
    Ping,
    Pong,
    Error { msg: String },
}

struct Ses {
    cipher: Arc<ChaCha20Poly1305>,
    key: [u8; 32],
    last_seen: Instant,
    shell_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

struct Srv {
    sock: Arc<UdpSocket>,
    sess: Arc<RwLock<HashMap<SocketAddr, Ses>>>,
    rsa_priv: RsaPrivateKey,
}

impl Srv {
    async fn new(bind: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        let mut rng = rand::thread_rng();
        let rsa_priv = RsaPrivateKey::new(&mut rng, 2048)?;
        
        info!("NotAProto server on {}", bind);
        Ok(Self {
            sock,
            sess: Arc::new(RwLock::new(HashMap::new())),
            rsa_priv,
        })
    }

    fn rsa_dec(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.rsa_priv.decrypt(Pkcs1v15Encrypt, data)?)
    }

    fn rsa_enc(&self, data: &[u8], pub_key_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pub_key = RsaPublicKey::from_pkcs1_der(pub_key_bytes)?;
        let mut rng = rand::thread_rng();
        Ok(pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)?)
    }

    fn chacha_enc(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce_bytes: [u8; NONCE_SIZE] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plain).unwrap();
        
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn chacha_dec(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < NONCE_SIZE + 16 {
            return None;
        }
        
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];
        cipher.decrypt(nonce, ciphertext).ok()
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                res = self.sock.recv_from(&mut buf) => {
                    if let Ok((len, addr)) = res {
                        let data = buf[..len].to_vec();
                        let srv = self.clone();
                        tokio::task::spawn_local(async move {
                            if let Err(e) = srv.proc(addr, data).await {
                                error!("Proc error {}: {}", addr, e);
                            }
                        });
                    }
                }
                _ = cleanup.tick() => {
                    self.clean().await;
                }
            }
        }
    }

    async fn proc(&self, addr: SocketAddr, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let ses_exists = {
            let sess = self.sess.read().await;
            sess.contains_key(&addr)
        };

        if ses_exists {
            let key = {
                let sess = self.sess.read().await;
                if let Some(s) = sess.get(&addr) {
                    s.key
                } else {
                    return Ok(());
                }
            };

            if let Some(plain) = Self::chacha_dec(&key, &data) {
                match bincode::deserialize(&plain) {
                    Ok(proto) => {
                        match proto {
                            Proto::ShellReq { cols, rows } => {
                                self.spawn_shell(addr, cols, rows).await?;
                            }
                            Proto::ShellData { data: shell_data } => {
                                self.send_to_shell(addr, shell_data).await?;
                            }
                            Proto::ShellResize { .. } => {
                                // Ресайз не поддерживается в этой версии
                                debug!("Shell resize requested for {}", addr);
                            }
                            Proto::ShellClose => {
                                self.close_shell(addr).await?;
                            }
                            Proto::Ping => {
                                let resp = Proto::Pong;
                                let plain = bincode::serialize(&resp)?;
                                let encrypted = Self::chacha_enc(&key, &plain);
                                self.sock.send_to(&encrypted, addr).await?;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        error!("Deserialize error from {}: {}", addr, e);
                        let resp = Proto::Error { msg: "Invalid proto".to_string() };
                        let plain = bincode::serialize(&resp)?;
                        let encrypted = Self::chacha_enc(&key, &plain);
                        self.sock.send_to(&encrypted, addr).await?;
                    }
                }

                let mut sess = self.sess.write().await;
                if let Some(s) = sess.get_mut(&addr) {
                    s.last_seen = Instant::now();
                }
            }
        } else {
            match self.rsa_dec(&data) {
                Ok(plain) => {
                    match bincode::deserialize(&plain) {
                        Ok(Proto::AuthReq { rsa_pub }) => {
                            let mut rng = rand::thread_rng();
                            let chacha_key: [u8; 32] = rng.gen();
                            let enc_key = self.rsa_enc(&chacha_key, &rsa_pub)?;
                            
                            let cipher = ChaCha20Poly1305::new(&chacha_key.into());
                            
                            let ses = Ses {
                                cipher: Arc::new(cipher),
                                key: chacha_key,
                                last_seen: Instant::now(),
                                shell_tx: None,
                            };
                            
                            self.sess.write().await.insert(addr, ses);
                            
                            let resp = Proto::AuthOk { chacha_key: enc_key };
                            let resp_bytes = bincode::serialize(&resp)?;
                            self.sock.send_to(&resp_bytes, addr).await?;
                            
                            info!("New session from {}", addr);
                        }
                        _ => {
                            let resp = Proto::AuthFail { reason: "Invalid auth".to_string() };
                            let resp_bytes = bincode::serialize(&resp)?;
                            self.sock.send_to(&resp_bytes, addr).await?;
                        }
                    }
                }
                Err(e) => {
                    error!("RSA decrypt error from {}: {}", addr, e);
                    let resp = Proto::AuthFail { reason: format!("Decrypt failed: {}", e) };
                    let resp_bytes = bincode::serialize(&resp)?;
                    self.sock.send_to(&resp_bytes, addr).await?;
                }
            }
        }
        
        Ok(())
    }

    async fn spawn_shell(&self, addr: SocketAddr, cols: u16, rows: u16) -> Result<(), Box<dyn std::error::Error>> {
        let pty_system = portable_pty::native_pty_system();
        let pty_pair = pty_system.openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        
        let shell_cmd = if cfg!(target_os = "windows") {
            "cmd"
        } else {
            &std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        };
        
        let cmd = CommandBuilder::new(shell_cmd);
        let mut child = pty_pair.slave.spawn_command(cmd)?;
        
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let sock = self.sock.clone();
        
        let key = {
            let sess = self.sess.read().await;
            if let Some(s) = sess.get(&addr) {
                s.key
            } else {
                return Err("Session not found".into());
            }
        };
        
        {
            let mut sess = self.sess.write().await;
            if let Some(s) = sess.get_mut(&addr) {
                s.shell_tx = Some(tx);
            }
        }
        
        let mut reader = pty_pair.master.try_clone_reader()?;
        let addr_clone = addr;
        tokio::task::spawn_local(async move {
            let mut buf = [0u8; 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let proto = Proto::ShellData { data: buf[..n].to_vec() };
                        if let Ok(plain) = bincode::serialize(&proto) {
                            let encrypted = Srv::chacha_enc(&key, &plain);
                            let _ = sock.send_to(&encrypted, addr_clone).await;
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        error!("PTY read error for {}: {}", addr_clone, e);
                        break;
                    }
                }
            }
            info!("Shell output closed for {}", addr_clone);
        });
        
        let mut writer = pty_pair.master.take_writer()?;
        let addr_clone2 = addr;
        tokio::task::spawn_local(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = writer.write_all(&data) {
                    error!("PTY write error for {}: {}", addr_clone2, e);
                    break;
                }
                let _ = writer.flush();
            }
        });
        
        tokio::task::spawn_local(async move {
            match child.wait() {
                Ok(status) => info!("Shell exited for {}: {:?}", addr, status),
                Err(e) => error!("Shell wait error for {}: {}", addr, e),
            }
        });
        
        Ok(())
    }

    async fn send_to_shell(&self, addr: SocketAddr, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let sess = self.sess.read().await;
        if let Some(s) = sess.get(&addr) {
            if let Some(tx) = &s.shell_tx {
                let _ = tx.send(data);
            }
        }
        Ok(())
    }

    async fn close_shell(&self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let mut sess = self.sess.write().await;
        if let Some(s) = sess.get_mut(&addr) {
            s.shell_tx = None;
        }
        info!("Shell closed for {}", addr);
        Ok(())
    }

    async fn clean(&self) {
        let now = Instant::now();
        let mut sess = self.sess.write().await;
        let before = sess.len();
        sess.retain(|addr, s| {
            if now.duration_since(s.last_seen).as_secs() > SESSION_TTL {
                info!("Session expired for {}", addr);
                false
            } else {
                true
            }
        });
        if before != sess.len() {
            debug!("Sessions: {} -> {}", before, sess.len());
        }
    }

    fn clone(&self) -> Self {
        Self {
            sock: self.sock.clone(),
            sess: self.sess.clone(),
            rsa_priv: self.rsa_priv.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    let srv = Srv::new("0.0.0.0:2024").await?;
    
    let local = tokio::task::LocalSet::new();
    local.run_until(srv.run()).await?;
    
    Ok(())
}
