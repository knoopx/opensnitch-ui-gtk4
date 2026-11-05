//! The daemon's peer.
//!
//! opensnitchd dials `Server.Address` and speaks the `UI` service there
//! (daemon/ui/client.go): it hands its ruleset over in `Subscribe()`, keeps a
//! `Notifications` stream open for the rest of the connection, and answers every
//! notification with a `NotificationReply` carrying the id it was given. So a
//! program that listens on that address is the daemon's UI, and rules change
//! through the same channel the GUI uses.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Response, Status, Streaming};

use crate::proto::ui_server::{Ui, UiServer};
use crate::proto::{
    Action, Alert, ClientConfig, Connection, MsgResponse, Notification, NotificationReply,
    NotificationReplyCode, PingReply, PingRequest, Rule, Statistics,
};
use crate::rule;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPORTED: usize = 64;

type Outbox = mpsc::Sender<Result<Notification, Status>>;
type Verdict = Result<String, String>;

/// How the connections the daemon asks about are answered while this program is
/// its peer, and no one is being asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ask {
    /// The daemon's own `DefaultAction`, which it sends in its configuration.
    #[default]
    Daemon,
    Allow,
    Deny,
}

impl Ask {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "daemon" | "default" => Ok(Self::Daemon),
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(format!("-ask takes daemon, allow or deny, not '{other}'")),
        }
    }

    fn action(&self, daemon: &str) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Daemon if daemon == "allow" => "allow",
            Self::Daemon => "deny",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Daemon {
    pub name: String,
    pub version: String,
    /// The `DefaultAction` of the configuration the daemon sent.
    pub default_action: String,
    pub interception: bool,
}

struct Inner {
    rules: Mutex<HashMap<String, Rule>>,
    outbox: Mutex<Option<Outbox>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Verdict>>>,
    next_id: AtomicU64,
    daemon: Mutex<Daemon>,
    stats: Mutex<Option<Statistics>>,
    connected: watch::Sender<bool>,
    asks: AtomicU64,
    ask: Ask,
}

/// One connection with the daemon: cheap to clone, and `UiServer::new` takes one
/// of its own.
#[derive(Clone)]
pub struct Peer {
    inner: Arc<Inner>,
}

impl Peer {
    pub fn new(ask: Ask) -> Self {
        Self {
            inner: Arc::new(Inner {
                rules: Mutex::default(),
                outbox: Mutex::default(),
                pending: Mutex::default(),
                next_id: AtomicU64::default(),
                daemon: Mutex::default(),
                stats: Mutex::default(),
                connected: watch::channel(false).0,
                asks: AtomicU64::default(),
                ask,
            }),
        }
    }

    fn lock<'a, T>(&self, mutex: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The daemon's own words about a rule: what it says when it refuses one.
    fn daemon(&self) -> Daemon {
        self.lock(&self.inner.daemon).clone()
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.lock(&self.inner.rules).values().cloned().collect()
    }

    pub fn rule(&self, name: &str) -> Option<Rule> {
        self.lock(&self.inner.rules).get(name).cloned()
    }

    pub fn connected(&self) -> bool {
        *self.inner.connected.borrow()
    }

    pub fn stats(&self) -> Option<Statistics> {
        self.lock(&self.inner.stats).clone()
    }

    /// Waits for the daemon to dial in and hand its rules over. The daemon
    /// retries its address once a second (daemon/ui/client.go: `poller`), so a
    /// daemon that is running arrives within two seconds.
    pub async fn await_daemon(&self, timeout: Duration) -> Result<Daemon, String> {
        let mut changes = self.inner.connected.subscribe();
        if self.connected() {
            return Ok(self.daemon());
        }
        match tokio::time::timeout(timeout, changes.changed()).await {
            Ok(Ok(())) if *changes.borrow_and_update() => Ok(self.daemon()),
            Ok(_) => Err("the daemon disconnected again".into()),
            Err(_) => Err("the daemon did not connect".into()),
        }
    }

    /// Waits for the first `Ping`, which carries the daemon's statistics.
    pub async fn await_stats(&self, timeout: Duration) -> Result<Statistics, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(stats) = self.stats() {
                return Ok(stats);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the daemon sent no statistics".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn attach(&self, outbox: Outbox) {
        *self.lock(&self.inner.outbox) = Some(outbox);
        self.inner.connected.send_replace(true);
    }

    fn detach(&self, outbox: &Outbox) {
        let mut stream = self.lock(&self.inner.outbox);
        if stream.as_ref().is_some_and(|s| s.same_channel(outbox)) {
            *stream = None;
            self.inner.connected.send_replace(false);
        }
    }

    fn handle_reply(&self, reply: NotificationReply) {
        let Some(waiter) = self.lock(&self.inner.pending).remove(&reply.id) else {
            return;
        };
        let verdict = if reply.code == NotificationReplyCode::Error as i32 {
            Err(reply.data)
        } else {
            Ok(reply.data)
        };
        let _ = waiter.send(verdict);
    }

    /// One notification, and the daemon's answer to it.
    async fn request(&self, build: impl FnOnce(u64) -> Notification) -> Verdict {
        let outbox = self
            .lock(&self.inner.outbox)
            .clone()
            .ok_or("the daemon is not connected")?;
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (waiter, answer) = oneshot::channel();
        self.lock(&self.inner.pending).insert(id, waiter);

        if outbox.try_send(Ok(build(id))).is_err() {
            self.lock(&self.inner.pending).remove(&id);
            return Err("cannot reach the daemon".into());
        }
        let verdict = match tokio::time::timeout(REPLY_TIMEOUT, answer).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) => Err("the daemon disconnected".into()),
            Err(_) => Err("the daemon did not answer".into()),
        };
        self.lock(&self.inner.pending).remove(&id);
        verdict
    }

    fn typed(&self, action: Action, rules: Vec<Rule>) -> impl FnOnce(u64) -> Notification {
        move |id| Notification {
            id,
            r#type: action as i32,
            rules,
            ..Default::default()
        }
    }

    /// Add a rule, or replace the one the daemon has under that name.
    pub async fn save(&self, rule: Rule) -> Verdict {
        self.request(self.typed(Action::ChangeRule, vec![rule.clone()]))
            .await
    }

    /// Turn a rule on or off.
    ///
    /// The whole rule goes, not just its name: opensnitchd reads the rule it is
    /// sent and a missing `operator` leaves it with a nil rule to set
    /// (`handleActionEnableRule` → `rule.Deserialize`), which is a crash.
    pub async fn set_enabled(&self, name: &str, on: bool) -> Verdict {
        let mut rule = self
            .rule(name)
            .ok_or(format!("no rule called {name} on the daemon"))?;
        rule.enabled = on;
        let action = if on {
            Action::EnableRule
        } else {
            Action::DisableRule
        };
        let verdict = self.request(self.typed(action, vec![rule])).await;
        if verdict.is_ok()
            && let Some(known) = self.lock(&self.inner.rules).get_mut(name)
        {
            known.enabled = on;
        }
        verdict
    }

    pub async fn delete(&self, name: &str) -> Verdict {
        let known = self
            .rule(name)
            .ok_or(format!("no rule called {name} on the daemon"))?;
        // opensnitchd deletes by name alone (`handleActionDeleteRule`), so the
        // name is all that has to travel.
        let verdict = self
            .request(move |id| Notification {
                id,
                r#type: Action::DeleteRule as i32,
                rules: vec![Rule {
                    name: known.name,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .await;
        if verdict.is_ok() {
            self.lock(&self.inner.rules).remove(name);
        }
        verdict
    }

    pub async fn set_interception(&self, on: bool) -> Verdict {
        let action = if on {
            Action::EnableInterception
        } else {
            Action::DisableInterception
        };
        self.request(move |id| Notification {
            id,
            r#type: action as i32,
            ..Default::default()
        })
        .await
    }
}

#[tonic::async_trait]
impl Ui for Peer {
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let request = request.into_inner();
        if let Some(stats) = request.stats {
            *self.lock(&self.inner.stats) = Some(stats);
        }
        Ok(Response::new(PingReply { id: request.id }))
    }

    async fn ask_rule(&self, request: Request<Connection>) -> Result<Response<Rule>, Status> {
        let con = request.into_inner();
        let action = self.inner.ask.action(&self.daemon().default_action);
        let asked = self.inner.asks.fetch_add(1, Ordering::Relaxed) + 1;
        let name = format!("cli.{}.{}", asked, rule::now_secs());
        tracing::info!("answered {action} once to {name}: {}", describe(&con));
        eprintln!("asked: {} -> {action} once", describe(&con));
        Ok(Response::new(Rule {
            created: rule::now_secs(),
            name,
            description: "answered by opensnitch-cli".into(),
            enabled: true,
            precedence: false,
            nolog: false,
            action: action.to_string(),
            duration: "once".into(),
            operator: Some(rule::always_operator()),
        }))
    }

    async fn subscribe(
        &self,
        request: Request<ClientConfig>,
    ) -> Result<Response<ClientConfig>, Status> {
        let config = request.into_inner();
        let mut daemon = Daemon {
            name: config.name.clone(),
            version: config.version.clone(),
            ..Default::default()
        };
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&config.config) {
            daemon.default_action = value["DefaultAction"]
                .as_str()
                .unwrap_or("deny")
                .to_string();
            daemon.interception = value["InterceptUnknown"].as_bool().unwrap_or(false);
        }
        tracing::info!(
            "daemon {} {} sent {} rules",
            daemon.name,
            daemon.version,
            config.rules.len()
        );
        *self.lock(&self.inner.daemon) = daemon;
        let mut rules = self.lock(&self.inner.rules);
        rules.clear();
        rules.extend(
            config
                .rules
                .clone()
                .into_iter()
                .map(|rule| (rule.name.clone(), rule)),
        );
        drop(rules);
        // The configuration goes back as it came: this program has no settings of
        // its own to press on the daemon, least of all its default action.
        Ok(Response::new(config))
    }

    type NotificationsStream = Pin<Box<dyn Stream<Item = Result<Notification, Status>> + Send>>;

    async fn notifications(
        &self,
        request: Request<Streaming<NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        let mut replies = request.into_inner();
        let (outbox, stream) = mpsc::channel::<Result<Notification, Status>>(8);
        self.attach(outbox.clone());
        let peer = self.clone();
        tokio::spawn(async move {
            while let Ok(Some(reply)) = replies.message().await {
                peer.handle_reply(reply);
            }
            peer.detach(&outbox);
            tracing::info!("the daemon closed its notification stream");
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(stream))))
    }

    async fn post_alert(&self, request: Request<Alert>) -> Result<Response<MsgResponse>, Status> {
        let alert = request.into_inner();
        tracing::info!("alert {}: {:?}", alert.id, alert.data);
        Ok(Response::new(MsgResponse { id: alert.id }))
    }
}

/// The connection in one line, for the terminal.
fn describe(con: &Connection) -> String {
    // The label is built as a String: the path is a field of the connection and
    // `comm` is computed, so the two arms cannot share a borrow.
    let process = if con.process_path.is_empty() {
        con.process_comm()
    } else {
        con.process_path.clone()
    };
    let host = if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    };
    format!(
        "{process}[{}] {} -> {host}:{} {}",
        con.process_id, con.user_id, con.dst_port, con.protocol
    )
}

impl Connection {
    /// The daemon sends `process_path`, and `comm` only when the path is unknown.
    fn process_comm(&self) -> String {
        if !self.process_args.is_empty() {
            self.process_args[0].clone()
        } else {
            format!("pid {}", self.process_id)
        }
    }
}

/// Who may act as the daemon. A socket at 0600 already admits only its owner and
/// root; this is the same rule read off the connection itself.
pub struct PeerPolicy {
    allowed: Vec<u32>,
    reported: Mutex<HashSet<(u32, Option<i32>)>>,
}

impl PeerPolicy {
    pub fn new(extra: &[u32]) -> Self {
        let mut allowed = vec![0];
        allowed.extend_from_slice(extra);
        Self {
            allowed,
            reported: Mutex::new(HashSet::new()),
        }
    }

    pub fn allows(&self, uid: u32) -> bool {
        self.allowed.contains(&uid)
    }

    pub fn check<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let Some(info) = request.extensions().get::<UdsConnectInfo>() else {
            return Ok(());
        };
        match info.peer_cred {
            Some(cred) if self.allows(cred.uid()) => Ok(()),
            cred => {
                self.report(cred);
                Err(Status::permission_denied(
                    "only the OpenSnitch daemon may use this address",
                ))
            }
        }
    }

    fn report(&self, cred: Option<tokio::net::unix::UCred>) {
        let key = cred.map_or((u32::MAX, None), |c| (c.uid(), c.pid()));
        let first = self
            .reported
            .lock()
            .is_ok_and(|mut seen| seen.len() < MAX_REPORTED && seen.insert(key));
        if first {
            match cred {
                Some(c) => tracing::warn!(
                    "refused a connection from uid {} (pid {:?}): only uid(s) {:?} may act as the daemon",
                    c.uid(),
                    c.pid(),
                    self.allowed
                ),
                None => tracing::warn!("refused a connection whose owner could not be determined"),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Listen {
    Unix(PathBuf),
    Abstract(String),
    Tcp(String),
}

pub fn parse_address(address: &str) -> Listen {
    if let Some(name) = address.strip_prefix("unix-abstract:") {
        Listen::Abstract(name.to_string())
    } else if let Some(name) = address.strip_prefix("unix:@") {
        Listen::Abstract(name.to_string())
    } else if let Some(path) = address
        .strip_prefix("unix://")
        .or_else(|| address.strip_prefix("unix:"))
    {
        Listen::Unix(PathBuf::from(path))
    } else {
        Listen::Tcp(address.to_string())
    }
}

pub fn socket_path(address: &str) -> Option<PathBuf> {
    match parse_address(address) {
        Listen::Unix(path) => Some(path),
        _ => None,
    }
}

/// Why a socket that cannot be replaced is out of reach, in terms of who has to
/// act: the socket is the daemon's address, so the program that holds it has to
/// give it up.
fn socket_taken_error(path: &Path, err: &std::io::Error) -> String {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::symlink_metadata(path).map(|meta| meta.uid()).ok();
    let me = std::fs::metadata("/proc/self").map_or(0, |meta| meta.uid());
    if owner.is_some_and(|uid| uid != me) && err.raw_os_error() == Some(1) {
        return format!(
            "cannot take the socket {}: it belongs to uid {owner:?}, and its directory is \
             sticky, so only its owner, the directory's owner, or root can unlink it. The daemon \
             dials one address at a time: stop the UI that holds it, or listen elsewhere with \
             -addr and point the daemon's Server.Address there",
            path.display()
        );
    }
    format!("cannot replace the socket {}: {err}", path.display())
}

async fn bind_unix(path: &Path) -> Result<UnixListener, BoxError> {
    use tokio::net::UnixStream;
    if UnixStream::connect(path).await.is_ok() {
        return Err(format!(
            "something is already listening on {}: the daemon dials one address, so the \
             opensnitch-ui-gtk4 (or another opensnitch-cli) that holds it has to stop first",
            path.display()
        )
        .into());
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(socket_taken_error(path, &err).into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn bind_abstract(name: &str) -> Result<UnixListener, BoxError> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&addr)?;
    listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(listener)?)
}

/// That the address is held, and who is expected to come to it: the daemon dials
/// its own `Server.Address`, so nothing has to be pointed at this program.
fn listening(address: &str) {
    tracing::info!("listening on {address}; opensnitchd connects to it");
}

/// Serve the `UI` service at the address the daemon dials, until the process
/// stops. The caller runs its command between the daemon's `Subscribe()` and the
/// end of the connection.
pub async fn serve(address: &str, peer: Peer, allowed_uids: &[u32]) -> Result<(), BoxError> {
    let policy = Arc::new(PeerPolicy::new(allowed_uids));
    let guarded = UiServer::with_interceptor(peer, move |request: Request<()>| {
        policy.check(&request)?;
        Ok(request)
    });
    let server = Server::builder().add_service(guarded);
    match parse_address(address) {
        Listen::Unix(path) => {
            let listener = bind_unix(&path).await?;
            listening(address);
            let served = server
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
            if served.is_err() {
                let _ = std::fs::remove_file(&path);
            }
            served?;
        }
        Listen::Abstract(name) => {
            let listener = bind_abstract(&name)?;
            listening(address);
            server
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await?;
        }
        Listen::Tcp(addr) => {
            tracing::warn!(
                "listening on TCP: the processes that connect cannot be identified, so any local process can act as the daemon"
            );
            let addr: SocketAddr = addr.parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            listening(address);
            server
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Operator;

    fn rule(name: &str, enabled: bool) -> Rule {
        Rule {
            name: name.into(),
            enabled,
            duration: "always".into(),
            action: "deny".into(),
            operator: Some(Operator {
                r#type: "simple".into(),
                operand: "process.path".into(),
                data: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn peer() -> Peer {
        Peer::new(Ask::Daemon)
    }

    /// A daemon that answers every notification the way opensnitchd does.
    fn daemon(peer: &Peer, code: NotificationReplyCode) -> mpsc::Receiver<Notification> {
        let (outbox, mut inbox) = mpsc::channel(8);
        peer.attach(outbox);
        let (seen_tx, seen) = mpsc::channel(8);
        let peer = peer.clone();
        tokio::spawn(async move {
            while let Some(Ok(notification)) = inbox.recv().await {
                peer.handle_reply(NotificationReply {
                    id: notification.id,
                    code: code as i32,
                    data: "the rule is bad".into(),
                });
                let _ = seen_tx.send(notification).await;
            }
        });
        seen
    }

    async fn subscribe(peer: &Peer, rules: Vec<Rule>) {
        peer.subscribe(Request::new(ClientConfig {
            name: "opensnitchd".into(),
            version: "1.8.0".into(),
            config: r#"{"DefaultAction":"allow","InterceptUnknown":true}"#.into(),
            rules,
            ..Default::default()
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn subscribe_is_the_ruleset_of_the_running_daemon() {
        let peer = peer();
        subscribe(&peer, vec![rule("a", true), rule("b", false)]).await;
        let daemon = peer.daemon();
        assert_eq!(
            (daemon.name.as_str(), daemon.version.as_str()),
            ("opensnitchd", "1.8.0")
        );
        assert_eq!(daemon.default_action, "allow");
        assert_eq!(peer.rules().len(), 2);
        assert!(!peer.rule("b").unwrap().enabled);
    }

    #[tokio::test]
    async fn the_configuration_goes_back_as_it_came() {
        let peer = peer();
        let reply = peer
            .subscribe(Request::new(ClientConfig {
                config: r#"{"DefaultAction":"allow","LogLevel":5}"#.into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let value: serde_json::Value = serde_json::from_str(&reply.config).unwrap();
        assert_eq!(value["DefaultAction"], "allow");
        assert_eq!(value["LogLevel"], 5);
    }

    #[tokio::test]
    async fn a_ping_keeps_the_statistics() {
        let peer = peer();
        let stats = peer.await_stats(Duration::from_secs(1)).await.unwrap_err();
        assert!(stats.contains("no statistics"), "{stats}");
        peer.ping(Request::new(PingRequest {
            id: 3,
            stats: Some(Statistics {
                daemon_version: "1.8.0".into(),
                rules: 12,
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
        assert_eq!(
            peer.await_stats(Duration::from_secs(1))
                .await
                .unwrap()
                .rules,
            12
        );
    }

    #[tokio::test]
    async fn enabling_sends_the_whole_rule_because_the_daemon_needs_its_operator() {
        let peer = peer();
        subscribe(&peer, vec![rule("a", false)]).await;
        let mut seen = daemon(&peer, NotificationReplyCode::Ok);

        peer.set_enabled("a", true).await.unwrap();
        let sent = seen.recv().await.unwrap();
        assert_eq!(sent.r#type, Action::EnableRule as i32);
        assert_eq!(sent.rules[0].name, "a");
        assert!(sent.rules[0].enabled);
        assert!(sent.rules[0].operator.is_some(), "the operator must travel");
        assert!(peer.rule("a").unwrap().enabled);
    }

    #[tokio::test]
    async fn a_refused_change_leaves_the_rule_as_it_was() {
        let peer = peer();
        subscribe(&peer, vec![rule("a", true)]).await;
        let _seen = daemon(&peer, NotificationReplyCode::Error);

        let err = peer.set_enabled("a", false).await.unwrap_err();
        assert!(err.contains("the rule is bad"), "{err}");
        assert!(peer.rule("a").unwrap().enabled);
        peer.delete("a").await.unwrap_err();
        assert!(peer.rule("a").is_some());
    }

    #[tokio::test]
    async fn a_name_the_daemon_does_not_have_is_reported_without_bothering_it() {
        let peer = peer();
        let (outbox, mut inbox) = mpsc::channel(4);
        peer.attach(outbox);
        assert!(
            peer.set_enabled("gone", true)
                .await
                .unwrap_err()
                .contains("no rule called")
        );
        assert!(
            peer.delete("gone")
                .await
                .unwrap_err()
                .contains("no rule called")
        );
        assert!(inbox.try_recv().is_err(), "nothing was sent");
    }

    #[tokio::test]
    async fn deleting_names_the_rule_and_drops_it_from_the_list() {
        let peer = peer();
        subscribe(&peer, vec![rule("a", true)]).await;
        let mut seen = daemon(&peer, NotificationReplyCode::Ok);
        peer.delete("a").await.unwrap();
        let sent = seen.recv().await.unwrap();
        assert_eq!(sent.r#type, Action::DeleteRule as i32);
        assert_eq!(sent.rules[0].name, "a");
        assert!(peer.rules().is_empty());
    }

    #[tokio::test]
    async fn saving_a_rule_is_change_rule_with_the_rule_itself() {
        let peer = peer();
        let mut seen = daemon(&peer, NotificationReplyCode::Ok);
        peer.save(rule("new", true)).await.unwrap();
        let sent = seen.recv().await.unwrap();
        assert_eq!(sent.r#type, Action::ChangeRule as i32);
        assert_eq!(sent.rules[0].name, "new");
    }

    #[tokio::test]
    async fn interception_is_a_notification_of_its_own() {
        let peer = peer();
        let mut seen = daemon(&peer, NotificationReplyCode::Ok);
        peer.set_interception(false).await.unwrap();
        assert_eq!(
            seen.recv().await.unwrap().r#type,
            Action::DisableInterception as i32
        );
        peer.set_interception(true).await.unwrap();
        assert_eq!(
            seen.recv().await.unwrap().r#type,
            Action::EnableInterception as i32
        );
    }

    #[tokio::test]
    async fn a_daemon_that_never_answers_is_said_so() {
        let peer = peer();
        let (outbox, _inbox) = mpsc::channel(4);
        peer.attach(outbox);
        let verdict = peer.save(rule("a", true)).await;
        assert!(verdict.unwrap_err().contains("did not answer"));
    }

    #[tokio::test]
    async fn the_answer_to_a_connection_is_once_and_the_asked_action() {
        let peer = peer();
        subscribe(&peer, vec![]).await;
        let answer = peer
            .ask_rule(Request::new(Connection {
                process_path: "/usr/bin/curl".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            (answer.action.as_str(), answer.duration.as_str()),
            ("allow", "once")
        );
        assert_eq!(answer.operator.unwrap().operand, "true");
        assert!(answer.name.starts_with("cli."));

        let strict = Peer::new(Ask::Deny);
        subscribe(&strict, vec![]).await;
        let answer = strict
            .ask_rule(Request::new(Connection::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(answer.action, "deny");
    }

    #[test]
    fn the_ask_flag_names_what_it_answers() {
        assert_eq!(Ask::parse("daemon").unwrap(), Ask::Daemon);
        assert_eq!(Ask::parse("allow").unwrap(), Ask::Allow);
        assert_eq!(Ask::parse("deny").unwrap(), Ask::Deny);
        assert!(Ask::parse("maybe").is_err());
        assert_eq!(Ask::Daemon.action("allow"), "allow");
        assert_eq!(Ask::Daemon.action("deny"), "deny");
        assert_eq!(Ask::Daemon.action(""), "deny");
        assert_eq!(Ask::Allow.action("deny"), "allow");
    }

    #[test]
    fn a_connection_is_described_in_one_line() {
        let con = Connection {
            protocol: "tcp".into(),
            process_path: "/usr/bin/curl".into(),
            process_id: 42,
            user_id: 1000,
            dst_host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(
            describe(&con),
            "/usr/bin/curl[42] 1000 -> example.com:443 tcp"
        );
        let bare = Connection {
            process_args: vec!["sh".into()],
            dst_ip: "1.2.3.4".into(),
            ..Default::default()
        };
        assert_eq!(describe(&bare), "sh[0] 0 -> 1.2.3.4:0 ");
    }

    #[test]
    fn addresses_are_the_three_the_daemon_accepts() {
        assert_eq!(
            parse_address("unix:///run/user/1000/osui.sock"),
            Listen::Unix("/run/user/1000/osui.sock".into())
        );
        assert_eq!(parse_address("unix:@osui"), Listen::Abstract("osui".into()));
        assert_eq!(
            parse_address("unix-abstract:osui"),
            Listen::Abstract("osui".into())
        );
        assert_eq!(
            parse_address("127.0.0.1:50051"),
            Listen::Tcp("127.0.0.1:50051".into())
        );
        assert_eq!(
            socket_path("unix:/tmp/osui.sock"),
            Some(PathBuf::from("/tmp/osui.sock"))
        );
        assert_eq!(socket_path("127.0.0.1:1"), None);
    }

    #[test]
    fn only_root_and_the_named_users_may_be_the_daemon() {
        let policy = PeerPolicy::new(&[1000]);
        assert!(policy.allows(0));
        assert!(policy.allows(1000));
        assert!(!policy.allows(1001));
        assert!(PeerPolicy::new(&[]).allows(0));
        assert!(!PeerPolicy::new(&[]).allows(1000));
    }
}
