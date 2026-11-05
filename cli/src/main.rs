//! opensnitch-cli - the rules of a running OpenSnitch daemon, from a terminal.
//!
//! opensnitchd dials the address of its own `Server` and speaks the `UI` service
//! there (daemon/ui/client.go), and hosts no gRPC server of its own: this program
//! listens, and the daemon connects to it. Its rules arrive in `Subscribe()`, and
//! every change goes back out over the daemon's `Notifications` channel. The
//! daemon retries that address once a second, so a daemon that is running arrives
//! within two of binding the address.
//!
//! Nothing here comes from the GTK UI: no gtk, no libadwaita, no D-Bus.

mod peer;
mod rule;

#[allow(clippy::excessive_nesting, clippy::too_many_lines)]
pub mod proto {
    tonic::include_proto!("protocol");
}

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::peer::{Ask, BoxError, Daemon, Peer};
use crate::proto::{Rule, Statistics};

const DEFAULT_ADDRESS: &str = "unix:///tmp/osui.sock";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
const ADDRESS_ENV: &str = "OPENSNITCH_ADDRESS";

/// How long the socket is waited for. Binding is local work that takes
/// milliseconds; anything past this is a directory that does not exist, an
/// address that cannot be parsed, or another peer that holds the socket.
const BIND_DEADLINE: Duration = Duration::from_secs(5);

const USAGE: &str = "\
opensnitch-cli - the rules of a running OpenSnitch daemon

opensnitchd dials the address of its own `Server` and speaks the UI service
there, so this program listens and the daemon connects to it. It retries that
address once a second. Only one peer is served at a time, so opensnitch-ui-gtk4
(or the Qt UI) has to be stopped first.

USAGE: opensnitch-cli [OPTIONS] <COMMAND>

COMMANDS:
    rules -list | list            Every rule of the running daemon, as a table
    rules -show NAME | show NAME  One rule, as the JSON opensnitchd keeps on disk
    rules -add FILE | add FILE    Add the rules of a JSON file ('-' reads stdin)
    rules -enable NAME...         Turn rules on
    rules -disable NAME...        Turn rules off
    rules -del NAME...            Delete rules
    status                        The daemon, its rules, and its statistics
    pause                         Stop intercepting: the default action decides
    resume                        Intercept again

OPTIONS:
    -addr, --addr <ADDRESS>       Address to listen on: unix:///path, unix:path,
                                  unix-abstract:name, unix:@name, host:port.
                                  Default: $OPENSNITCH_ADDRESS, else unix:///tmp/osui.sock.
                                  This has to be the daemon's `Server.Address`: the daemon
                                  dials that address of its own, so -addr somewhere else
                                  leaves it dialing where it already points.
    -json                         Machine-readable JSON
    -quiet                        Names only
    -filter <TEXT>                Only the rules whose name, description, action,
                                  duration or condition hold TEXT
    -all                          Every rule, ignoring -filter
    -enabled, -disabled           Only the rules that are on, or off (with -list)
    -ask daemon|allow|deny        How to answer the connections the daemon asks
                                  about while this program is its peer. Default
                                  'daemon': the daemon's own DefaultAction.
    -allow-uid <UID>              Let this user, besides root, act as the daemon
                                  (repeatable; needed when opensnitchd does not run
                                  as root)
    -timeout <SECONDS>            How long to wait for the daemon to dial in, for
                                  its statistics, and for it to answer a change
                                  (default: 20)
    -h, --help                    Show this help

An added rule is saved to the daemon's rules directory only when its duration is
\"always\"; the rest live until they expire. actions: {ACTIONS}. durations:
{DURATIONS}. condition fields: {OPERANDS}.";

#[derive(Debug, Default)]
struct Args {
    address: Option<String>,
    json: bool,
    quiet: bool,
    all: bool,
    filter: Option<String>,
    enabled: Option<bool>,
    ask: Ask,
    allow_uids: Vec<u32>,
    timeout: Option<Duration>,
    verb: Option<Verb>,
    names: Vec<String>,
}

impl Args {
    fn timeout(&self) -> Duration {
        self.timeout.unwrap_or(DEFAULT_TIMEOUT)
    }

    fn command(&self) -> Result<Command, String> {
        let verb = self
            .verb
            .ok_or("no command: try `rules -list`, `status` or `rules -add FILE`")?;
        let names = self.names.as_slice();
        Ok(match verb {
            Verb::List => {
                no_names("-list", names)?;
                Command::List(self.enabled)
            }
            Verb::Show => Command::Show(exactly_one("-show", names)?),
            Verb::Add => Command::Add(PathBuf::from(exactly_one("-add", names)?)),
            Verb::Enable => Command::Enable(at_least_one("-enable", names)?),
            Verb::Disable => Command::Disable(at_least_one("-disable", names)?),
            Verb::Del => Command::Delete(at_least_one("-del", names)?),
            Verb::Status => {
                no_names("status", names)?;
                Command::Status
            }
            Verb::Pause => {
                no_names("pause", names)?;
                Command::Interception(false)
            }
            Verb::Resume => {
                no_names("resume", names)?;
                Command::Interception(true)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verb {
    List,
    Show,
    Add,
    Enable,
    Disable,
    Del,
    Status,
    Pause,
    Resume,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    List(Option<bool>),
    Show(String),
    Add(PathBuf),
    Enable(Vec<String>),
    Disable(Vec<String>),
    Delete(Vec<String>),
    Status,
    /// Turn interception off, then on.
    Interception(bool),
}

/// The noun the upstream program puts in front of its verbs: `rules -list`.
const NOUNS: [&str; 2] = ["rules", "rule"];

/// The words that say what to do; the terse spellings drop the leading dash.
fn verb_of(word: &str) -> Option<Verb> {
    match word {
        "-list" | "ls" | "list" => Some(Verb::List),
        "-show" | "show" => Some(Verb::Show),
        "-add" | "add" => Some(Verb::Add),
        "-enable" | "enable" => Some(Verb::Enable),
        "-disable" | "disable" => Some(Verb::Disable),
        "-del" | "del" | "delete" => Some(Verb::Del),
        "status" => Some(Verb::Status),
        "pause" => Some(Verb::Pause),
        "resume" => Some(Verb::Resume),
        _ => None,
    }
}

fn parse_args(mut args: impl Iterator<Item = String> + Unpin) -> Result<Option<Args>, String> {
    let mut out = Args::default();
    while let Some(arg) = args.next() {
        if matches!(arg.as_str(), "-h" | "-help" | "--help") {
            return Ok(None);
        }
        if NOUNS.contains(&arg.as_str()) {
            continue;
        }
        if let Some(verb) = verb_of(&arg) {
            out.verb = Some(verb);
            // `-show NAME` and `-add FILE` read their name here; the terse
            // spellings leave it to follow, where any bare word is a name.
            if matches!(verb, Verb::Show | Verb::Add) && arg.starts_with('-') {
                out.names.push(next(&mut args, &arg)?);
            }
            continue;
        }
        if is_flag(&mut out, &arg, &mut args)? {
            continue;
        }
        if arg.starts_with('-') {
            return Err(format!("unknown argument '{arg}'"));
        }
        out.names.push(arg);
    }
    Ok(Some(out))
}

/// One flag of `OPTIONS`, answered with whether the word was one at all.
fn is_flag(
    out: &mut Args,
    name: &str,
    args: &mut impl Iterator<Item = String>,
) -> Result<bool, String> {
    match name {
        "-addr" | "--addr" => out.address = Some(next(args, name)?),
        "-json" | "--json" => out.json = true,
        "-quiet" | "--quiet" => out.quiet = true,
        "-all" | "--all" => out.all = true,
        "-filter" | "--filter" => out.filter = Some(next(args, name)?),
        "-enabled" => out.enabled = Some(true),
        "-disabled" => out.enabled = Some(false),
        "-ask" => out.ask = Ask::parse(&next(args, name)?)?,
        "-allow-uid" | "--allow-uid" => out.allow_uids.push(user_id(&next(args, name)?)?),
        "-timeout" => out.timeout = Some(seconds(&next(args, name)?)?),
        _ => return Ok(false),
    }
    Ok(true)
}

fn next(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{name} needs a value"))
}

fn user_id(text: &str) -> Result<u32, String> {
    text.parse()
        .map_err(|_| format!("-allow-uid needs a user id, not '{text}'"))
}

fn seconds(text: &str) -> Result<Duration, String> {
    let secs = text
        .parse::<u64>()
        .map_err(|_| format!("-timeout needs a number of seconds, not '{text}'"))?;
    if secs == 0 {
        return Err("-timeout needs at least one second".into());
    }
    Ok(Duration::from_secs(secs))
}

fn exactly_one(what: &str, names: &[String]) -> Result<String, String> {
    match names {
        [] => Err(format!("{what} needs one name")),
        [one] => Ok(one.clone()),
        many => Err(format!("{what} takes one name, not {}", many.join(" "))),
    }
}

fn at_least_one(what: &str, names: &[String]) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Err(format!("{what} needs at least one rule name"));
    }
    Ok(names.to_vec())
}

fn no_names(what: &str, names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        Ok(())
    } else {
        Err(format!("{what} takes no names, only {}", names.join(" ")))
    }
}

/// The address to listen on: the option, then the environment, then the address
/// opensnitchd's configuration uses by default.
fn listen_address(from_flag: Option<String>, from_env: Option<String>) -> String {
    from_flag
        .filter(|text| !text.is_empty())
        .or(from_env.filter(|text| !text.is_empty()))
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_string())
}

/// The accepted values, so the help and the checks cannot drift apart.
fn usage() -> String {
    USAGE
        .replace("{ACTIONS}", &rule::ACTIONS.join(", "))
        .replace("{DURATIONS}", &rule::DURATIONS.join(", "))
        .replace("{OPERANDS}", &rule::OPERANDS.join(", "))
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("opensnitch-cli: {err}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };
    let command = match args.command() {
        Ok(command) => command,
        Err(err) => {
            eprintln!("opensnitch-cli: {err}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };
    let address = listen_address(
        args.address.clone(),
        std::env::var(ADDRESS_ENV)
            .ok()
            .filter(|text| !text.is_empty()),
    );
    match runtime().block_on(run(command, &args, &address)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("opensnitch-cli: {err}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("opensnitch-cli: cannot start the async runtime: {err}");
            std::process::exit(1);
        }
    }
}

type Serving = tokio::task::JoinHandle<Result<(), BoxError>>;

async fn run(command: Command, args: &Args, address: &str) -> Result<(), String> {
    let peer = Peer::new(args.ask);
    let serving = tokio::spawn({
        let peer = peer.clone();
        let address = address.to_string();
        let allowed = args.allow_uids.clone();
        async move { peer::serve(&address, peer, &allowed).await }
    });
    let serving = await_binding(address, serving).await?;

    let daemon = peer
        .await_daemon(args.timeout())
        .await
        .map_err(|why| format!("{why}\n{}", diagnosis(address, args.timeout())))?;
    let outcome = match command {
        Command::List(on) => list(&peer, args, on),
        Command::Show(name) => show(&peer, &name),
        Command::Add(source) => add(&peer, args, &source).await,
        Command::Enable(names) => set_enabled(&peer, args, &names, true).await,
        Command::Disable(names) => set_enabled(&peer, args, &names, false).await,
        Command::Delete(names) => del(&peer, args, &names).await,
        Command::Status => status(&peer, args, address, daemon).await,
        Command::Interception(on) => interception(&peer, args, on).await,
    };
    stop(address, serving);
    outcome
}

/// The listener, held in a task of its own; the peer is usable as soon as the
/// address answers.
async fn await_binding(address: &str, mut serving: Serving) -> Result<Serving, String> {
    let path = peer::socket_path(address);
    let deadline = Instant::now() + BIND_DEADLINE;
    while Instant::now() < deadline {
        if serving.is_finished() {
            return Err(stopped(&mut serving).await);
        }
        // A file in the filesystem is the address becoming real: any socket left
        // there by a dead peer is unlinked before binding, so this one is ours.
        if path.as_ref().is_some_and(|path| path.exists()) {
            return Ok(serving);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if let Some(path) = path {
        if serving.is_finished() {
            return Err(stopped(&mut serving).await);
        }
        return Err(format!(
            "nothing is listening on {}: {} was not created, so check that its directory \
             exists and that this user may write in it",
            address,
            path.display()
        ));
    }
    // An abstract socket and a TCP port leave nothing to look at, so a listener
    // still running after the deadline is taken as bound.
    if serving.is_finished() {
        return Err(stopped(&mut serving).await);
    }
    Ok(serving)
}

/// What a listener that has already returned has to say.
async fn stopped(serving: &mut Serving) -> String {
    let outcome = tokio::time::timeout(Duration::from_secs(1), &mut *serving).await;
    match outcome {
        Ok(Ok(Ok(()))) => "the listener stopped".to_string(),
        Ok(Ok(Err(err))) => err.to_string(),
        _ => "the listener stopped".to_string(),
    }
}

/// The socket is ours to take down: the rule of the GUI applies, a peer that
/// never bound unlinks nothing, because that socket belongs to the peer that is
/// listening on it.
fn stop(address: &str, serving: Serving) {
    serving.abort();
    if let Some(path) = peer::socket_path(address) {
        let _ = std::fs::remove_file(path);
    }
}

/// Why no daemon answered, in terms of what to check.
fn diagnosis(address: &str, timeout: Duration) -> String {
    format!(
        "no daemon at {address} within {}s. opensnitchd dials the address of its own \
         `Server`, and retries it once a second, so a daemon that is running arrives in \
         about two. Check that:
  - opensnitchd is running (`systemctl status opensnitchd`)
  - `Server.Address` in its configuration (usually /etc/opensnitchd/default-config.yaml)
    is {address}, exactly as it is given here
  - no other UI holds the address: opensnitchd serves one peer at a time, and
    opensnitch-ui-gtk4 and the Qt UI both take it at once
{ADDRESS_ENV}, or -addr, is how the address is set here.",
        timeout.as_secs()
    )
}

fn listed(peer: &Peer, args: &Args, on: Option<bool>) -> Vec<Rule> {
    let mut rules = peer.rules();
    if !args.all
        && let Some(query) = &args.filter
    {
        rules = rule::filter(&rules, query);
    }
    if let Some(enabled) = on {
        rules.retain(|rule| rule.enabled == enabled);
    }
    rule::sort_by_name(&mut rules);
    rules
}

fn list(peer: &Peer, args: &Args, on: Option<bool>) -> Result<(), String> {
    let rules = listed(peer, args, on);
    if args.json {
        return print_json(&rule::json(&rules));
    }
    if args.quiet {
        for rule in &rules {
            println!("{}", rule.name);
        }
        return Ok(());
    }
    print!("{}", rule::table(&rules));
    Ok(())
}

/// One rule as opensnitchd writes it: a single JSON object, not a list.
fn show(peer: &Peer, name: &str) -> Result<(), String> {
    let rule = peer
        .rule(name)
        .ok_or(format!("the daemon has no rule called {name}"))?;
    print_json(&one(rule::json(&[rule])))
}

fn one(mut rules: Value) -> Value {
    rules
        .as_array_mut()
        .and_then(|items| items.pop())
        .unwrap_or(Value::Null)
}

fn print_json(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| format!("cannot write the JSON: {err}"))?;
    println!("{text}");
    Ok(())
}

async fn add(peer: &Peer, args: &Args, source: &Path) -> Result<(), String> {
    let text = read_source(source)?;
    let rules = rule::from_json_text(&text)?;
    for rule in rules {
        let summary = rule::summary(&rule);
        // A rule whose duration is "always" lands in the daemon's rules
        // directory; the rest are added to the running ruleset only.
        verdict(peer.save(rule), args.timeout())
            .await
            .map_err(|why| format!("{summary}: {why}"))?;
        println!("added {summary}");
    }
    Ok(())
}

fn read_source(source: &Path) -> Result<String, String> {
    if source == Path::new("-") {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|err| format!("cannot read stdin: {err}"))?;
        return Ok(text);
    }
    std::fs::read_to_string(source)
        .map_err(|err| format!("cannot read {}: {err}", source.display()))
}

async fn set_enabled(peer: &Peer, args: &Args, names: &[String], on: bool) -> Result<(), String> {
    let word = if on { "enabled" } else { "disabled" };
    for name in names {
        // The whole rule goes with the request: opensnitchd re-reads the rule it
        // is sent, and a rule without its operator is a nil rule to it.
        verdict(peer.set_enabled(name, on), args.timeout())
            .await
            .map_err(|why| format!("{name}: {why}"))?;
        println!("{word} {name}");
    }
    Ok(())
}

async fn del(peer: &Peer, args: &Args, names: &[String]) -> Result<(), String> {
    for name in names {
        verdict(peer.delete(name), args.timeout())
            .await
            .map_err(|why| format!("{name}: {why}"))?;
        println!("deleted {name}");
    }
    Ok(())
}

async fn interception(peer: &Peer, args: &Args, on: bool) -> Result<(), String> {
    let word = if on { "resumed" } else { "paused" };
    verdict(peer.set_interception(on), args.timeout()).await?;
    println!("interception {word}");
    Ok(())
}

/// A notification and the daemon's answer to it, within the caller's timeout.
async fn verdict(
    call: impl std::future::Future<Output = Result<String, String>>,
    timeout: Duration,
) -> Result<String, String> {
    tokio::time::timeout(timeout, call)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "the daemon did not answer in {}s",
                timeout.as_secs()
            ))
        })
}

/// What `status` reports, gathered from the peer while its printing stays plain.
struct Status {
    address: String,
    connected: bool,
    daemon: Daemon,
    rules: usize,
    enabled: usize,
    stats: Result<Statistics, String>,
}

impl Status {
    fn lines(&self) -> Vec<String> {
        let mut out = vec![
            format!("daemon: {} {}", self.daemon.name, self.daemon.version),
            format!("address: {}", self.address),
            format!("connected: {}", yes_no(self.connected)),
            format!("interception: {}", yes_no(self.daemon.interception)),
            format!("default action: {}", self.daemon.default_action),
            format!(
                "rules: {} ({} on, {} off)",
                self.rules,
                self.enabled,
                self.rules - self.enabled
            ),
        ];
        match self.stats.as_ref() {
            Err(why) => out.push(format!("statistics: {why}")),
            Ok(stats) => {
                out.extend([
                    format!("daemon version: {}", stats.daemon_version),
                    format!("rules: {}", stats.rules),
                    format!("uptime: {}", uptime(stats.uptime)),
                    format!("connections: {}", stats.connections),
                    format!("accepted: {}", stats.accepted),
                    format!("dropped: {}", stats.dropped),
                    format!("ignored: {}", stats.ignored),
                    format!("dns responses: {}", stats.dns_responses),
                    format!("rule hits: {}", stats.rule_hits),
                    format!("rule misses: {}", stats.rule_misses),
                ]);
            }
        }
        out
    }

    fn json(&self) -> Value {
        let mut out = json!({
            "daemon": self.daemon.name,
            "version": self.daemon.version,
            "address": self.address,
            "connected": self.connected,
            "interception": self.daemon.interception,
            "default_action": self.daemon.default_action,
            "rules": self.rules,
            "rules_on": self.enabled,
            "rules_off": self.rules - self.enabled,
        });
        match self.stats.as_ref() {
            Err(why) => out["statistics"] = why.clone().into(),
            Ok(stats) => {
                out["statistics"] = json!({
                    "daemon_version": stats.daemon_version,
                    "rules": stats.rules,
                    "uptime": stats.uptime,
                    "uptime_text": uptime(stats.uptime),
                    "connections": stats.connections,
                    "accepted": stats.accepted,
                    "dropped": stats.dropped,
                    "ignored": stats.ignored,
                    "dns_responses": stats.dns_responses,
                    "rule_hits": stats.rule_hits,
                    "rule_misses": stats.rule_misses,
                });
            }
        }
        out
    }
}

async fn status(peer: &Peer, args: &Args, address: &str, daemon: Daemon) -> Result<(), String> {
    let rules = peer.rules();
    let enabled = rules.iter().filter(|rule| rule.enabled).count();
    let stats = peer.await_stats(args.timeout()).await.map_err(|_| {
        format!(
            "the daemon sent no statistics in {}s",
            args.timeout().as_secs()
        )
    });
    let status = Status {
        address: address.to_string(),
        connected: peer.connected(),
        daemon,
        rules: rules.len(),
        enabled,
        stats,
    };
    if args.json {
        return print_json(&status.json());
    }
    for line in status.lines() {
        println!("{line}");
    }
    Ok(())
}

fn yes_no(on: bool) -> &'static str {
    if on { "yes" } else { "no" }
}

/// The daemon's uptime in seconds, as it is worth reading.
fn uptime(secs: u64) -> String {
    let (hours, rest) = (secs / 3600, secs % 3600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Args>, String> {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    fn command(args: &[&str]) -> Result<Command, String> {
        parse(args)?.unwrap().command()
    }

    #[test]
    fn parses_flags() {
        let args = parse(&[
            "-addr",
            "unix:@osui",
            "-json",
            "-quiet",
            "-filter",
            "curl",
            "-ask",
            "allow",
            "-timeout",
            "45",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(args.address.as_deref(), Some("unix:@osui"));
        assert!(args.json);
        assert!(args.quiet);
        assert_eq!(args.filter.as_deref(), Some("curl"));
        assert_eq!(args.ask, Ask::Allow);
        assert_eq!(args.timeout(), Duration::from_secs(45));
        assert!(!args.all);
        assert!(parse(&["-all", "-list"]).unwrap().unwrap().all);
        assert_eq!(parse(&[]).unwrap().unwrap().timeout(), DEFAULT_TIMEOUT);
        assert_eq!(parse(&[]).unwrap().unwrap().ask, Ask::Daemon);
    }

    #[test]
    fn help_is_not_a_command() {
        for flag in ["-h", "-help", "--help"] {
            assert!(parse(&[flag]).unwrap().is_none(), "{flag}");
        }
        assert!(parse(&["-json", "--help"]).unwrap().is_none());
    }

    #[test]
    fn allow_uid_can_be_repeated() {
        let args = parse(&["-allow-uid", "1000", "-allow-uid", "0", "-list"])
            .unwrap()
            .unwrap();
        assert_eq!(args.allow_uids, [1000, 0]);
        assert!(parse(&["-allow-uid"]).is_err());
        assert!(parse(&["-allow-uid", "me"]).is_err());
        assert!(parse(&["-allow-uid", "-1"]).is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse(&["-addr"]).is_err());
        assert!(parse(&["-filter"]).is_err());
        assert!(parse(&["-ask", "maybe"]).is_err());
        assert!(parse(&["-timeout", "20m"]).is_err());
        assert!(parse(&["-timeout", "0"]).is_err());
        assert!(parse(&["-wat"]).is_err());
    }

    #[test]
    fn the_address_prefers_the_option_then_the_environment() {
        assert_eq!(listen_address(None, None), DEFAULT_ADDRESS);
        assert_eq!(
            listen_address(None, Some("unix:@osui".into())),
            "unix:@osui",
            "the daemon's Server.Address is passed in the environment"
        );
        assert_eq!(
            listen_address(Some("unix:/run/x.sock".into()), Some("unix:@osui".into())),
            "unix:/run/x.sock"
        );
        assert_eq!(listen_address(Some(String::new()), None), DEFAULT_ADDRESS);
    }

    #[test]
    fn the_commands_are_spelled_the_long_way_and_the_short() {
        assert_eq!(command(&["list"]), Ok(Command::List(None)));
        assert_eq!(command(&["rules", "-list"]), Ok(Command::List(None)));
        assert_eq!(command(&["-list"]), Ok(Command::List(None)));
        assert_eq!(command(&["show", "web"]), Ok(Command::Show("web".into())));
        assert_eq!(
            command(&["rules", "-show", "web"]),
            Ok(Command::Show("web".into()))
        );
        assert_eq!(
            command(&["add", "/tmp/rule.json"]),
            Ok(Command::Add(PathBuf::from("/tmp/rule.json")))
        );
        assert_eq!(
            command(&["rules", "-add", "-"]),
            Ok(Command::Add("-".into()))
        );
        assert_eq!(command(&["status"]), Ok(Command::Status));
        assert_eq!(command(&["pause"]), Ok(Command::Interception(false)));
        assert_eq!(command(&["resume"]), Ok(Command::Interception(true)));
    }

    #[test]
    fn severals_names_go_to_one_command() {
        assert_eq!(
            command(&["rules", "-enable", "a", "b", "c"]),
            Ok(Command::Enable(vec!["a".into(), "b".into(), "c".into()]))
        );
        assert_eq!(
            command(&["enable", "a"]),
            Ok(Command::Enable(vec!["a".into()]))
        );
        assert_eq!(
            command(&["rules", "-disable", "a", "-quiet", "b"]),
            Ok(Command::Disable(vec!["a".into(), "b".into()])),
            "a flag between the names does not end them"
        );
        assert_eq!(
            command(&["rules", "-del", "a", "b"]),
            Ok(Command::Delete(vec!["a".into(), "b".into()]))
        );
    }

    #[test]
    fn the_state_of_the_listed_rules_is_given_with_the_list() {
        assert_eq!(
            command(&["rules", "-list", "-enabled"]),
            Ok(Command::List(Some(true)))
        );
        assert_eq!(
            command(&["-disabled", "list"]),
            Ok(Command::List(Some(false)))
        );
    }

    #[test]
    fn commands_are_checked_before_the_daemon_is_bothered() {
        assert!(command(&[]).is_err());
        assert!(command(&["rules"]).is_err());
        assert!(command(&["rules", "-enable"]).is_err());
        assert!(command(&["-del"]).is_err());
        assert!(command(&["-show"]).is_err());
        assert!(command(&["show", "a", "b"]).is_err());
        assert!(command(&["add"]).is_err());
        assert!(command(&["status", "extra"]).is_err());
        assert!(command(&["pause", "extra"]).is_err());
        assert!(command(&["list", "a"]).is_err());
    }

    #[test]
    fn the_listened_to_rules_are_filtered_then_narrowed_by_state() {
        let peer = Peer::new(Ask::Daemon);
        let args = parse(&["-filter", "curl", "list"]).unwrap().unwrap();
        let on = matches!(args.command().unwrap(), Command::List(_));
        assert!(on);

        let mut args = parse(&["-filter", "curl", "-all", "-enabled", "list"])
            .unwrap()
            .unwrap();
        let Command::List(state) = args.command().unwrap() else {
            panic!("-enabled with list is a list");
        };
        assert_eq!(state, Some(true));
        args.all = false;
        assert_eq!(listed(&peer, &args, state), Vec::new());
    }

    #[test]
    fn the_uptime_reads_like_a_duration() {
        assert_eq!(uptime(0), "0s");
        assert_eq!(uptime(59), "59s");
        assert_eq!(uptime(60), "1m00s");
        assert_eq!(uptime(3_661), "1h01m01s");
        assert_eq!(uptime(90_061), "25h01m01s");
    }

    fn status(stats: Result<Statistics, String>) -> Status {
        Status {
            address: "unix:///run/user/1000/osui.sock".into(),
            connected: true,
            daemon: Daemon {
                name: "opensnitchd".into(),
                version: "1.8.0".into(),
                default_action: "allow".into(),
                interception: false,
            },
            rules: 12,
            enabled: 10,
            stats,
        }
    }

    #[test]
    fn status_says_the_daemon_and_its_counters() {
        let lines = status(Ok(Statistics {
            daemon_version: "1.8.0".into(),
            rules: 12,
            uptime: 3_661,
            connections: 100,
            accepted: 90,
            dropped: 8,
            ignored: 2,
            dns_responses: 7,
            rule_hits: 80,
            rule_misses: 20,
            ..Default::default()
        }))
        .lines();
        assert_eq!(lines[0], "daemon: opensnitchd 1.8.0");
        assert_eq!(lines[2], "connected: yes");
        assert_eq!(lines[3], "interception: no");
        assert_eq!(lines[5], "rules: 12 (10 on, 2 off)");
        assert!(lines.iter().any(|l| l == "uptime: 1h01m01s"));
        assert!(lines.iter().any(|l| l == "rule misses: 20"));
        assert!(lines.iter().any(|l| l == "dns responses: 7"));
    }

    #[test]
    fn status_says_so_when_the_statistics_are_missing() {
        let lines = status(Err("the daemon sent no statistics in 20s".into())).lines();
        assert!(
            lines
                .iter()
                .any(|l| l == "statistics: the daemon sent no statistics in 20s"),
            "{lines:?}"
        );

        let value = status(Err("the daemon sent no statistics in 20s".into())).json();
        assert_eq!(value["rules_on"], 10);
        assert_eq!(value["connected"], true);
        assert_eq!(value["interception"], false);
        assert!(value["statistics"].is_string());
    }

    #[test]
    fn the_statistics_json_keeps_the_names_of_their_fields() {
        let value = status(Ok(Statistics {
            daemon_version: "1.8.0".into(),
            rules: 3,
            uptime: 90,
            accepted: 2,
            dropped: 1,
            ..Default::default()
        }))
        .json();
        assert_eq!(value["statistics"]["daemon_version"], "1.8.0");
        assert_eq!(value["statistics"]["uptime"], 90);
        assert_eq!(value["statistics"]["uptime_text"], "1m30s");
        assert_eq!(value["statistics"]["accepted"], 2);
        assert_eq!(value["statistics"]["dropped"], 1);
    }

    #[test]
    fn one_rule_is_the_object_on_disk() {
        let rule = Rule {
            name: "web".into(),
            action: "deny".into(),
            duration: "always".into(),
            operator: Some(rule::always_operator()),
            ..Default::default()
        };
        let value = one(rule::json(&[rule]));
        assert_eq!(value["name"], "web");
        assert_eq!(value["operator"]["operand"], "true");
    }

    #[test]
    fn the_help_lists_the_values_the_daemon_accepts() {
        let text = usage();
        assert!(text.contains("unix-abstract:name"));
        assert!(text.contains("OPENSNITCH_ADDRESS"));
        assert!(text.contains("always"), "the durations are named");
        assert!(text.contains("process.path"), "the fields are named");
        assert!(text.contains("reject"), "the actions are named");
        assert!(!text.contains('{'), "nothing is left to fill in");
    }
}
