
mod bus;
mod checksum;
mod dialog;
mod link;
mod model;
mod rule;
mod rule_edit;
mod rules;
mod server;
mod settings;
mod tray;
mod view;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use gtk4::gio::ApplicationFlags;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::link::Updater;
use crate::server::{PromptRequest, Service};
use crate::settings::{DEFAULT_ADDRESS, Settings};

#[allow(clippy::excessive_nesting, clippy::too_many_lines)]
pub mod proto {
    tonic::include_proto!("protocol");
}

const APP_ID: &str = "io.github.jeronimoalbi.Snitch";

const USAGE: &str = "\
opensnitch-ui-gtk4 - GTK4 UI for the OpenSnitch daemon

USAGE: opensnitch-ui-gtk4 [OPTIONS]

OPTIONS:
    --socket <ADDRESS>       Address to listen on (default: the Qt UI setting, else unix:///tmp/osui.sock)
    --settings <PATH>        Qt UI settings file (default: ~/.config/opensnitch/settings.conf)
    --allow-uid <UID>        Let this user, besides root, act as the daemon (repeatable)
    -h, --help               Show this help";

#[derive(Debug, Default)]
struct Args {
    socket: Option<String>,
    settings: Option<PathBuf>,
    allow_uids: Vec<u32>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut out = Args::default();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--socket" => out.socket = Some(value("--socket")?),
            "--settings" => out.settings = Some(PathBuf::from(value("--settings")?)),
            "--allow-uid" => {
                let uid = value("--allow-uid")?;
                let uid = uid
                    .parse()
                    .map_err(|_| format!("--allow-uid needs a user id, not '{uid}'"))?;
                out.allow_uids.push(uid);
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(Some(out))
}

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return glib::ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("opensnitch-ui-gtk4: {err}\n\n{USAGE}");
            return glib::ExitCode::FAILURE;
        }
    };

    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(ApplicationFlags::NON_UNIQUE)
        .build();
    let args = Rc::new(args);
    app.connect_activate(move |app| {
        let settings_path = args.settings.clone().unwrap_or_else(Settings::default_path);
        std::mem::forget(app.hold());
        run_daemon(
            app,
            args.socket.clone(),
            settings_path,
            args.allow_uids.clone(),
        );
    });
    app.run_with_args::<String>(&[])
}

fn listen_address(socket: Option<String>, settings_path: &Path) -> String {
    socket
        .or_else(|| Settings::load(settings_path).server_address)
        .unwrap_or_else(|| DEFAULT_ADDRESS.to_string())
}

fn missing_socket_dir(address: &str) -> Option<PathBuf> {
    let path = server::socket_path(address)?;
    let dir = path.parent()?;
    (!dir.is_dir()).then(|| dir.to_path_buf())
}

fn start_runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!("cannot start the async runtime: {err}");
            std::process::exit(1);
        }
    }
}

fn spawn_server(
    runtime: tokio::runtime::Runtime,
    address: String,
    service: Service,
    allow_uids: Vec<u32>,
) {
    std::thread::spawn(move || {
        let outcome = runtime.block_on(async {
            tokio::select! {
                result = server::serve(&address, service, &allow_uids) => result,
                () = server::shutdown_signal() => Ok(()),
            }
        });
        if let Some(path) = server::socket_path(&address) {
            let _ = std::fs::remove_file(path);
        }
        if let Err(err) = outcome {
            tracing::error!("server stopped: {err}");
            std::process::exit(1);
        }
        std::process::exit(0);
    });
}

fn run_daemon(
    app: &adw::Application,
    socket: Option<String>,
    settings_path: PathBuf,
    allow_uids: Vec<u32>,
) {
    let address = listen_address(socket, &settings_path);
    if let Some(dir) = missing_socket_dir(&address) {
        tracing::error!("socket directory {} does not exist", dir.display());
        app.quit();
        return;
    }

    let (prompts, requests) = async_channel::unbounded::<PromptRequest>();
    let bus_settings = settings_path.clone();
    let service = Service::new(prompts, settings_path);
    let link = service.link();
    link.keep_pause_in(glib::user_runtime_dir().join("snitch-paused"));
    let runtime = start_runtime();
    let updater = Updater::on(link, runtime.handle().clone());
    spawn_server(runtime, address, service, allow_uids);
    tray::show(app, &updater);
    bus::serve(updater, bus_settings);

    let prompt_app = app.clone();
    glib::spawn_future_local(async move {
        while let Ok(request) = requests.recv().await {
            handle_prompt(&prompt_app, request).await;
        }
    });
}

async fn handle_prompt(app: &adw::Application, request: PromptRequest) {
    let PromptRequest {
        con,
        settings,
        mismatch,
        updater,
        reply,
    } = request;
    let reply = Rc::new(RefCell::new(Some(reply)));
    let gone = reply.clone();
    let cancelled = move || gone.borrow().as_ref().is_none_or(|r| r.is_closed());
    let checks = dialog::Checks { mismatch, updater };
    let asked = con.clone();
    let answer = dialog::prompt(app, con, settings, checks, cancelled).await;
    let abandoned = reply.borrow().as_ref().is_none_or(|r| r.is_closed());
    log_answer(&answer, &asked, abandoned);
    if answer.timed_out
        && let Some(rule) = &answer.rule
    {
        let (title, body) = view::missed_popup(&asked, rule);
        glib::spawn_future_local(notify_desktop(title, body));
    }
    if let Some(reply) = reply.borrow_mut().take() {
        let _ = reply.send(answer.rule);
    }
}

fn log_answer(answer: &dialog::Answer, asked: &proto::Connection, abandoned: bool) {
    match (&answer.rule, answer.timed_out) {
        (Some(rule), true) => tracing::info!(
            "no answer in time, applied the default: {} {}",
            rule.action,
            rule.duration
        ),
        (None, _) if abandoned => tracing::info!(
            "the daemon stopped waiting for {}",
            view::connection_summary(asked)
        ),
        (None, _) => tracing::warn!(
            "no rule came out of the prompt for {}",
            view::connection_summary(asked)
        ),
        (Some(_), false) => {}
    }
}

async fn notify_desktop(title: String, body: String) {
    use std::collections::HashMap;

    use glib::prelude::ToVariant;

    let urgency_normal: u8 = 1;
    let hints = HashMap::from([("urgency".to_string(), urgency_normal.to_variant())]);
    let expire_ms: i32 = -1;
    let params = (
        "OpenSnitch",
        0u32,
        "dialog-information",
        title,
        body,
        Vec::<String>::new(),
        hints,
        expire_ms,
    )
        .to_variant();

    let sent = async {
        let bus = gtk4::gio::bus_get_future(gtk4::gio::BusType::Session).await?;
        bus.call_future(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify",
            Some(&params),
            None,
            gtk4::gio::DBusCallFlags::NONE,
            5_000,
        )
        .await
    };
    if let Err(err) = sent.await {
        tracing::warn!("cannot show the notification: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Option<Args>, String> {
        parse_args(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn parses_flags() {
        let a = parse(&["--socket", "unix:/x"]).unwrap().unwrap();
        assert_eq!(a.socket.as_deref(), Some("unix:/x"));
        assert!(parse(&["--help"]).unwrap().is_none());
    }

    #[test]
    fn allow_uid_can_be_repeated() {
        let a = parse(&["--allow-uid", "1000", "--allow-uid", "0"])
            .unwrap()
            .unwrap();
        assert_eq!(a.allow_uids, [1000, 0]);
        assert!(parse(&["--allow-uid", "me"]).is_err());
        assert!(parse(&["--allow-uid"]).is_err());
        assert!(parse(&["--allow-uid", "-1"]).is_err());
        assert!(parse(&[]).unwrap().unwrap().allow_uids.is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(&["--socket"]).is_err());
        assert!(parse(&["--wat"]).is_err());
    }

    #[test]
    fn the_listen_address_prefers_the_option_then_the_file_then_the_default() {
        let missing = Path::new("/nonexistent/settings.conf");
        assert_eq!(listen_address(Some("unix:/x".into()), missing), "unix:/x");
        assert_eq!(listen_address(None, missing), DEFAULT_ADDRESS);

        let dir = std::env::temp_dir().join(format!("snitch-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.conf");
        std::fs::write(&file, "[global]\nserver_address=unix:///run/x.sock\n").unwrap();
        assert_eq!(listen_address(None, &file), "unix:///run/x.sock");
        assert_eq!(listen_address(Some("unix:/y".into()), &file), "unix:/y");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_missing_socket_directory_is_reported() {
        let missing = missing_socket_dir("unix:///nonexistent-dir/osui.sock");
        assert_eq!(missing, Some(PathBuf::from("/nonexistent-dir")));
        assert_eq!(missing_socket_dir("unix:///tmp/osui.sock"), None);
        assert_eq!(missing_socket_dir("127.0.0.1:50051"), None);
    }
}
