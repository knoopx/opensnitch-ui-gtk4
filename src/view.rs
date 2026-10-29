
use std::path::{Component, Path};

use crate::model::command_line;
use crate::proto::{Connection, Operator, Rule};

pub fn escape_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

pub fn printable_lines(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect()
}

fn escape_body(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn missed_popup(con: &Connection, rule: &Rule) -> (String, String) {
    let verb = match rule.action.as_str() {
        "allow" => "allowed",
        "reject" => "rejected",
        _ => "dropped",
    };
    let program = match con.process_path.rsplit('/').next() {
        Some(name) if !name.is_empty() => printable(name),
        _ => "A program".to_string(),
    };
    let host = if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    };
    let destination = match con.dst_port {
        0 => printable(host),
        port => format!("{}:{port}", printable(host)),
    };
    let protocol = match con.protocol.as_str() {
        "" => String::new(),
        p => format!(" ({})", printable(&p.to_uppercase())),
    };
    let body = format!(
        "{} to {}{}\nNobody answered in time, so the default action was applied.",
        escape_body(&program),
        escape_body(&destination),
        escape_body(&protocol),
    );
    (format!("Connection {verb}"), body)
}

pub fn connection_summary(con: &Connection) -> String {
    let program = if con.process_path.is_empty() {
        "unknown program"
    } else {
        &con.process_path
    };
    let host = if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    };
    let destination = match con.dst_port {
        0 => printable(host),
        port => format!("{}:{port}", printable(host)),
    };
    format!(
        "{} -> {destination} {}",
        printable(program),
        printable(&con.protocol)
    )
}

const SYSTEM_DIRS: [&str; 7] = ["/usr", "/opt", "/bin", "/sbin", "/lib", "/lib64", "/snap"];

pub fn in_system_dir(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|c| matches!(c, Component::ParentDir))
        && SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
}

pub fn same_program(exec: &Path, process: &Path) -> bool {
    exec == process
        || (in_system_dir(process)
            && exec.file_name().is_some()
            && exec.file_name() == process.file_name())
}

pub fn app_name(desktop_name: Option<&str>, con: &Connection) -> String {
    if let Some(name) = desktop_name.filter(|n| !n.is_empty()) {
        return name.to_string();
    }
    match con.process_path.rsplit('/').next() {
        Some(base) if !base.is_empty() => base.to_string(),
        _ => "Outgoing connection".to_string(),
    }
}

pub fn popup_message(app_name: &str, con: &Connection) -> String {
    let name = format!("<b>{}</b>", escape_markup(app_name));
    let target = escape_markup(if con.dst_host.is_empty() {
        &con.dst_ip
    } else {
        &con.dst_host
    });
    let proto = escape_markup(&con.protocol.to_uppercase());
    let action = if con.dst_port == 53 && con.dst_ip != con.dst_host && !con.dst_host.is_empty() {
        format!(
            "is attempting to resolve <b>{target}</b> via {}, {proto} port {}",
            escape_markup(&con.dst_ip),
            con.dst_port
        )
    } else if con.dst_port == 0 {
        format!("is connecting to <b>{target}</b>, {proto}")
    } else {
        format!(
            "is connecting to <b>{target}</b> on {proto} port {}",
            con.dst_port
        )
    };
    format!("{name} {action}")
}

pub fn path_label(app_name: &str, con: &Connection) -> Option<String> {
    let path = &con.process_path;
    if path.is_empty() {
        return None;
    }
    let text = if con.process_args.is_empty() {
        path.clone()
    } else if !con.process_args.contains(path) {
        if app_name.to_lowercase() == command_line(con) {
            path.clone()
        } else {
            format!("({path})")
        }
    } else {
        return None;
    };
    Some(printable(&text))
}

pub fn args_label(app_name: &str, con: &Connection) -> Option<String> {
    let args = command_line(con);
    if app_name.to_lowercase() == args || args.is_empty() {
        None
    } else {
        Some(printable(&args))
    }
}

pub fn user_label(uid: u32, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("{uid} ({name})"),
        None => uid.to_string(),
    }
}

pub fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let (name, _, id) = (f.next()?, f.next()?, f.next()?);
        (id.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

pub fn md5(con: &Connection) -> &str {
    con.process_checksums
        .get("process.hash.md5")
        .map_or("", String::as_str)
}

pub fn details_text(con: &Connection, user: &str) -> String {
    let mut out = format!(
        "{} {}:{} -> {}:{}\n\n",
        con.protocol.to_uppercase(),
        con.src_ip,
        con.src_port,
        con.dst_ip,
        con.dst_port
    );
    let mut line =
        |key: &str, value: &str| out.push_str(&format!("{key:<9}{}\n", printable(value)));
    line("Path:", &con.process_path);
    line("Cmdline:", &command_line(con));
    line("CWD:", &con.process_cwd);
    line("MD5:", md5(con));
    line("UID:", user);
    line("PID:", &con.process_id.to_string());

    if !con.process_tree.is_empty() {
        out.push_str("\nProcess tree:\n");
        for (depth, entry) in con.process_tree.iter().rev().enumerate() {
            let indent = "  ".repeat(depth);
            let branch = if depth == 0 { "" } else { "\\_ " };
            out.push_str(&format!(
                "{indent}{branch}{} ({})\n",
                printable(&entry.key),
                entry.value
            ));
        }
    }
    if !con.process_env.is_empty() {
        out.push_str("\nEnvironment:\n");
        let mut env: Vec<_> = con.process_env.iter().collect();
        env.sort();
        for (key, value) in env {
            out.push_str(&format!("{}={}\n", printable(key), printable(value)));
        }
    }
    out
}

fn clause_text(op: &Operator) -> String {
    let data = printable(&op.data);
    match op.operand.as_str() {
        "process.path" | "dest.ip" => data,
        "process.command" => format!("command {data}"),
        "process.id" => format!("pid {data}"),
        "process.hash.md5" => format!("checksum {data}"),
        "user.id" => format!("user {data}"),
        "dest.host" => format!("host {data}"),
        "dest.port" => format!("port {data}"),
        "dest.network" => format!("network {data}"),
        other => format!("{other} {data}"),
    }
}

pub fn rule_clauses(rule: &Rule) -> String {
    fn join(op: &Operator) -> Vec<String> {
        if op.list.is_empty() {
            vec![clause_text(op)]
        } else {
            op.list.iter().flat_map(join).collect()
        }
    }
    match &rule.operator {
        Some(op) => join(op).join(" and "),
        None => String::new(),
    }
}

pub fn rule_matches(rule: &Rule, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    [
        rule.name.as_str(),
        rule.description.as_str(),
        &rule_clauses(rule),
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(&query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::StringInt;

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            src_ip: "10.0.0.2".into(),
            src_port: 5555,
            dst_ip: "1.2.3.4".into(),
            dst_host: "example.com".into(),
            dst_port: 443,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["curl".into(), "x".into()],
            ..Default::default()
        }
    }

    #[test]
    fn message_variants() {
        let mut c = con();
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is connecting to <b>example.com</b> on TCP port 443"
        );
        c.dst_port = 0;
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is connecting to <b>example.com</b>, TCP"
        );
        c.dst_port = 53;
        c.protocol = "udp".into();
        assert_eq!(
            popup_message("curl", &c),
            "<b>curl</b> is attempting to resolve <b>example.com</b> via 1.2.3.4, UDP port 53"
        );
    }

    #[test]
    fn message_escapes_markup() {
        let mut c = con();
        c.dst_host = "<i>evil</i>&".into();
        assert!(popup_message("<b>x", &c).contains("&lt;i&gt;evil&lt;/i&gt;&amp;"));
        assert!(popup_message("<b>x", &c).starts_with("<b>&lt;b&gt;x</b>"));
    }

    #[test]
    fn path_and_args_labels() {
        let mut c = con();
        assert_eq!(path_label("curl", &c).as_deref(), Some("(/usr/bin/curl)"));
        assert_eq!(args_label("curl", &c).as_deref(), Some("curl x"));
        c.process_args = vec!["/usr/bin/curl".into()];
        assert_eq!(path_label("curl", &c), None);
        c.process_args.clear();
        assert_eq!(path_label("curl", &c).as_deref(), Some("/usr/bin/curl"));
        assert_eq!(args_label("curl", &c), None);
    }

    #[test]
    fn summary_names_program_destination_and_protocol() {
        let mut c = con();
        assert_eq!(
            connection_summary(&c),
            "/usr/bin/curl -> example.com:443 tcp"
        );
        c.process_args = vec!["--token=secret".into()];
        assert!(!connection_summary(&c).contains("secret"));
        c.process_path.clear();
        c.dst_host.clear();
        c.dst_port = 0;
        assert_eq!(connection_summary(&c), "unknown program -> 1.2.3.4 tcp");
    }

    #[test]
    fn summary_cannot_forge_log_lines() {
        let mut c = con();
        c.process_path = "/tmp/x\nINFO answered allow always".into();
        assert!(!connection_summary(&c).contains('\n'));
    }

    #[test]
    fn system_directories_are_recognised() {
        let system = |p: &str| in_system_dir(Path::new(p));
        assert!(system("/usr/bin/firefox"));
        assert!(system("/usr/lib/firefox/firefox"));
        assert!(system("/opt/google/chrome/chrome"));
        assert!(system("/snap/firefox/4793/usr/lib/firefox/firefox"));
        assert!(!system("/tmp/evil/firefox"));
        assert!(!system("/home/user/bin/firefox"));
        assert!(!system("/dev/shm/firefox"));
        assert!(!system("/usrx/bin/firefox"), "only whole directory names");
        assert!(!system("/usr/../tmp/evil/firefox"), "no parent components");
        assert!(!system("usr/bin/firefox"), "relative");
    }

    #[test]
    fn a_program_borrows_a_desktop_entry_only_from_a_system_directory() {
        let same = |exec: &str, process: &str| same_program(Path::new(exec), Path::new(process));
        assert!(same("firefox", "/usr/lib/firefox/firefox"));
        assert!(same("firefox", "/usr/bin/firefox"));
        assert!(!same("firefox", "/tmp/evil/firefox"));
        assert!(!same("firefox", "/home/user/.cache/firefox"));
        assert!(!same("chrome", "/usr/bin/firefox"));
        assert!(same("/opt/app/bin/app", "/opt/app/bin/app"));
        assert!(same("/home/user/app/app", "/home/user/app/app"));
        assert!(!same("", "/usr/bin/firefox"));
    }

    #[test]
    fn names() {
        let mut c = con();
        assert_eq!(app_name(None, &c), "curl");
        assert_eq!(app_name(Some("Curl App"), &c), "Curl App");
        c.process_path.clear();
        assert_eq!(app_name(None, &c), "Outgoing connection");
    }

    fn applied(action: &str) -> Rule {
        Rule {
            action: action.into(),
            ..Default::default()
        }
    }

    #[test]
    fn missed_popup_says_what_happened() {
        let (title, body) = missed_popup(&con(), &applied("deny"));
        assert_eq!(title, "Connection dropped");
        assert_eq!(
            body,
            "curl to example.com:443 (TCP)\nNobody answered in time, so the default action was applied."
        );
    }

    #[test]
    fn missed_popup_title_follows_the_action() {
        assert_eq!(
            missed_popup(&con(), &applied("allow")).0,
            "Connection allowed"
        );
        assert_eq!(
            missed_popup(&con(), &applied("reject")).0,
            "Connection rejected"
        );
    }

    #[test]
    fn missed_popup_copes_with_missing_data() {
        let mut c = con();
        c.process_path.clear();
        c.dst_host.clear();
        c.dst_port = 0;
        c.protocol.clear();
        let (_, body) = missed_popup(&c, &applied("deny"));
        assert!(body.starts_with("A program to 1.2.3.4\n"), "{body}");
    }

    #[test]
    fn missed_popup_escapes_connection_data() {
        let mut c = con();
        c.process_path = "/tmp/<i>evil&".into();
        c.dst_host = "<a href=\"x\">".into();
        let (_, body) = missed_popup(&c, &applied("deny"));
        assert!(
            body.starts_with("&lt;i&gt;evil&amp; to &lt;a href=\"x\"&gt;:443 (TCP)\n"),
            "{body}"
        );
    }

    fn simple(operand: &str, data: &str) -> Operator {
        Operator {
            r#type: "simple".into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn listed(list: Vec<Operator>) -> Operator {
        Operator {
            r#type: "list".into(),
            operand: "list".into(),
            list,
            ..Default::default()
        }
    }

    fn saved(action: &str, duration: &str, operator: Operator) -> Rule {
        Rule {
            name: "allow-always-simple-curl".into(),
            action: action.into(),
            duration: duration.into(),
            operator: Some(operator),
            ..Default::default()
        }
    }

    #[test]
    fn list_clauses_are_joined_by_and() {
        let rule = saved(
            "allow",
            "5m",
            listed(vec![
                simple("dest.port", "443"),
                simple("user.id", "1000"),
                simple("process.path", "/usr/bin/curl"),
            ]),
        );
        assert_eq!(
            rule_clauses(&rule),
            "port 443 and user 1000 and /usr/bin/curl"
        );
    }

    #[test]
    fn nested_lists_are_flattened_into_the_same_line() {
        let rule = saved(
            "allow",
            "always",
            listed(vec![
                simple("dest.host", "example.com"),
                listed(vec![simple("dest.port", "80"), simple("dest.port", "443")]),
            ]),
        );
        assert_eq!(
            rule_clauses(&rule),
            "host example.com and port 80 and port 443"
        );
    }

    #[test]
    fn operands_without_a_name_keep_theirs() {
        let rule = saved("allow", "always", simple("dest.mac", "aa:bb:cc:dd:ee:ff"));
        assert_eq!(rule_clauses(&rule), "dest.mac aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn a_rule_without_an_operator_has_no_clauses() {
        let rule = Rule {
            name: "empty".into(),
            action: "allow".into(),
            duration: "always".into(),
            ..Default::default()
        };
        assert_eq!(rule_clauses(&rule), "");
    }

    #[test]
    fn the_filter_reads_name_description_and_clauses() {
        let mut rule = saved("allow", "always", simple("process.path", "/usr/bin/curl"));
        rule.description = "dev box".into();
        assert!(rule_matches(&rule, ""));
        assert!(rule_matches(&rule, "  "));
        assert!(rule_matches(&rule, "CURL"));
        assert!(rule_matches(&rule, "dev"));
        assert!(rule_matches(&rule, "usr/bin"));
        assert!(!rule_matches(&rule, "firefox"));
    }

    #[test]
    fn clause_text_drops_control_characters() {
        let rule = saved("allow", "always", simple("process.path", "/tmp/a\nb"));
        assert!(!rule_clauses(&rule).contains('\n'));
    }

    #[test]
    fn details_include_tree_and_env() {
        let mut c = con();
        c.process_tree = vec![
            StringInt {
                key: "/usr/bin/systemd".into(),
                value: 1,
            },
            StringInt {
                key: "/usr/bin/curl".into(),
                value: 77,
            },
        ];
        c.process_env.insert("HOME".into(), "/root".into());
        let text = details_text(&c, "0 (root)");
        assert!(text.starts_with("TCP 10.0.0.2:5555 -> 1.2.3.4:443"));
        assert!(text.contains("/usr/bin/curl (77)\n  \\_ /usr/bin/systemd (1)"));
        assert!(text.contains("HOME=/root"));
    }
}
