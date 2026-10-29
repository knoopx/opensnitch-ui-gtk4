
use crate::model::{self, Field, Op, Target, kind, operand};
use crate::proto::{Connection, Operator, Rule};
use crate::settings::Settings;

pub const DURATIONS: [(&str, &str); 9] = [
    ("once", "once"),
    ("30s", "30s"),
    ("5m", "5m"),
    ("15m", "15m"),
    ("30m", "30m"),
    ("1h", "1h"),
    ("12h", "12h"),
    ("until reboot", "until restart"),
    ("forever", "always"),
];

pub fn duration_secs(duration: &str) -> Option<i64> {
    let (number, unit) = [("s", 1), ("m", 60), ("h", 3600)]
        .into_iter()
        .find_map(|(suffix, unit)| duration.strip_suffix(suffix).map(|n| (n, unit)))?;
    number.parse::<i64>().ok()?.checked_mul(unit)
}

pub fn is_expired(rule: &Rule, now: i64) -> bool {
    duration_secs(&rule.duration).is_some_and(|secs| rule.created.saturating_add(secs) <= now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Drop,
    Allow,
    Reject,
}

impl Action {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            1 => Self::Allow,
            2 => Self::Reject,
            _ => Self::Drop,
        }
    }

    pub fn as_rule_action(self) -> &'static str {
        match self {
            Self::Drop => "deny",
            Self::Allow => "allow",
            Self::Reject => "reject",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Drop => "Drop",
            Self::Allow => "Allow",
            Self::Reject => "Reject",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Choice<'a> {
    pub action: Action,
    pub duration_idx: usize,
    pub from: Option<&'a Target>,
    pub ip: Option<&'a Target>,
    pub check_port: bool,
    pub check_uid: bool,
    pub check_sum: bool,
    pub checksum: &'a str,
}

pub fn slugify(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn to_operator(op: &Op) -> Operator {
    Operator {
        r#type: op.kind.to_string(),
        operand: op.operand.to_string(),
        data: op.data.clone(),
        sensitive: false,
        list: Vec::new(),
    }
}

const MAX_NAME: usize = 200;

pub fn build_rule(con: &Connection, choice: &Choice, created: i64) -> Option<Rule> {
    let duration = DURATIONS.get(choice.duration_idx).map_or("always", |d| d.1);
    let action = choice.action.as_rule_action();

    let mut conditions: Vec<(Op, String)> = Vec::new();
    if let Some(t) = choice.ip {
        let op = t.op.clone();
        conditions.push((op.clone(), op.data.clone()));
    }
    if choice.check_port {
        let op = Op::simple(operand::DEST_PORT, con.dst_port.to_string());
        conditions.push((op.clone(), op.data.clone()));
    }
    if choice.check_uid {
        let op = Op::simple(operand::USER_ID, con.user_id.to_string());
        conditions.push((op.clone(), op.data.clone()));
    }
    if choice.check_sum && !choice.checksum.is_empty() {
        conditions.push((
            Op::simple(operand::PROCESS_HASH_MD5, choice.checksum),
            operand::PROCESS_HASH_MD5.to_string(),
        ));
    }

    let mut main = choice.from.map(|t| t.op.clone());
    if main.is_none() && !conditions.is_empty() {
        main = Some(conditions.remove(0).0);
    }
    let main = main.filter(|op| !op.data.is_empty())?;
    conditions.retain(|(op, _)| *op != main);

    let first_arg = model::command_line(con)
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_string();
    let loose_command = |op: &Op| {
        op.operand == operand::PROCESS_COMMAND
            && (!first_arg.starts_with('/') || first_arg.starts_with("/proc"))
    };
    let network = |op: &Op| op.operand == operand::DEST_NETWORK;
    let aliased = model::network_alias(&con.dst_ip).is_some();
    let loose = loose_command(&main) || conditions.iter().any(|(op, _)| loose_command(op));
    let alias = aliased && (network(&main) || conditions.iter().any(|(op, _)| network(op)));
    let pinned = main.operand == operand::PROCESS_PATH
        || conditions
            .iter()
            .any(|(op, _)| op.operand == operand::PROCESS_PATH);
    if (loose || alias) && !pinned {
        let base = con.process_path.rsplit('/').next().unwrap_or_default();
        conditions.push((
            Op::simple(operand::PROCESS_PATH, con.process_path.clone()),
            if alias {
                base.to_string()
            } else {
                String::new()
            },
        ));
    }

    let shape = if conditions.is_empty() {
        "simple"
    } else {
        "list"
    };
    let mut name = slugify(&format!(
        "{} {shape} {}",
        slugify(&format!("{action} {duration}")),
        main.data
    ));
    name.truncate(128);

    let append = |name: &mut String, part: &str| {
        if !part.is_empty() {
            *name = slugify(&format!("{name} {part}"));
        }
    };
    for (_, part) in &conditions {
        append(&mut name, part);
    }

    let operator = if conditions.is_empty() {
        to_operator(&main)
    } else {
        let extra: Vec<Op> = conditions.iter().map(|(op, _)| op.clone()).collect();
        Operator {
            r#type: kind::LIST.to_string(),
            operand: kind::LIST.to_string(),
            data: String::new(),
            sensitive: false,
            list: extra
                .iter()
                .chain(std::iter::once(&main))
                .map(to_operator)
                .collect(),
        }
    };

    name.truncate(MAX_NAME);
    Some(Rule {
        created,
        name,
        enabled: true,
        action: action.to_string(),
        duration: duration.to_string(),
        operator: Some(operator),
        ..Default::default()
    })
}

pub fn make_name_unique(rule: &mut Rule, known: &[Rule], now: i64) {
    let holder = |name: &str| known.iter().find(|r| r.name == name && !is_expired(r, now));
    match holder(&rule.name) {
        None => return,
        Some(r)
            if (&r.action, &r.duration, &r.operator)
                == (&rule.action, &rule.duration, &rule.operator) =>
        {
            return;
        }
        Some(_) => {}
    }
    let free = (0..100)
        .map(|i| format!("{}-{i}", rule.name))
        .find(|name| holder(name).is_none());
    if let Some(name) = free {
        rule.name = name;
    }
}

pub fn default_rule(
    con: &Connection,
    settings: &Settings,
    duration_idx: Option<usize>,
    created: i64,
) -> Option<Rule> {
    let what = model::what_targets(con);
    let ip = model::ip_targets(con);
    let target = what.get(model::default_target_index(
        &what,
        con,
        settings.default_target,
    ))?;
    let from = target.field.is_process().then_some(target);
    let ip_target = if target.field == Field::DstIp {
        Some(target)
    } else if settings.advanced_dstip {
        ip.first()
    } else {
        None
    };
    let choice = Choice {
        action: Action::from_index(settings.default_action),
        duration_idx: duration_idx.unwrap_or(settings.default_duration),
        from,
        ip: ip_target,
        check_port: settings.advanced_dstport || target.field == Field::DstPort,
        check_uid: settings.advanced_uid || target.field == Field::UserId,
        check_sum: settings.advanced_checksum,
        checksum: crate::view::md5(con),
    };
    build_rule(con, &choice, created)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn con() -> Connection {
        Connection {
            protocol: "tcp".into(),
            dst_ip: "93.184.216.34".into(),
            dst_host: "example.com".into(),
            dst_port: 443,
            user_id: 1000,
            process_id: 7,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["/usr/bin/curl".into(), "x".into()],
            ..Default::default()
        }
    }

    fn choice<'a>(from: &'a [Target], idx: usize) -> Choice<'a> {
        Choice {
            action: Action::Allow,
            duration_idx: 8,
            from: Some(&from[idx]),
            ip: None,
            check_port: false,
            check_uid: false,
            check_sum: false,
            checksum: "",
        }
    }

    fn bare<'a>() -> Choice<'a> {
        Choice {
            action: Action::Allow,
            duration_idx: 8,
            from: None,
            ip: None,
            check_port: false,
            check_uid: false,
            check_sum: false,
            checksum: "",
        }
    }

    #[test]
    fn slugify_matches_python_slugify() {
        assert_eq!(
            slugify("allow always simple /usr/bin/curl"),
            "allow-always-simple-usr-bin-curl"
        );
        assert_eq!(slugify("  --Hi  there!! "), "hi-there");
    }

    #[test]
    fn simple_rule() {
        let c = con();
        let t = model::from_targets(&c);
        let rule = build_rule(&c, &choice(&t, 0), 1).unwrap();
        assert_eq!(rule.name, "allow-always-simple-usr-bin-curl");
        assert_eq!(
            (rule.action.as_str(), rule.duration.as_str()),
            ("allow", "always")
        );
        let op = rule.operator.unwrap();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str(), op.data.as_str()),
            ("simple", "process.path", "/usr/bin/curl")
        );
        assert!(rule.enabled);
    }

    #[test]
    fn list_rule_from_checkboxes() {
        let c = con();
        let t = model::from_targets(&c);
        let mut ch = choice(&t, 0);
        ch.check_port = true;
        ch.check_uid = true;
        ch.check_sum = true;
        ch.checksum = "abc";
        let rule = build_rule(&c, &ch, 1).unwrap();
        assert_eq!(
            rule.name,
            "allow-always-list-usr-bin-curl-443-1000-process-hash-md5"
        );
        let op = rule.operator.unwrap();
        assert_eq!(op.r#type, "list");
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(
            operands,
            ["dest.port", "user.id", "process.hash.md5", "process.path"]
        );
    }

    #[test]
    fn a_lone_destination_row_is_a_rule_of_its_own() {
        let c = con();
        let mut ch = bare();
        ch.check_port = true;
        let rule = build_rule(&c, &ch, 1).unwrap();
        assert_eq!(rule.name, "allow-always-simple-443");
        assert_eq!(rule.action, "allow");
        let op = rule.operator.unwrap();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str(), op.data.as_str()),
            ("simple", "dest.port", "443")
        );
    }

    #[test]
    fn rows_and_the_program_clause_combine_into_one_list() {
        let c = con();
        let ip = model::ip_targets(&c);
        let exe = model::from_targets(&c);
        let mut ch = choice(&exe, 0);
        ch.check_port = true;
        ch.ip = ip.iter().find(|t| t.label == "to 93.184.216.34");
        let op = build_rule(&c, &ch, 1).unwrap().operator.unwrap();
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(operands, ["dest.ip", "dest.port", "process.path"]);
    }

    #[test]
    fn nothing_selected_builds_no_rule() {
        let c = con();
        assert!(build_rule(&c, &bare(), 1).is_none());
    }

    #[test]
    fn relative_command_adds_path() {
        let mut c = con();
        c.process_args = vec!["curl".into(), "x".into()];
        let t = model::from_targets(&c);
        let op = build_rule(&c, &choice(&t, 1), 1).unwrap().operator.unwrap();
        assert_eq!(op.r#type, "list");
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(operands, ["process.path", "process.command"]);
    }

    #[test]
    fn network_alias_adds_process_path() {
        let mut c = con();
        c.dst_ip = "192.168.0.5".into();
        let ip = model::ip_targets(&c);
        let idx = ip.iter().position(|t| t.label == "to LAN").unwrap();
        let mut ch = bare();
        ch.ip = Some(&ip[idx]);
        let rule = build_rule(&c, &ch, 1).unwrap();
        assert!(rule.name.ends_with("-curl"), "{}", rule.name);
        let op = rule.operator.unwrap();
        assert_eq!(op.list.len(), 2);
        assert_eq!(op.list[1].operand, "dest.network");
    }

    #[test]
    fn empty_operator_data_discards_rule() {
        let mut c = con();
        c.process_path.clear();
        let t = model::from_targets(&c);
        assert!(build_rule(&c, &choice(&t, 0), 1).is_none());
    }

    #[test]
    fn the_saved_target_keeps_its_shape_in_the_default_rule() {
        let c = con();
        let s = Settings {
            default_target: 3,
            ..Settings::default()
        };
        let op = default_rule(&c, &s, None, 1).unwrap().operator.unwrap();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str(), op.data.as_str()),
            ("simple", "dest.ip", "93.184.216.34")
        );
        let s = Settings {
            default_target: 0,
            ..Settings::default()
        };
        let op = default_rule(&c, &s, None, 1).unwrap().operator.unwrap();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str()),
            ("simple", "process.path")
        );
        let s = Settings {
            default_target: 0,
            advanced_dstip: true,
            ..Settings::default()
        };
        let op = default_rule(&c, &s, None, 1).unwrap().operator.unwrap();
        let operands: Vec<&str> = op.list.iter().map(|o| o.operand.as_str()).collect();
        assert_eq!(operands, ["dest.host", "process.path"]);
    }

    fn named(name: &str, action: &str) -> Rule {
        Rule {
            name: name.into(),
            action: action.into(),
            duration: "always".into(),
            operator: Some(Operator {
                r#type: "simple".into(),
                operand: "process.path".into(),
                data: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn free_names_are_kept() {
        let mut rule = named("allow-always-simple-curl", "allow");
        make_name_unique(&mut rule, &[named("other", "allow")], 100);
        assert_eq!(rule.name, "allow-always-simple-curl");
    }

    #[test]
    fn identical_rule_keeps_its_name() {
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &[named("a", "allow")], 100);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn taken_names_get_the_first_free_suffix() {
        let known = [
            named("a", "deny"),
            named("a-0", "deny"),
            named("a-1", "deny"),
        ];
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &known, 100);
        assert_eq!(rule.name, "a-2");
    }

    #[test]
    fn expired_rules_release_their_name() {
        let mut old = named("a", "deny");
        old.duration = "5m".into();
        old.created = 0;
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &[old], 1_000);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn gives_up_after_one_hundred_suffixes() {
        let mut known = vec![named("a", "deny")];
        known.extend((0..100).map(|i| named(&format!("a-{i}"), "deny")));
        let mut rule = named("a", "allow");
        make_name_unique(&mut rule, &known, 100);
        assert_eq!(rule.name, "a");
    }

    #[test]
    fn parses_durations() {
        assert_eq!(duration_secs("30s"), Some(30));
        assert_eq!(duration_secs("5m"), Some(300));
        assert_eq!(duration_secs("12h"), Some(43_200));
        assert_eq!(duration_secs("5\u{e9}"), None);
        assert_eq!(duration_secs("until restart"), None);
        assert_eq!(duration_secs("always"), None);
        assert_eq!(duration_secs(""), None);
    }

    #[test]
    fn drop_is_sent_as_deny() {
        assert_eq!(Action::from_index(0).as_rule_action(), "deny");
        assert_eq!(Action::from_index(2).as_rule_action(), "reject");
    }
}
