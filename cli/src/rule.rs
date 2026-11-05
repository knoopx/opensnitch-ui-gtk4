//! The rule as opensnitchd keeps it: the same JSON that lands in its rules
//! directory, and the same tree of conditions that goes over the wire.

use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::proto::{Operator, Rule};

pub const ACTIONS: [&str; 3] = ["allow", "deny", "reject"];

/// The durations opensnitchd accepts: three of its own, and anything
/// `time.ParseDuration()` reads, which is what a temporary rule is scheduled by
/// (daemon/rule/loader.go: `scheduleTemporaryRule`).
pub const DURATIONS: [&str; 9] = [
    "once",
    "30s",
    "5m",
    "15m",
    "30m",
    "1h",
    "12h",
    "until restart",
    "always",
];

pub const KINDS: [&str; 4] = ["simple", "regexp", "network", "list"];

pub const OPERANDS: [&str; 10] = [
    "true",
    "process.path",
    "process.command",
    "process.id",
    "process.hash.md5",
    "process.hash.sha256",
    "user.id",
    "dest.ip",
    "dest.host",
    "dest.port",
];

/// A rule that matches every connection, the answer to `AskRule` when nobody is
/// asked. opensnitchd's own stand-in (`dummyOperator`) is this one.
pub fn always_operator() -> Operator {
    Operator {
        r#type: "simple".into(),
        operand: "true".into(),
        data: String::new(),
        sensitive: false,
        list: Vec::new(),
    }
}

pub fn json(rules: &[Rule]) -> Value {
    Value::Array(rules.iter().map(rule_json).collect())
}

fn rule_json(rule: &Rule) -> Value {
    let mut out = Map::new();
    out.insert("created".into(), Value::String(epoch_rfc3339(rule.created)));
    out.insert("name".into(), rule.name.clone().into());
    out.insert("description".into(), rule.description.clone().into());
    out.insert("enabled".into(), rule.enabled.into());
    out.insert("precedence".into(), rule.precedence.into());
    out.insert("nolog".into(), rule.nolog.into());
    out.insert("action".into(), rule.action.clone().into());
    out.insert("duration".into(), rule.duration.clone().into());
    out.insert("operator".into(), operator_json(rule.operator.as_ref()));
    Value::Object(out)
}

fn operator_json(op: Option<&Operator>) -> Value {
    let empty = Operator::default();
    let op = op.unwrap_or(&empty);
    let mut out = Map::new();
    out.insert("type".into(), op.r#type.clone().into());
    out.insert("operand".into(), op.operand.clone().into());
    out.insert("data".into(), op.data.clone().into());
    out.insert("sensitive".into(), op.sensitive.into());
    out.insert(
        "list".into(),
        Value::Array(
            op.list
                .iter()
                .map(|nested| operator_json(Some(nested)))
                .collect(),
        ),
    );
    Value::Object(out)
}

/// A rule from opensnitchd's JSON.
///
/// The defaults are the ones opensnitchd itself fills in: enabled, not checked
/// before the others, kept in the log, forever.
pub fn from_json(value: &Value) -> Result<Rule, String> {
    let map = value
        .as_object()
        .ok_or("a rule has to be a JSON object, not a list of them")?;
    let name = text(map, "name").ok_or("a rule needs a \"name\"")?;
    let action = text(map, "action").unwrap_or_else(|| "deny".into());
    if !ACTIONS.contains(&action.as_str()) {
        return Err(format!(
            "rule {name}: action '{action}' is not one of {}",
            ACTIONS.join(", ")
        ));
    }
    let duration = text(map, "duration").unwrap_or_else(|| "always".into());
    if !known_duration(&duration) {
        return Err(format!(
            "rule {name}: duration '{duration}' is not one of {}, or a Go duration like \"45m\"",
            DURATIONS.join(", ")
        ));
    }
    let enabled = bool_of(map, "enabled", true);
    let precedence = bool_of(map, "precedence", false);
    let nolog = bool_of(map, "nolog", false);
    let created = match text(map, "created") {
        None => now_secs(),
        Some(text) => rfc3339_secs(&text).ok_or(format!(
            "rule {name}: created '{text}' is not a time opensnitchd writes (RFC3339, \
             like \"2026-11-05T21:00:00Z\")"
        ))?,
    };
    let operator = operator_from(map.get("operator"), &name)?;
    Ok(Rule {
        created,
        name,
        description: text(map, "description").unwrap_or_default(),
        enabled,
        precedence,
        nolog,
        action,
        duration,
        operator: Some(operator),
    })
}

/// Rules from a file: one object, a list of them, or `{"rules": [...]}`.
pub fn from_json_text(text: &str) -> Result<Vec<Rule>, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|err| format!("the JSON does not parse: {err}"))?;
    let items: Vec<&Value> = match &value {
        Value::Object(map) if map.get("rules").is_some_and(|rules| rules.is_array()) => {
            map["rules"]
                .as_array()
                .map_or(vec![], |a| a.iter().collect())
        }
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    if items.is_empty() {
        return Err("the JSON holds no rule".into());
    }
    items.iter().map(|item| from_json(item)).collect()
}

fn operator_from(value: Option<&Value>, name: &str) -> Result<Operator, String> {
    let map = value
        .and_then(Value::as_object)
        .ok_or(format!("rule {name}: needs an \"operator\" object"))?;
    let kind = text(map, "type").ok_or(format!("rule {name}: the operator needs a \"type\""))?;
    if !KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "rule {name}: operator type '{kind}' is not one of {}",
            KINDS.join(", ")
        ));
    }
    let operand = text(map, "operand").unwrap_or_default();
    let data = text(map, "data").unwrap_or_default();
    let list = map
        .get("list")
        .and_then(Value::as_array)
        .map(|items| items.iter().cloned())
        .unwrap_or_default()
        .collect::<Vec<_>>();
    let nested = list
        .iter()
        .map(|item| {
            let as_object = Value::Object(
                item.as_object()
                    .cloned()
                    .ok_or("an entry of the operator list has to be an object")?
                    .into_iter()
                    .collect(),
            );
            operator_from(Some(&as_object), name)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if kind == "list" {
        if nested.is_empty() {
            return Err(format!(
                "rule {name}: an operator of type \"list\" needs entries in \"list\""
            ));
        }
    } else {
        if operand.is_empty() {
            return Err(format!(
                "rule {name}: the operator needs an \"operand\" (like \"process.path\")"
            ));
        }
        if data.is_empty() && operand != "true" {
            return Err(format!(
                "rule {name}: the operator on {operand} needs a \"data\" value"
            ));
        }
    }
    Ok(Operator {
        r#type: kind,
        operand,
        data,
        sensitive: bool_of(map, "sensitive", false),
        list: nested,
    })
}

fn text(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn bool_of(map: &Map<String, Value>, key: &str, when_missing: bool) -> bool {
    map.get(key)
        .and_then(Value::as_bool)
        .unwrap_or(when_missing)
}

/// The conditions of a rule on one line: `process.path=/usr/bin/curl &&
/// dest.port=443`.
pub fn conditions(rule: &Rule) -> String {
    match rule.operator.as_ref() {
        None => String::from("(no condition)"),
        Some(op) => operator_text(op),
    }
}

fn operator_text(op: &Operator) -> String {
    if op.r#type == "list" {
        let parts: Vec<String> = op.list.iter().map(operator_text).collect();
        return parts.join(" && ");
    }
    let matcher = match op.r#type.as_str() {
        "regexp" => "~",
        "network" => " in ",
        _ => "=",
    };
    format!("{}{matcher}{}", op.operand, op.data)
}

pub fn table(rules: &[Rule]) -> String {
    // The state column carries the marks themselves, so its header is the mark of
    // the rules that are filtering.
    let head = ["on", "NAME", "ACTION", "DURATION", "CONDITIONS", "CREATED"];
    fn enabled_mark(rule: &Rule) -> &'static str {
        if rule.enabled { "on" } else { "off" }
    }
    let rows: Vec<[String; 6]> = rules
        .iter()
        .map(|rule| {
            [
                enabled_mark(rule).to_string(),
                rule.name.clone(),
                rule.action.clone(),
                rule.duration.clone(),
                conditions(rule),
                epoch_rfc3339(rule.created),
            ]
        })
        .collect();
    let mut widths = head.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    write_row(&mut out, &head, &widths);
    for row in &rows {
        write_row(&mut out, &row.each_ref().map(String::as_str), &widths);
    }
    out
}

fn write_row(out: &mut String, cells: &[&str], widths: &[usize]) {
    let last = cells.len() - 1;
    for (idx, cell) in cells.iter().enumerate() {
        if idx == last {
            let _ = write!(out, "{cell}");
        } else {
            let _ = write!(out, "{:<width$}  ", cell, width = widths[idx]);
        }
    }
    out.push('\n');
}

pub fn summary(rule: &Rule) -> String {
    format!(
        "{} {} {} ({})",
        rule.name,
        rule.action,
        rule.duration,
        conditions(rule)
    )
}

/// Rules whose name, description, action, duration, condition, or kind of
/// matcher holds `query`, case-insensitively.
pub fn filter(rules: &[Rule], query: &str) -> Vec<Rule> {
    let query = query.to_lowercase();
    rules
        .iter()
        .filter(|rule| haystack(rule).contains(&query))
        .cloned()
        .collect()
}

/// The words a filter is allowed to find: the rule's own text, its conditions as
/// they read, and the kinds of its matchers, so "regexp" finds the rule matched
/// by a regular expression.
fn haystack(rule: &Rule) -> String {
    let mut parts = vec![
        rule.name.clone(),
        rule.description.clone(),
        rule.action.clone(),
        rule.duration.clone(),
        conditions(rule),
    ];
    if let Some(op) = rule.operator.as_ref() {
        parts.extend(operator_kinds(op));
    }
    parts.join("\n").to_lowercase()
}

fn operator_kinds(op: &Operator) -> Vec<String> {
    let mut kinds = vec![op.r#type.clone()];
    for nested in &op.list {
        kinds.extend(operator_kinds(nested));
    }
    kinds
}

pub fn sort_by_name(rules: &mut [Rule]) {
    rules.sort_by(|a, b| a.name.cmp(&b.name));
}

pub fn known_duration(duration: &str) -> bool {
    if DURATIONS.contains(&duration) {
        return true;
    }
    go_duration(duration)
}

/// What Go's `time.ParseDuration` accepts: a run of number+unit pairs out of
/// `ns, us, µs, ms, s, m, h`. "until restart", "once" and "always" are handled
/// by the caller, before this is reached.
fn go_duration(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    if chars.peek() == Some(&'-') || chars.peek() == Some(&'+') {
        chars.next();
    }
    let mut seen = false;
    while chars.peek().is_some() {
        let mut digits = String::new();
        while chars.peek().is_some_and(char::is_ascii_digit) {
            digits.push(chars.next().unwrap());
        }
        if digits.is_empty() {
            return false;
        }
        let mut unit = String::new();
        while chars
            .peek()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == 'µ' || *c == 's')
        {
            unit.push(chars.next().unwrap());
        }
        if !["ns", "us", "µs", "ms", "s", "m", "h"].contains(&unit.as_str()) {
            return false;
        }
        seen = true;
    }
    seen
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// opensnitchd stores `created` as an RFC3339 string on disk and as unix seconds
/// on the wire (daemon/rule/rule.go: `Serialize`).
pub fn epoch_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The same time as opensnitchd writes it: RFC3339, with an offset or `Z`, and
/// with the fractional seconds the daemon's `time.Now()` leaves in.
pub fn rfc3339_secs(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(['T', 't', ' '])?;
    let mut parts = date.split('-').map(|part| part.parse::<i64>().ok());
    let (Some(year), Some(month), Some(day)) = (parts.next()?, parts.next()?, parts.next()?) else {
        return None;
    };
    if parts.next().is_some() {
        return None;
    }
    let (time, zone) = split_zone(rest);
    // The daemon's `time.Now()` leaves nanoseconds behind the seconds; only whole
    // seconds reach the wire, where `created` is a count of them.
    let time = time.split('.').next().unwrap_or(time);
    let mut numbers = time.split(':').map(|part| part.parse::<i64>().ok());
    let (Some(hour), Some(minute)) = (numbers.next()?, numbers.next()?) else {
        return None;
    };
    let second = numbers.next().unwrap_or(Some(0))?;
    if numbers.next().is_some() {
        return None;
    }
    let offset = match zone {
        "" | "Z" | "z" => 0,
        zone => zone_offset(zone)?,
    };
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

fn split_zone(rest: &str) -> (&str, &str) {
    let bytes = rest.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        if idx > 0 && (*byte == b'Z' || *byte == b'z' || *byte == b'+' || *byte == b'-') {
            return (&rest[..idx], &rest[idx..]);
        }
    }
    (rest, "")
}

fn zone_offset(text: &str) -> Option<i64> {
    let (sign, rest) = text.split_at(1);
    let (hours, minutes) = match rest.split_once(':') {
        Some((h, m)) => (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?),
        None if rest.len() == 4 => (rest[..2].parse().ok()?, rest[2..].parse().ok()?),
        None => (rest.parse::<i64>().ok()?, 0),
    };
    let secs = hours * 3600 + minutes * 60;
    Some(if sign == "-" { -secs } else { secs })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // January and February belong to the year before, whose leap day they follow.
    let year = year - i64::from(month <= 2);
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Operator;

    fn op(kind: &str, operand: &str, data: &str) -> Operator {
        Operator {
            r#type: kind.into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn rule() -> Rule {
        Rule {
            created: 1_607_879_192,
            name: "block-curl".into(),
            description: "no curl out".into(),
            enabled: true,
            precedence: false,
            nolog: false,
            action: "deny".into(),
            duration: "always".into(),
            operator: Some(Operator {
                r#type: "list".into(),
                operand: "list".into(),
                list: vec![
                    op("simple", "process.path", "/usr/bin/curl"),
                    op("regexp", "dest.host", r".*\.example\.com"),
                ],
                ..Default::default()
            }),
        }
    }

    #[test]
    fn the_json_is_the_shape_of_the_file_on_disk() {
        let value = rule_json(&rule());
        assert_eq!(value["name"], "block-curl");
        assert_eq!(value["action"], "deny");
        assert_eq!(value["duration"], "always");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["created"], "2020-12-13T17:06:32Z");
        assert_eq!(value["operator"]["type"], "list");
        assert_eq!(value["operator"]["list"][0]["operand"], "process.path");
        assert_eq!(value["operator"]["list"][0]["data"], "/usr/bin/curl");
        assert_eq!(
            value["operator"]["list"][0]["list"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn a_rule_read_from_json_is_the_rule_sent_to_the_daemon() {
        let text = r#"{
            "created": "2020-12-13T18:06:52.209804547+01:00",
            "name": "001-deny-chrome",
            "enabled": true,
            "precedence": true,
            "action": "deny",
            "duration": "always",
            "operator": {"type": "simple", "operand": "process.path", "data": "/opt/google/chrome/chrome"}
        }"#;
        let rules = from_json_text(text).unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.name, "001-deny-chrome");
        assert_eq!(rule.action, "deny");
        assert!(rule.precedence);
        assert!(!rule.nolog);
        assert_eq!(rule.created, 1_607_879_212);
        assert_eq!(rule.operator.as_ref().unwrap().operand, "process.path");
    }

    #[test]
    fn a_missing_action_and_duration_take_the_daemons_own_defaults() {
        let rule = from_json(&serde_json::json!({
            "name": "n",
            "operator": {"type": "simple", "operand": "dest.port", "data": "53"}
        }))
        .unwrap();
        assert_eq!(
            (rule.action.as_str(), rule.duration.as_str()),
            ("deny", "always")
        );
        assert!(rule.enabled);
        assert_eq!(rule.description, "");
    }

    #[test]
    fn a_file_may_hold_one_rule_a_list_or_a_rules_key() {
        let one = r#"{"name":"a","operator":{"type":"simple","operand":"true"}}"#;
        let list = format!(
            "[{one},{{\"name\":\"b\",\"operator\":{{\"type\":\"simple\",\"operand\":\"true\"}}}}]"
        );
        let wrapped = format!("{{\"rules\":[{one}]}}");
        assert_eq!(from_json_text(one).unwrap().len(), 1);
        assert_eq!(from_json_text(&list).unwrap().len(), 2);
        assert_eq!(from_json_text(&wrapped).unwrap().len(), 1);
        assert_eq!(from_json_text(&list).unwrap()[1].name, "b");
    }

    #[test]
    fn a_rule_without_what_the_daemon_needs_is_refused_before_it_is_sent() {
        let no_name = from_json(&serde_json::json!({"action": "allow"}));
        assert!(no_name.unwrap_err().contains("name"));

        let bad_action = from_json(&serde_json::json!({
            "name": "a", "action": "block",
            "operator": {"type": "simple", "operand": "true"}
        }));
        assert!(bad_action.unwrap_err().contains("action"));

        let bad_duration = from_json(&serde_json::json!({
            "name": "a", "duration": "a fortnight",
            "operator": {"type": "simple", "operand": "true"}
        }));
        assert!(bad_duration.unwrap_err().contains("duration"));

        let list_without_entries = from_json(&serde_json::json!({
            "name": "a", "operator": {"type": "list", "list": []}
        }));
        assert!(list_without_entries.unwrap_err().contains("list"));

        let simple_without_data = from_json(&serde_json::json!({
            "name": "a", "operator": {"type": "simple", "operand": "dest.port", "data": ""}
        }));
        assert!(simple_without_data.unwrap_err().contains("data"));

        let bad_created = from_json(&serde_json::json!({
            "name": "a", "created": "last tuesday",
            "operator": {"type": "simple", "operand": "true"}
        }));
        assert!(bad_created.unwrap_err().contains("created"));
    }

    #[test]
    fn the_conditions_of_a_rule_read_like_the_rule_itself() {
        assert_eq!(
            conditions(&rule()),
            "process.path=/usr/bin/curl && dest.host~.*\\.example\\.com"
        );
        let network = Rule {
            operator: Some(op("network", "dest.network", "192.168.0.0/16")),
            ..rule()
        };
        assert_eq!(conditions(&network), "dest.network in 192.168.0.0/16");
        assert_eq!(conditions(&Rule::default()), "(no condition)");
    }

    #[test]
    fn the_table_lines_the_columns_up() {
        let text = table(&[rule()]);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0].split("  ").next(), Some("on"));
        assert!(lines[1].contains("block-curl"));
        assert!(lines[1].contains("2020-12-13T17:06:32Z"));
        assert!(lines[1].find("block-curl").unwrap() < lines[1].find("deny").unwrap());
    }

    #[test]
    fn the_seconds_of_a_time_the_daemon_writes() {
        assert_eq!(rfc3339_secs("2020-12-13T17:06:32Z"), Some(1_607_879_192));
        assert_eq!(
            rfc3339_secs("2020-12-13T18:06:52.209804547+01:00"),
            Some(1_607_879_212)
        );
        // 18:06:52 at UTC-1 is 19:06:52 in the morning, by the Greenwich meridian.
        assert_eq!(
            rfc3339_secs("2020-12-13T18:06:52-0100"),
            Some(1_607_886_412)
        );
        assert_eq!(rfc3339_secs("2026-11-05T00:00:00Z"), Some(1_793_836_800));
        assert_eq!(rfc3339_secs("2020-12-13 17:06:32Z"), Some(1_607_879_192));
        assert_eq!(rfc3339_secs("last tuesday"), None);
        assert_eq!(rfc3339_secs("2020-12-13T17:06:32Q"), None);
    }

    #[test]
    fn the_time_the_daemon_writes_comes_out_of_the_seconds() {
        assert_eq!(epoch_rfc3339(1_607_879_192), "2020-12-13T17:06:32Z");
        assert_eq!(epoch_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_rfc3339(1_793_836_800), "2026-11-05T00:00:00Z");
        assert_eq!(epoch_rfc3339(-86_400), "1969-12-31T00:00:00Z");
        let round = |secs| rfc3339_secs(&epoch_rfc3339(secs)) == Some(secs);
        assert!(round(1_607_879_192) && round(0) && round(1_793_836_800) && round(9_999_999_999));
    }

    #[test]
    fn a_duration_is_one_of_the_daemons_or_something_it_can_time() {
        for duration in [
            "once",
            "always",
            "until restart",
            "30s",
            "5m",
            "12h",
            "1h30m",
            "500ms",
            "2h15m30s",
        ] {
            assert!(known_duration(duration), "{duration}");
        }
        for duration in ["", "fortnight", "30", "s", "10 days", "1d"] {
            assert!(!known_duration(duration), "{duration}");
        }
    }

    #[test]
    fn the_filter_looks_everywhere_in_the_rule() {
        let rules = [rule()];
        assert_eq!(filter(&rules, "curl").len(), 1);
        assert_eq!(filter(&rules, "REGEX").len(), 1);
        assert_eq!(filter(&rules, "no curl out").len(), 1);
        assert_eq!(filter(&rules, "deny").len(), 1);
        assert_eq!(filter(&rules, "CHROME").len(), 0);
    }

    #[test]
    fn sorting_is_by_name_so_the_list_is_stable() {
        let mut rules = vec![
            Rule {
                name: "b".into(),
                ..Default::default()
            },
            Rule {
                name: "a".into(),
                ..Default::default()
            },
        ];
        sort_by_name(&mut rules);
        assert_eq!((rules[0].name.as_str(), rules[1].name.as_str()), ("a", "b"));
    }

    #[test]
    fn the_answer_to_an_unasked_connection_is_the_operators_true() {
        let op = always_operator();
        assert_eq!(
            (op.r#type.as_str(), op.operand.as_str()),
            ("simple", "true")
        );
    }
}
