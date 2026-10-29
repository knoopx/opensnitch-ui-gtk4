
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use adw::prelude::*;
use gtk4 as gtk;
use gtk4::glib;
use libadwaita as adw;

use crate::link::Updater;
use crate::proto::{Operator, Rule};
use crate::rule::{self, DURATIONS};

pub const OPERANDS: [(&str, &str); 9] = [
    ("process.path", "Process path"),
    ("process.command", "Command line"),
    ("process.id", "Process id"),
    ("process.hash.md5", "Process checksum"),
    ("user.id", "User id"),
    ("dest.ip", "Destination IP"),
    ("dest.host", "Destination host"),
    ("dest.port", "Destination port"),
    ("dest.network", "Destination network"),
];

pub const KINDS: [(&str, &str); 3] = [
    ("simple", "is"),
    ("regexp", "matches"),
    ("network", "in network"),
];

pub const ACTIONS: [rule::Action; 3] = [
    rule::Action::Allow,
    rule::Action::Drop,
    rule::Action::Reject,
];

const OTHER: &str = "Other…";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clause {
    pub kind: String,
    pub operand: String,
    pub data: String,
}

impl Default for Clause {
    fn default() -> Self {
        Self {
            kind: KINDS[0].0.to_string(),
            operand: OPERANDS[0].0.to_string(),
            data: String::new(),
        }
    }
}

impl Clause {
    fn to_operator(&self) -> Operator {
        Operator {
            r#type: self.kind.clone(),
            operand: self.operand.clone(),
            data: self.data.clone(),
            sensitive: false,
            list: Vec::new(),
        }
    }

    fn is_usable(&self) -> bool {
        !self.data.trim().is_empty() && !self.operand.trim().is_empty()
    }
}

pub fn clauses(rule: &Rule) -> Vec<Clause> {
    fn gather(op: &Operator, out: &mut Vec<Clause>) {
        if op.list.is_empty() {
            out.push(Clause {
                kind: op.r#type.clone(),
                operand: op.operand.clone(),
                data: op.data.clone(),
            });
        } else {
            op.list.iter().for_each(|inner| gather(inner, out));
        }
    }

    let mut out = Vec::new();
    if let Some(op) = &rule.operator {
        gather(op, &mut out);
    }
    if out.is_empty() {
        out.push(Clause::default());
    }
    out
}

pub fn operator(clauses: &[Clause]) -> Option<Operator> {
    let kept: Vec<Operator> = clauses
        .iter()
        .filter(|c| c.is_usable())
        .map(Clause::to_operator)
        .collect();
    match kept.len() {
        0 => None,
        1 => kept.into_iter().next(),
        _ => Some(Operator {
            r#type: crate::model::kind::LIST.to_string(),
            operand: crate::model::kind::LIST.to_string(),
            list: kept,
            ..Default::default()
        }),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Form {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub precedence: bool,
    pub nolog: bool,
    pub action: usize,
    pub duration: usize,
    pub clauses: Vec<Clause>,
}

pub fn validate(form: &Form) -> Result<(), String> {
    if form.name.contains('/') {
        return Err("the rule name cannot contain '/'".into());
    }
    if form.clauses.iter().any(|c| !c.is_usable()) {
        return Err("every condition needs its field and its value".into());
    }
    if operator(&form.clauses).is_none() {
        return Err("select at least one condition".into());
    }
    Ok(())
}

pub fn auto_name(action: rule::Action, clauses: &[Clause]) -> String {
    let shape = if clauses.iter().filter(|c| c.is_usable()).count() > 1 {
        "list"
    } else {
        "simple"
    };
    let first = clauses
        .iter()
        .find(|c| c.is_usable())
        .map_or("", |c| c.data.as_str());
    rule::slugify(&format!("{} {shape} {first}", action.as_rule_action()))
}

pub fn build(form: &Form, known: &[Rule], original: Option<&Rule>, created: i64) -> Rule {
    let action = ACTIONS
        .get(form.action)
        .copied()
        .unwrap_or(rule::Action::Drop);
    let duration = DURATIONS
        .get(form.duration)
        .map_or("always", |(_, value)| *value);
    let name = if form.name.trim().is_empty() {
        auto_name(action, &form.clauses)
    } else {
        form.name.trim().to_string()
    };
    let mut made = Rule {
        created: original.map_or(created, |old| old.created),
        name,
        description: form.description.clone(),
        enabled: form.enabled,
        precedence: form.precedence,
        nolog: form.nolog,
        action: action.as_rule_action().to_string(),
        duration: duration.to_string(),
        operator: operator(&form.clauses),
    };
    rule::make_name_unique(&mut made, known, created);
    made
}

/// The rule the Delete button removes: the one already saved on the daemon,
/// never the name being typed in the form, so a half-finished rename can't
/// leave the old rule behind. A new rule has nothing to remove.
pub fn delete_target(original: Option<&Rule>) -> Option<&Rule> {
    original.filter(|rule| !rule.name.trim().is_empty())
}

pub fn form_of(rule: &Rule) -> Form {
    Form {
        name: rule.name.clone(),
        description: rule.description.clone(),
        enabled: rule.enabled,
        precedence: rule.precedence,
        nolog: rule.nolog,
        action: match rule.action.as_str() {
            "allow" => 0,
            "reject" => 2,
            _ => 1,
        },
        duration: DURATIONS
            .iter()
            .position(|(_, value)| *value == rule.duration)
            .unwrap_or(DURATIONS.len() - 1),
        clauses: clauses(rule),
    }
}

fn operand_index(operand: &str) -> usize {
    OPERANDS
        .iter()
        .position(|(name, _)| *name == operand)
        .unwrap_or(OPERANDS.len())
}

fn kind_index(kind: &str) -> usize {
    KINDS
        .iter()
        .position(|(name, _)| *name == kind)
        .unwrap_or(0)
}

fn seconds_of(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(0)
}

struct ClauseUi {
    row: gtk::ListBoxRow,
    operand: gtk::DropDown,
    custom: gtk::Entry,
    kind: gtk::DropDown,
    value: gtk::Entry,
    remove: gtk::Button,
}

impl ClauseUi {
    fn new(clause: &Clause) -> Self {
        let row = gtk::ListBoxRow::new();
        let box_ = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        box_.set_margin_top(6);
        box_.set_margin_bottom(6);
        box_.set_margin_start(6);
        box_.set_margin_end(6);

        let labels: Vec<&str> = OPERANDS
            .iter()
            .map(|(_, label)| *label)
            .chain(std::iter::once(OTHER))
            .collect();
        let operand = gtk::DropDown::from_strings(&labels);
        operand.set_selected(seconds_of(operand_index(&clause.operand)));

        let custom = gtk::Entry::new();
        custom.set_placeholder_text(Some("field, as the daemon names it"));
        custom.set_text(&clause.operand);
        custom.set_visible(operand_index(&clause.operand) == OPERANDS.len());
        custom.set_width_chars(14);

        let kinds: Vec<&str> = KINDS.iter().map(|(_, label)| *label).collect();
        let kind = gtk::DropDown::from_strings(&kinds);
        kind.set_selected(seconds_of(kind_index(&clause.kind)));

        let value = gtk::Entry::new();
        value.set_text(&clause.data);
        value.set_hexpand(true);
        value.set_placeholder_text(Some("value"));

        let remove = gtk::Button::from_icon_name("user-trash-symbolic");
        remove.set_tooltip_text(Some("Remove this condition"));

        box_.append(&operand);
        box_.append(&custom);
        box_.append(&kind);
        box_.append(&value);
        box_.append(&remove);
        row.set_child(Some(&box_));
        Self {
            row,
            operand,
            custom,
            kind,
            value,
            remove,
        }
    }

    fn mark_incomplete(&self, incomplete: bool) {
        if incomplete {
            self.value.add_css_class("error");
        } else {
            self.value.remove_css_class("error");
        }
    }

    fn clause(&self) -> Clause {
        let operand = match usize::try_from(self.operand.selected()) {
            Ok(index) if index < OPERANDS.len() => OPERANDS[index].0.to_string(),
            _ => self.custom.text().to_string(),
        };
        let kind = KINDS
            .get(usize::try_from(self.kind.selected()).unwrap_or(0))
            .map_or(KINDS[0].0, |(kind, _)| *kind)
            .to_string();
        Clause {
            kind,
            operand,
            data: self.value.text().to_string(),
        }
    }

    fn connect_changed(&self, changed: &Rc<dyn Fn()>) {
        for dropdown in [&self.operand, &self.kind] {
            let changed = changed.clone();
            dropdown.connect_selected_notify(move |_| changed());
        }
        for entry in [&self.value, &self.custom] {
            let changed = changed.clone();
            entry.connect_changed(move |_| changed());
        }
    }
}

fn field_row(title: &str, placeholder: Option<&str>, width: i32) -> (adw::ActionRow, gtk::Entry) {
    let row = adw::ActionRow::new();
    row.set_title(title);

    let entry = gtk::Entry::new();
    entry.set_placeholder_text(placeholder);
    entry.set_width_chars(width);
    entry.set_valign(gtk::Align::Center);
    row.set_activatable_widget(Some(&entry));
    row.add_suffix(&entry);

    (row, entry)
}

fn switch_row(title: &str, subtitle: Option<&str>) -> adw::SwitchRow {
    let row = adw::SwitchRow::new();
    row.set_title(title);
    if let Some(subtitle) = subtitle {
        row.set_subtitle(subtitle);
    }
    row
}

fn rule_group() -> (
    adw::PreferencesGroup,
    gtk::Entry,
    gtk::Entry,
    adw::SwitchRow,
    adw::SwitchRow,
    adw::SwitchRow,
) {
    let group = adw::PreferencesGroup::new();
    group.set_title("Rule");

    let (name_row, name) = field_row("Name", Some("empty means name it after the rule"), 30);
    let (description_row, description) = field_row("Description", None, 30);
    let enabled = switch_row("Enabled", None);
    enabled.set_active(true);
    let precedence = switch_row(
        "Overrides other rules",
        Some("This rule is checked before the others"),
    );
    let nolog = switch_row(
        "Do not log",
        Some("Connections it matches are left out of the log"),
    );

    group.add(&name_row);
    group.add(&description_row);
    group.add(&enabled);
    group.add(&precedence);
    group.add(&nolog);
    (group, name, description, enabled, precedence, nolog)
}

fn decision_group() -> (adw::PreferencesGroup, adw::ComboRow, adw::ComboRow) {
    let group = adw::PreferencesGroup::new();
    group.set_title("When it matches");

    let action = adw::ComboRow::new();
    action.set_title("Action");
    action.set_model(Some(&gtk::StringList::new(
        &ACTIONS.iter().map(|a| a.label()).collect::<Vec<_>>(),
    )));
    let duration = adw::ComboRow::new();
    duration.set_title("Duration");
    duration.set_model(Some(&gtk::StringList::new(
        &DURATIONS
            .iter()
            .map(|(label, _)| *label)
            .collect::<Vec<_>>(),
    )));

    group.add(&action);
    group.add(&duration);
    (group, action, duration)
}

fn conditions_group() -> (adw::PreferencesGroup, gtk::ListBox, gtk::Button) {
    let group = adw::PreferencesGroup::new();
    group.set_title("Conditions");

    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_selection_mode(gtk::SelectionMode::None);
    group.add(&list);

    let add = gtk::Button::with_label("Add condition");
    add.set_halign(gtk::Align::Start);
    add.set_margin_top(6);
    group.add(&add);
    (group, list, add)
}

fn header_bar(
    window: &adw::ApplicationWindow,
    existing: bool,
) -> (adw::HeaderBar, gtk::Button, Option<gtk::Button>) {
    let header = adw::HeaderBar::new();

    let cancel = gtk::Button::with_label("Cancel");
    let close = window.clone();
    cancel.connect_clicked(move |_| close.close());
    header.pack_start(&cancel);

    // Deleting is only possible for a rule the daemon already has. It sits with
    // Cancel, away from the suggested Save, so it can't be hit by accident.
    let remove = existing.then(|| {
        let remove = gtk::Button::with_label("Delete");
        remove.add_css_class("destructive-action");
        header.pack_start(&remove);
        remove
    });

    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    header.pack_end(&save);
    (header, save, remove)
}

struct Editor {
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    updater: Updater,
    original: Option<Rule>,
    name: gtk::Entry,
    description: gtk::Entry,
    enabled: adw::SwitchRow,
    precedence: adw::SwitchRow,
    nolog: adw::SwitchRow,
    action: adw::ComboRow,
    duration: adw::ComboRow,
    list: gtk::ListBox,
    clauses: Rc<RefCell<Vec<ClauseUi>>>,
    save: gtk::Button,
    delete: Option<gtk::Button>,
    saved: Rc<dyn Fn()>,
    deleted: Rc<dyn Fn(Rule)>,
}

thread_local! {
    static OPEN: RefCell<Vec<Rc<Editor>>> = const { RefCell::new(Vec::new()) };
}

impl Editor {
    fn new(
        app: &adw::Application,
        parent: &adw::ApplicationWindow,
        updater: Updater,
        existing: Option<&Rule>,
        saved: Rc<dyn Fn()>,
        deleted: Rc<dyn Fn(Rule)>,
    ) -> Rc<Self> {
        let window = adw::ApplicationWindow::new(app);
        window.set_title(Some(if existing.is_some() {
            "Edit rule"
        } else {
            "New rule"
        }));
        window.set_transient_for(Some(parent));
        window.set_modal(true);
        window.set_default_width(680);

        let keys = gtk::EventControllerKey::new();
        let dismissed = window.clone();
        keys.connect_key_pressed(move |_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                dismissed.close();
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        window.add_controller(keys);

        let toasts = adw::ToastOverlay::new();
        let view = adw::ToolbarView::new();
        let (header, save, remove) = header_bar(&window, existing.is_some());
        view.add_top_bar(&header);

        let page = adw::PreferencesPage::new();
        page.set_vexpand(true);

        let (general, name, description, enabled, precedence, nolog) = rule_group();
        let (decision, action, duration) = decision_group();
        let (conditions, list, add) = conditions_group();

        page.add(&general);
        page.add(&decision);
        page.add(&conditions);

        view.set_content(Some(&page));
        toasts.set_child(Some(&view));
        window.set_content(Some(&toasts));

        let editor = Rc::new(Self {
            window,
            toasts,
            updater,
            original: existing.cloned(),
            name,
            description,
            enabled,
            precedence,
            nolog,
            action,
            duration,
            list,
            clauses: Rc::new(RefCell::new(Vec::new())),
            save,
            delete: remove,
            saved,
            deleted,
        });

        let changed = editor.change_watcher();
        for entry in [&editor.name, &editor.description] {
            let changed = changed.clone();
            entry.connect_changed(move |_| changed());
        }

        if let Some(rule) = existing {
            editor.fill(rule);
        }
        for clause in existing.map_or_else(|| vec![Clause::default()], clauses) {
            editor.add_clause(&clause);
        }

        let editor_for_add = editor.clone();
        add.connect_clicked(move |_| editor_for_add.add_clause(&Clause::default()));
        let editor_for_save = editor.clone();
        editor.save.connect_clicked(move |_| editor_for_save.save());
        if let Some(remove) = editor.delete.clone() {
            let editor_for_delete = editor.clone();
            remove.connect_clicked(move |_| editor_for_delete.delete());
        }
        editor.show_state();
        editor
    }

    fn change_watcher(self: &Rc<Self>) -> Rc<dyn Fn()> {
        let editor = Rc::downgrade(self);
        Rc::new(move || {
            if let Some(editor) = editor.upgrade() {
                editor.show_state();
            }
        })
    }

    fn fill(&self, rule: &Rule) {
        let form = form_of(rule);
        self.name.set_text(&form.name);
        self.description.set_text(&form.description);
        self.enabled.set_active(form.enabled);
        self.precedence.set_active(form.precedence);
        self.nolog.set_active(form.nolog);
        self.action.set_selected(seconds_of(form.action));
        self.duration.set_selected(seconds_of(form.duration));
    }

    fn add_clause(self: &Rc<Self>, clause: &Clause) {
        let ui = ClauseUi::new(clause);
        let changed = self.change_watcher();
        ui.connect_changed(&changed);

        let list = self.list.clone();
        let row = ui.row.clone();
        let store = self.clauses.clone();
        let marked = self.change_watcher();
        ui.remove.connect_clicked(move |_| {
            list.remove(&row);
            store.borrow_mut().retain(|kept| kept.row != row);
            marked();
        });

        self.list.append(&ui.row);
        self.clauses.borrow_mut().push(ui);
    }

    fn form(&self) -> Form {
        Form {
            name: self.name.text().to_string(),
            description: self.description.text().to_string(),
            enabled: self.enabled.is_active(),
            precedence: self.precedence.is_active(),
            nolog: self.nolog.is_active(),
            action: usize::try_from(self.action.selected()).unwrap_or(0),
            duration: usize::try_from(self.duration.selected()).unwrap_or(0),
            clauses: self.clauses.borrow().iter().map(ClauseUi::clause).collect(),
        }
    }

    fn show_state(&self) {
        for clause in self.clauses.borrow().iter() {
            clause.mark_incomplete(!clause.clause().is_usable());
        }
        self.save.set_sensitive(validate(&self.form()).is_ok());
    }

    fn save(self: &Rc<Self>) {
        let form = self.form();
        if validate(&form).is_err() {
            return;
        }
        let known = self.updater.rules();
        let renamed = self
            .original
            .as_ref()
            .filter(|old| old.name != form.name.trim())
            .map(|old| old.name.clone());
        let made = build(&form, &known, self.original.as_ref(), now_secs());

        let editor = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = editor.updater.save_rule(made.clone()).await {
                editor.toast(&format!("{} was not saved: {err}", made.name));
                return;
            }
            if let Some(old) = renamed
                && let Err(err) = editor.updater.delete_rule(old.clone()).await
            {
                tracing::warn!("{old} was saved under a new name, but could not be removed: {err}");
                editor.toast("the rule was saved, but the old name is still there");
            }
            (editor.saved)();
            editor.toast(&format!("{} saved", made.name));
            editor.window.close();
        });
    }

    /// Removes the rule the editor was opened with, then closes: the list it
    /// came from gets the rule back for an undo.
    fn delete(self: &Rc<Self>) {
        let Some(rule) = delete_target(self.original.as_ref()).cloned() else {
            return;
        };
        let name = rule.name.clone();
        let editor = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = editor.updater.delete_rule(name.clone()).await {
                editor.toast(&format!("{name} was not deleted: {err}"));
                return;
            }
            (editor.deleted)(rule);
            editor.window.close();
        });
    }

    fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }
}

pub fn open(
    app: &adw::Application,
    parent: &adw::ApplicationWindow,
    updater: Updater,
    existing: Option<&Rule>,
    saved: Rc<dyn Fn()>,
    deleted: Rc<dyn Fn(Rule)>,
) {
    let editor = Editor::new(app, parent, updater, existing, saved, deleted);
    OPEN.with(|open| open.borrow_mut().push(editor.clone()));

    let gone = editor.window.clone();
    editor.window.connect_destroy(move |_| {
        OPEN.with(|open| {
            open.borrow_mut().retain(|kept| kept.window != gone);
        });
    });
    editor.window.present();
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause(operand: &str, data: &str) -> Clause {
        Clause {
            kind: "simple".into(),
            operand: operand.into(),
            data: data.into(),
        }
    }

    fn op(kind: &str, operand: &str, data: &str) -> Operator {
        Operator {
            r#type: kind.into(),
            operand: operand.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn saved(operator: Option<Operator>) -> Rule {
        Rule {
            name: "rule".into(),
            action: "allow".into(),
            duration: "5m".into(),
            created: 1234,
            enabled: true,
            precedence: true,
            nolog: true,
            description: "kept".into(),
            operator,
        }
    }

    #[test]
    fn a_saved_rule_reads_back_as_conditions() {
        let rule = saved(Some(Operator {
            r#type: "list".into(),
            operand: "list".into(),
            list: vec![
                op("simple", "process.path", "/usr/bin/curl"),
                op("regexp", "dest.host", "^.*\\.example\\.com$"),
            ],
            ..Default::default()
        }));
        let found = clauses(&rule);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].operand, "process.path");
        assert_eq!(
            (found[1].kind.as_str(), found[1].data.as_str()),
            ("regexp", "^.*\\.example\\.com$")
        );
    }

    #[test]
    fn a_rule_without_conditions_starts_with_a_blank_one() {
        let found = clauses(&saved(None));
        assert_eq!(found, vec![Clause::default()]);
    }

    #[test]
    fn nested_lists_are_flattened_for_editing() {
        let rule = saved(Some(Operator {
            r#type: "list".into(),
            operand: "list".into(),
            list: vec![
                op("simple", "dest.port", "443"),
                Operator {
                    r#type: "list".into(),
                    operand: "list".into(),
                    list: vec![op("simple", "user.id", "1000")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }));
        assert_eq!(
            clauses(&rule)
                .iter()
                .map(|c| c.operand.as_str())
                .collect::<Vec<_>>(),
            ["dest.port", "user.id"]
        );
    }

    #[test]
    fn one_condition_stays_a_plain_operator() {
        let one = operator(&[clause("process.path", "/bin/x")]).unwrap();
        assert_eq!(
            (one.r#type.as_str(), one.operand.as_str()),
            ("simple", "process.path")
        );
        let many =
            operator(&[clause("process.path", "/bin/x"), clause("dest.port", "443")]).unwrap();
        assert_eq!(many.r#type, "list");
        assert_eq!(many.list.len(), 2);
        assert!(operator(&[]).is_none());
        assert!(operator(&[Clause::default()]).is_none());
    }

    #[test]
    fn unusable_conditions_are_left_out() {
        let mixed = operator(&[
            clause("process.path", "/bin/x"),
            clause("dest.port", "   "),
            Clause {
                kind: "simple".into(),
                operand: String::new(),
                data: "x".into(),
            },
        ])
        .unwrap();
        assert_eq!(mixed.r#type, "simple");
        assert_eq!(mixed.data, "/bin/x");
    }

    #[test]
    fn the_form_refuses_names_and_conditions_that_cannot_be_stored() {
        let good = Form {
            name: "allow-curl".into(),
            clauses: vec![clause("process.path", "/usr/bin/curl")],
            ..Default::default()
        };
        assert_eq!(validate(&good), Ok(()));

        let slash = Form {
            name: "usr/bin/curl".into(),
            ..good.clone()
        };
        assert_eq!(
            validate(&slash).unwrap_err(),
            "the rule name cannot contain '/'"
        );

        let empty = Form {
            clauses: Vec::new(),
            ..good.clone()
        };
        assert_eq!(
            validate(&empty).unwrap_err(),
            "select at least one condition"
        );

        let blank_value = Form {
            clauses: vec![clause("process.path", "  ")],
            ..good
        };
        assert_eq!(
            validate(&blank_value).unwrap_err(),
            "every condition needs its field and its value"
        );
    }

    #[test]
    fn unnamed_rules_get_a_name_like_the_qt_ui() {
        assert_eq!(
            auto_name(
                rule::Action::Allow,
                &[clause("process.path", "/usr/bin/curl")]
            ),
            "allow-simple-usr-bin-curl"
        );
        assert_eq!(
            auto_name(
                rule::Action::Drop,
                &[
                    clause("process.path", "/usr/bin/curl"),
                    clause("dest.port", "443")
                ]
            ),
            "deny-list-usr-bin-curl"
        );
        assert_eq!(auto_name(rule::Action::Allow, &[]), "allow-simple");
    }

    #[test]
    fn the_rule_takes_the_fields_of_the_form() {
        let form = Form {
            name: "  my rule ".into(),
            description: "because".into(),
            enabled: false,
            precedence: true,
            nolog: true,
            action: 1,
            duration: 2,
            clauses: vec![
                clause("process.path", "/usr/bin/curl"),
                clause("dest.port", "443"),
            ],
        };
        let made = build(&form, &[], None, 99);
        assert_eq!(made.name, "my rule");
        assert_eq!(made.description, "because");
        assert!(!made.enabled);
        assert!(made.precedence && made.nolog);
        assert_eq!(
            (made.action.as_str(), made.duration.as_str()),
            ("deny", "5m")
        );
        assert_eq!(made.created, 99);
        assert_eq!(made.operator.unwrap().list.len(), 2);
    }

    #[test]
    fn an_empty_name_is_filled_from_the_conditions() {
        let form = Form {
            clauses: vec![clause("process.path", "/usr/bin/curl")],
            ..Default::default()
        };
        assert_eq!(build(&form, &[], None, 1).name, "allow-simple-usr-bin-curl");
    }

    #[test]
    fn editing_keeps_the_moment_the_rule_was_made() {
        let old = saved(Some(op("simple", "process.path", "/bin/x")));
        let made = build(&form_of(&old), &[], Some(&old), 99);
        assert_eq!(made.created, 1234, "a 5m rule's clock is not restarted");
        assert_eq!(made.name, "rule");
        assert_eq!(
            (made.action.as_str(), made.duration.as_str()),
            ("allow", "5m")
        );
        assert!(made.precedence && made.nolog && made.enabled);
        assert_eq!(made.description, "kept");
    }

    #[test]
    fn an_existing_name_is_not_stolen() {
        let taken = vec![saved(Some(op("simple", "process.path", "/bin/y")))];
        let form = Form {
            name: "rule".into(),
            clauses: vec![clause("process.path", "/bin/x")],
            ..Default::default()
        };
        assert_eq!(build(&form, &taken, None, 1).name, "rule-0");
    }

    #[test]
    fn the_form_of_a_rule_round_trips() {
        let rule = saved(Some(op("simple", "process.path", "/bin/x")));
        let form = form_of(&rule);
        assert_eq!(form.name, "rule");
        assert_eq!(form.description, "kept");
        assert!(form.enabled, "the switches keep their state");
        assert!(form.nolog);
        assert_eq!(form.duration, 2, "5m");
        assert_eq!(form.action, 0, "allow is first");
        assert_eq!(form.clauses, vec![clause("process.path", "/bin/x")]);

        let unknown = Rule {
            duration: "2 weeks".into(),
            ..saved(None)
        };
        assert_eq!(
            form_of(&unknown).duration,
            DURATIONS.len() - 1,
            "a duration the daemon invented reads as forever"
        );
    }

    #[test]
    fn foreign_operands_fall_to_the_other_entry() {
        assert_eq!(operand_index("dest.mac"), OPERANDS.len());
        assert_eq!(operand_index("process.path"), 0);
        assert_eq!(kind_index("regexp"), 1);
        assert_eq!(kind_index("nonsense"), 0);
    }

    #[test]
    fn delete_removes_the_saved_rule_not_the_one_being_typed() {
        let rule = saved(Some(op("simple", "process.path", "/bin/x")));
        assert_eq!(
            delete_target(Some(&rule)).map(|rule| rule.name.as_str()),
            Some("rule")
        );

        let renamed = Rule {
            name: "brand new".into(),
            ..rule.clone()
        };
        let form = form_of(&renamed);
        assert_eq!(form.name, "brand new");
        assert_eq!(
            delete_target(Some(&rule)).map(|rule| rule.name.as_str()),
            Some("rule"),
            "the old name is what the daemon still has"
        );
    }

    #[test]
    fn a_new_or_nameless_rule_has_nothing_to_delete() {
        assert!(
            delete_target(None).is_none(),
            "the New rule dialog has no Delete button"
        );
        let nameless = Rule {
            name: "  ".into(),
            ..saved(None)
        };
        assert!(delete_target(Some(&nameless)).is_none());
    }

    #[test]
    fn the_action_order_matches_the_qt_editor() {
        assert_eq!(
            ACTIONS.iter().map(|a| a.label()).collect::<Vec<_>>(),
            ["Allow", "Drop", "Reject"]
        );
    }
}
