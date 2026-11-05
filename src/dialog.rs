use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use adw::prelude::*;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;

use crate::checksum::{self, Mismatch};
use crate::link::{Outcome, Updater};
use crate::model::{self, Target};
use crate::proto::{Connection, Rule};
use crate::rule::{self, Action, Choice, DURATIONS};
use crate::settings::Settings;
use crate::view;

const WIDTH: i32 = 540;

pub struct Checks {
    pub mismatch: Mismatch,
    pub updater: Updater,
}

#[derive(Debug, Default)]
pub struct Answer {
    pub rule: Option<Rule>,
    pub timed_out: bool,
}

pub async fn prompt(
    app: &adw::Application,
    con: Connection,
    settings: Settings,
    checks: Checks,
    cancelled: impl Fn() -> bool + 'static,
) -> Answer {
    if settings.popups_disabled() {
        return Answer {
            rule: rule::default_rule(&con, &settings, None, now_secs()),
            timed_out: true,
        };
    }
    let (result, answer) = async_channel::bounded(1);
    let dialog = Dialog::new(app, con, settings, checks, result);
    dialog.start(cancelled);
    answer.recv().await.unwrap_or_default()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn desktop_info(path: &str) -> Option<gtk::gio::AppInfo> {
    if path.is_empty() {
        return None;
    }
    let wanted = Path::new(path);
    gtk::gio::AppInfo::all()
        .into_iter()
        .find(|app| view::same_program(&app.executable(), wanted))
}

fn label(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.set_wrap(true);
    l
}

fn any_active(rows: [&gtk::Switch; 5]) -> bool {
    rows.into_iter().any(|c| c.is_active())
}

#[derive(Clone)]
struct ChecksumsUi {
    names: gtk::DropDown,
    status: gtk::Label,
    buttons: gtk::Box,
    update: gtk::Button,
    update_all: gtk::Button,
}

fn list_names(dd: &gtk::DropDown) -> Vec<String> {
    let Some(model) = dd.model() else {
        return Vec::new();
    };
    (0..model.n_items())
        .filter_map(|i| model.item(i).and_downcast::<gtk::StringObject>())
        .map(|s| s.string().to_string())
        .collect()
}

fn selected_name(dd: &gtk::DropDown) -> Option<String> {
    dd.selected_item()
        .and_downcast::<gtk::StringObject>()
        .map(|s| s.string().to_string())
}

fn remove_names(dd: &gtk::DropDown, names: &[String]) {
    let Some(list) = dd.model().and_downcast::<gtk::StringList>() else {
        return;
    };
    for name in names {
        let position = (0..list.n_items()).find(|&i| list.string(i).as_deref() == Some(name));
        if let Some(position) = position {
            list.remove(position);
        }
    }
}

fn name_dropdown(names: &[String]) -> gtk::DropDown {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let dd = gtk::DropDown::from_strings(&names);
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let l = label("");
        l.set_wrap(false);
        l.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        l.set_max_width_chars(44);
        item.set_child(Some(&l));
    });
    factory.connect_bind(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let text = item
            .item()
            .and_downcast::<gtk::StringObject>()
            .map(|s| s.string());
        if let (Some(text), Some(l)) = (text, item.child().and_downcast::<gtk::Label>()) {
            l.set_text(&text);
        }
    });
    dd.set_factory(Some(&factory));
    dd.set_hexpand(true);
    dd
}

fn combo(labels: &[&str]) -> adw::ComboRow {
    let row = adw::ComboRow::new();
    row.set_model(Some(&gtk::StringList::new(labels)));
    row
}

fn target_combo(targets: &[Target]) -> adw::ComboRow {
    let labels: Vec<&str> = targets.iter().map(|t| t.label.as_str()).collect();
    combo(&labels)
}

fn clause_switch() -> gtk::Switch {
    let switch = gtk::Switch::new();
    switch.set_valign(gtk::Align::Center);
    switch
}

fn info_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder().title(title).build();
    let value = gtk::Label::new(Some(value));
    value.set_hexpand(true);
    value.set_xalign(1.0);
    value.set_valign(gtk::Align::Center);
    value.set_wrap(true);
    value.set_selectable(true);
    value.add_css_class("dim-label");
    row.add_suffix(&value);
    row
}

fn guarded_row(title: &str, value: &str, on: &gtk::Switch) -> adw::ActionRow {
    let row = info_row(title, value);
    row.add_suffix(on);
    row
}

fn page(
    header: &adw::HeaderBar,
    content: &impl IsA<gtk::Widget>,
    actions: Option<&impl IsA<gtk::Widget>>,
) -> adw::ToolbarView {
    let view = adw::ToolbarView::new();
    view.add_top_bar(header);
    view.set_content(Some(content));
    if let Some(actions) = actions {
        view.add_bottom_bar(actions);
    }
    view
}

fn sub_header(dialog: &Rc<Dialog>, title: &str) -> adw::HeaderBar {
    let bar = adw::HeaderBar::new();
    bar.set_title_widget(Some(&adw::WindowTitle::new(title, "")));
    let back = gtk::Button::with_label("Back");
    back.set_valign(gtk::Align::Center);
    let stack = dialog.stack.clone();
    back.connect_clicked(move |_| stack.set_visible_child_name("main"));
    bar.pack_start(&back);
    bar
}

fn button_row(buttons: &[&gtk::Widget]) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    row.set_halign(gtk::Align::Center);
    row.set_margin_top(10);
    row.set_margin_bottom(10);
    for b in buttons {
        row.append(*b);
    }
    row
}

struct Dialog {
    window: adw::ApplicationWindow,
    stack: gtk::Stack,
    con: Connection,
    from: Vec<Target>,
    ip: Vec<Target>,
    checksum: String,
    from_dd: adw::ComboRow,
    ip_dd: adw::ComboRow,
    duration_dd: adw::ComboRow,
    check_from: gtk::Switch,
    check_ip: gtk::Switch,
    check_port: gtk::Switch,
    check_uid: gtk::Switch,
    check_sum: gtk::Switch,
    checks: Checks,
    allow_btn: gtk::Button,
    deny_btn: adw::SplitButton,
    default_action: Action,
    remaining: Cell<u32>,
    timeout: u32,
    counting: Cell<bool>,
    done: Cell<bool>,
    result: async_channel::Sender<Answer>,
    timed_out: Cell<bool>,
    warning: RefCell<Option<adw::ActionRow>>,
}

impl Dialog {
    fn new(
        app: &adw::Application,
        con: Connection,
        settings: Settings,
        checks: Checks,
        result: async_channel::Sender<Answer>,
    ) -> Rc<Self> {
        let info = desktop_info(&con.process_path);
        let app_name = view::app_name(info.as_ref().map(|i| i.display_name()).as_deref(), &con);
        let user = view::user_label(con.user_id, view::user_name(con.user_id).as_deref());

        let from: Vec<Target> = model::from_targets(&con)
            .into_iter()
            .filter(|t| t.enabled)
            .collect();
        let ip = model::ip_targets(&con);
        let plan = model::default_plan(&from, &ip, &con, settings.default_target);

        let from_dd = target_combo(&from);
        from_dd.set_selected(u32::try_from(plan.from.unwrap_or(0)).unwrap_or(0));
        let ip_dd = target_combo(&ip);
        if let Some(pos) = plan.ip {
            ip_dd.set_selected(u32::try_from(pos).unwrap_or(0));
        }
        let duration_labels: Vec<&str> = DURATIONS.iter().map(|d| d.0).collect();
        let duration_dd = combo(&duration_labels);
        duration_dd.set_title("Keep the rule for");
        duration_dd.set_selected(u32::try_from(settings.default_duration).unwrap_or(0));

        let checksum = view::md5(&con).to_string();
        let check_from = clause_switch();
        let check_ip = clause_switch();
        let check_port = clause_switch();
        let check_uid = clause_switch();
        let check_sum = clause_switch();
        check_from.set_active(plan.from.is_some());
        check_ip.set_active(settings.advanced_dstip || plan.ip.is_some());
        check_port.set_active(con.dst_port != 0 && (settings.advanced_dstport || plan.port));
        check_uid.set_active(settings.advanced_uid || plan.uid);
        check_sum.set_active(settings.advanced_checksum);
        if !any_active([&check_from, &check_ip, &check_port, &check_uid, &check_sum])
            && let Some(pos) = from.iter().position(|t| !t.op.data.is_empty())
        {
            from_dd.set_selected(u32::try_from(pos).unwrap_or(0));
            check_from.set_active(true);
        }

        let default_action = Action::from_index(settings.default_action);
        let allow_btn = gtk::Button::with_label("Allow");
        allow_btn.add_css_class("suggested-action");
        let deny_btn = adw::SplitButton::new();
        deny_btn.add_css_class("destructive-action");

        // A plain window, not a layer surface: the compositor decorates it, so
        // the prompt carries the same title bar, border and corners as any
        // other window and can be moved out of the way.
        let window = adw::ApplicationWindow::new(app);
        window.set_title(Some("OpenSnitch"));
        window.set_resizable(false);

        let stack = gtk::Stack::new();
        stack.set_vhomogeneous(false);
        stack.set_width_request(WIDTH);

        let dialog = Rc::new(Self {
            window,
            stack,
            con,
            from,
            ip,
            checksum,
            from_dd,
            ip_dd,
            duration_dd,
            check_from,
            check_ip,
            check_port,
            check_uid,
            check_sum,
            checks,
            allow_btn,
            deny_btn,
            default_action,
            remaining: Cell::new(settings.timeout),
            timeout: settings.timeout,
            counting: Cell::new(!settings.advanced),
            done: Cell::new(false),
            result,
            timed_out: Cell::new(false),
            warning: RefCell::new(None),
        });
        dialog.build_ui(&app_name, &user);
        dialog.update_buttons();
        dialog.update_guards();
        dialog.lock_button_widths();
        dialog.connect_signals();
        dialog
    }

    fn build_ui(self: &Rc<Self>, app_name: &str, user: &str) {
        self.stack
            .add_named(&self.main_page(app_name, user), Some("main"));
        self.stack
            .add_named(&self.details_page(user), Some("details"));
        if !self.checks.mismatch.is_empty() {
            self.stack
                .add_named(&self.checksums_page(), Some("checksums"));
        }
        self.window.set_content(Some(&self.stack));
        self.deny_btn.set_popover(Some(&self.deny_menu()));
    }

    fn main_page(self: &Rc<Self>, app_name: &str, user: &str) -> adw::ToolbarView {
        let bar = adw::HeaderBar::new();
        bar.set_title_widget(Some(&adw::WindowTitle::new(app_name, "")));
        let details_btn = gtk::Button::builder()
            .icon_name("view-list-symbolic")
            .tooltip_text("Process Details")
            .build();
        details_btn.add_css_class("flat");
        let d = self.clone();
        details_btn.connect_clicked(move |_| {
            d.stop_countdown();
            d.stack.set_visible_child_name("details");
        });
        bar.pack_end(&details_btn);

        let list = adw::PreferencesPage::new();
        list.set_vexpand(true);

        let asking = adw::PreferencesGroup::new();
        asking.set_description(Some(&view::popup_message(app_name, &self.con)));
        let program: [(&str, Option<String>); 3] = [
            ("Program", view::path_label(app_name, &self.con)),
            ("Command", view::args_label(app_name, &self.con)),
            (
                "Executed from",
                Some(view::printable(&self.con.process_cwd)),
            ),
        ];
        for (title, text) in program {
            if let Some(text) = text {
                asking.add(&info_row(title, &text));
            }
        }
        let facts = adw::PreferencesGroup::new();
        facts.set_title("Connection");
        facts.add(&info_row("Source IP", &self.con.src_ip));
        self.ip_dd.set_title("Destination IP");
        self.ip_dd.add_suffix(&self.check_ip);
        facts.add(&self.ip_dd);
        if self.con.dst_port != 0 {
            facts.add(&guarded_row(
                "Destination port",
                &self.con.dst_port.to_string(),
                &self.check_port,
            ));
        }
        facts.add(&guarded_row("User", user, &self.check_uid));
        if !self.checksum.is_empty() {
            facts.add(&guarded_row("Checksum", &self.checksum, &self.check_sum));
        }

        let reach = adw::PreferencesGroup::new();
        reach.set_title("The rule");
        self.from_dd.set_title("Applies to");
        self.from_dd.add_suffix(&self.check_from);
        reach.add(&self.from_dd);
        reach.add(&self.duration_dd);

        list.add(&asking);
        list.add(&facts);
        list.add(&reach);

        if !self.checks.mismatch.is_empty() {
            let fixes = adw::PreferencesGroup::new();
            let row = self.checksum_row();
            fixes.add(&row);
            list.add(&fixes);
            *self.warning.borrow_mut() = Some(row);
        }

        let answers = button_row(&[
            self.deny_btn.upcast_ref::<gtk::Widget>(),
            self.allow_btn.upcast_ref::<gtk::Widget>(),
        ]);
        page(&bar, &list, Some(&answers))
    }

    fn details_page(self: &Rc<Self>, user: &str) -> adw::ToolbarView {
        let bar = sub_header(self, "Process Details");

        let text = gtk::TextView::new();
        text.set_editable(false);
        text.set_cursor_visible(false);
        text.set_monospace(true);
        text.set_wrap_mode(gtk::WrapMode::WordChar);
        text.buffer().set_text(&view::details_text(&self.con, user));
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_child(Some(&text));
        scroll.set_min_content_height(320);
        scroll.set_vexpand(true);

        let group = adw::PreferencesGroup::new();
        group.add(&scroll);
        let list = adw::PreferencesPage::new();
        list.add(&group);
        page(&bar, &list, None::<&gtk::Widget>)
    }

    fn deny_menu(self: &Rc<Self>) -> gtk::Popover {
        let menu = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let popover = gtk::Popover::new();
        for action in [Action::Drop, Action::Reject] {
            let item = gtk::Button::with_label(action.label());
            item.add_css_class("flat");
            let (d, p) = (self.clone(), popover.clone());
            item.connect_clicked(move |_| {
                p.popdown();
                d.send_rule(action);
            });
            menu.append(&item);
        }
        popover.set_child(Some(&menu));
        popover
    }

    fn checksum_row(self: &Rc<Self>) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title("The program's checksum is not the one its rules pin")
            .build();
        let fix = gtk::Button::with_label("Update checksums");
        let d = self.clone();
        fix.connect_clicked(move |_| {
            d.stop_countdown();
            d.stack.set_visible_child_name("checksums");
        });
        row.add_suffix(&fix);
        row
    }

    fn checksums_page(self: &Rc<Self>) -> adw::ToolbarView {
        let bar = sub_header(self, "Checksums");

        let update = gtk::Button::with_label("Update rule");
        let update_all = gtk::Button::with_label("Update all");
        let ui = ChecksumsUi {
            names: name_dropdown(&self.checks.mismatch.rule_names),
            status: label(""),
            buttons: button_row(&[
                update.upcast_ref::<gtk::Widget>(),
                update_all.upcast_ref::<gtk::Widget>(),
            ]),
            update,
            update_all,
        };

        for (button, all) in [(&ui.update, false), (&ui.update_all, true)] {
            let (d, ui) = (self.clone(), ui.clone());
            button.connect_clicked(move |_| d.request_update(&ui, all));
        }

        let group = adw::PreferencesGroup::new();
        group.set_description(Some(&view::printable_lines(&checksum::note(
            &self.con,
            &self.checks.mismatch,
        ))));
        let names_row = adw::ActionRow::builder().title("Rule").build();
        ui.names.set_valign(gtk::Align::Center);
        names_row.add_suffix(&ui.names);
        group.add(&names_row);
        ui.status.set_hexpand(true);
        ui.status.set_xalign(0.0);
        group.add(&ui.status);

        let list = adw::PreferencesPage::new();
        list.add(&group);
        page(&bar, &list, Some(&ui.buttons))
    }

    fn request_update(self: &Rc<Self>, ui: &ChecksumsUi, all: bool) {
        let targets = if all {
            list_names(&ui.names)
        } else {
            selected_name(&ui.names).into_iter().collect()
        };
        if !targets.is_empty() {
            self.update_rules(ui, targets);
        }
    }

    fn update_rules(self: &Rc<Self>, ui: &ChecksumsUi, names: Vec<String>) {
        let md5 = view::md5(&self.con).to_string();
        let updater = self.checks.updater.clone();
        let (d, ui) = (self.clone(), ui.clone());
        ui.status.remove_css_class("error");
        ui.status.remove_css_class("success");
        ui.status.set_text("Updating...");
        ui.buttons.set_sensitive(false);
        gtk::glib::spawn_future_local(async move {
            let outcome = updater.update_checksums(names, md5).await;
            d.show_outcome(&ui, &outcome);
        });
    }

    fn show_outcome(&self, ui: &ChecksumsUi, outcome: &Outcome) {
        remove_names(&ui.names, &outcome.updated);
        let (class, text) = outcome_line(outcome);
        ui.status.add_css_class(class);
        ui.status.set_text(&text);
        ui.buttons.set_sensitive(true);
        if list_names(&ui.names).is_empty() {
            self.retire_checksums(ui);
        }
    }

    fn retire_checksums(&self, ui: &ChecksumsUi) {
        for b in [&ui.update, &ui.update_all] {
            b.set_sensitive(false);
        }
        ui.names.set_sensitive(false);
        if let Some(warning) = self.warning.borrow().as_ref() {
            warning.set_visible(false);
        }
    }

    fn deny_action(&self) -> Action {
        if self.default_action == Action::Allow {
            Action::Drop
        } else {
            self.default_action
        }
    }

    fn update_buttons(&self) {
        let text = |action: Action, is_default: bool| {
            if is_default && self.counting.get() {
                format!("{} ({}s)", action.label(), self.remaining.get())
            } else {
                action.label().to_string()
            }
        };
        let allow_is_default = self.default_action == Action::Allow;
        self.allow_btn
            .set_label(&text(Action::Allow, allow_is_default));
        self.deny_btn
            .set_label(&text(self.deny_action(), !allow_is_default));
    }

    fn lock_button_widths(&self) {
        let widgets = [
            self.allow_btn.clone().upcast::<gtk::Widget>(),
            self.deny_btn.clone().upcast::<gtk::Widget>(),
        ];
        let widest = widgets
            .iter()
            .map(|w| w.measure(gtk::Orientation::Horizontal, -1).1)
            .max()
            .unwrap_or(0);
        for widget in widgets {
            widget.set_width_request(widest);
        }
    }

    fn stop_countdown(&self) {
        if self.counting.replace(false) {
            self.update_buttons();
        }
    }

    fn connect_signals(self: &Rc<Self>) {
        let d = self.clone();
        self.allow_btn
            .connect_clicked(move |_| d.send_rule(Action::Allow));
        let d = self.clone();
        self.deny_btn
            .connect_clicked(move |_| d.send_rule(d.deny_action()));

        // A choice made in a dropdown is a choice about the rule, so it turns on
        // the clause it belongs to: picking "Applies to" writes the process
        // clause, picking a destination IP writes the destination clause. The
        // duration has no clause of its own, it only lengthens the rule.
        for (row, check) in [
            (&self.from_dd, &self.check_from),
            (&self.ip_dd, &self.check_ip),
        ] {
            let (d, check) = (self.clone(), check.clone());
            row.connect_selected_notify(move |_| {
                d.stop_countdown();
                check.set_active(true);
                d.update_guards();
            });
        }
        let d = self.clone();
        self.duration_dd
            .connect_selected_notify(move |_| d.stop_countdown());
        for check in [
            &self.check_from,
            &self.check_ip,
            &self.check_port,
            &self.check_uid,
            &self.check_sum,
        ] {
            let d = self.clone();
            check.connect_active_notify(move |_| {
                d.stop_countdown();
                d.update_guards();
            });
        }
        let click = gtk::GestureClick::new();
        click.set_propagation_phase(gtk::PropagationPhase::Capture);
        let d = self.clone();
        click.connect_pressed(move |_, _, _, _| d.stop_countdown());
        self.window.add_controller(click);

        let keys = gtk::EventControllerKey::new();
        keys.connect_key_pressed(|_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        self.window.add_controller(keys);
        let d = self.clone();
        self.window.connect_close_request(move |_| {
            d.send_rule(d.default_action);
            gtk::glib::Propagation::Stop
        });
    }

    fn start(self: &Rc<Self>, cancelled: impl Fn() -> bool + 'static) {
        self.window.present();
        let d = self.clone();
        gtk::glib::timeout_add_seconds_local(1, move || d.tick(&cancelled));
    }

    fn tick(&self, cancelled: &impl Fn() -> bool) -> gtk::glib::ControlFlow {
        use gtk::glib::ControlFlow::Break;
        if self.done.get() {
            return Break;
        }
        if cancelled() {
            self.finish(None);
            return Break;
        }
        self.advance_countdown()
    }

    fn advance_countdown(&self) -> gtk::glib::ControlFlow {
        match countdown(self.counting.get(), self.timeout, self.remaining.get()) {
            Countdown::Idle => gtk::glib::ControlFlow::Continue,
            Countdown::Running(left) => {
                self.remaining.set(left);
                self.update_buttons();
                gtk::glib::ControlFlow::Continue
            }
            Countdown::Expired => {
                self.remaining.set(0);
                self.timed_out.set(true);
                self.send_rule(self.default_action);
                gtk::glib::ControlFlow::Break
            }
        }
    }

    fn selection_any(&self) -> bool {
        any_active([
            &self.check_from,
            &self.check_ip,
            &self.check_port,
            &self.check_uid,
            &self.check_sum,
        ])
    }

    fn update_guards(&self) {
        let any = self.selection_any();
        self.allow_btn.set_sensitive(any);
        self.deny_btn.set_sensitive(any);
    }

    fn send_rule(&self, action: Action) {
        let index = |row: &adw::ComboRow| usize::try_from(row.selected()).unwrap_or(0);
        let from = self
            .check_from
            .is_active()
            .then(|| self.from.get(index(&self.from_dd)))
            .flatten();
        let ip = self
            .check_ip
            .is_active()
            .then(|| self.ip.get(index(&self.ip_dd)))
            .flatten();
        let choice = Choice {
            action,
            duration_idx: index(&self.duration_dd),
            from,
            ip,
            check_port: self.check_port.is_active(),
            check_uid: self.check_uid.is_active(),
            check_sum: self.check_sum.is_active(),
            checksum: &self.checksum,
        };
        self.finish(rule::build_rule(&self.con, &choice, now_secs()));
    }

    fn finish(&self, rule: Option<Rule>) {
        if self.done.replace(true) {
            return;
        }
        let _ = self.result.try_send(Answer {
            rule,
            timed_out: self.timed_out.get(),
        });
        self.window.destroy();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Countdown {
    Idle,
    Running(u32),
    Expired,
}

fn countdown(counting: bool, timeout: u32, remaining: u32) -> Countdown {
    if !counting || timeout == 0 {
        return Countdown::Idle;
    }
    match remaining.saturating_sub(1) {
        0 => Countdown::Expired,
        left => Countdown::Running(left),
    }
}

fn outcome_line(outcome: &Outcome) -> (&'static str, String) {
    match (&outcome.error, outcome.updated.len()) {
        (None, 1) => ("success", "\u{2714} Rule updated.".to_string()),
        (None, n) => ("success", format!("\u{2714} {n} rules updated.")),
        (Some(err), _) => ("error", format!("\u{2718} {}", view::printable(err))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_countdown_runs_down_and_expires() {
        assert_eq!(countdown(true, 30, 30), Countdown::Running(29));
        assert_eq!(countdown(true, 30, 2), Countdown::Running(1));
        assert_eq!(countdown(true, 30, 1), Countdown::Expired);
        assert_eq!(countdown(true, 30, 0), Countdown::Expired);
    }

    #[test]
    fn the_countdown_stays_idle_when_stopped_or_without_timeout() {
        assert_eq!(countdown(false, 30, 10), Countdown::Idle);
        assert_eq!(countdown(true, 0, 10), Countdown::Idle);
    }

    #[test]
    fn an_update_is_described_by_its_outcome() {
        let updated = |n: usize, error: Option<&str>| Outcome {
            updated: vec!["rule".to_string(); n],
            error: error.map(String::from),
        };
        assert_eq!(
            outcome_line(&updated(1, None)),
            ("success", "\u{2714} Rule updated.".to_string())
        );
        assert_eq!(
            outcome_line(&updated(3, None)),
            ("success", "\u{2714} 3 rules updated.".to_string())
        );
        let (class, text) = outcome_line(&updated(1, Some("daemon says no")));
        assert_eq!(class, "error");
        assert!(text.ends_with("daemon says no"), "{text}");
    }
}
