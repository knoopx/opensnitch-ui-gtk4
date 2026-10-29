
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use adw::prelude::*;
use gtk4 as gtk;
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;

use crate::link::Updater;
use crate::proto::{Operator, Rule};
use crate::rule;
use crate::view;

const COL_ENABLED: usize = 0;
const COL_NAME: usize = 1;
const COL_DESCRIPTION: usize = 2;
const COL_ACTION: usize = 3;
const COL_DURATION: usize = 4;
const COL_OP_TYPE: usize = 5;
const COL_OP_OPERAND: usize = 6;
const COL_OP_DATA: usize = 7;
const COL_CREATED: usize = 8;

const HEADERS: [&str; 9] = [
    "Enabled",
    "Name",
    "Description",
    "Action",
    "Duration",
    "Type",
    "Operand",
    "Data",
    "Created",
];

const CENTERED: [usize; 3] = [COL_ENABLED, COL_ACTION, COL_CREATED];

const EXPANDING: [usize; 4] = [COL_NAME, COL_DESCRIPTION, COL_OP_OPERAND, COL_OP_DATA];

const NARROW: [usize; 2] = [COL_DURATION, COL_OP_TYPE];

const CHECKED: [usize; 1] = [COL_ENABLED];

const WIDE: i32 = 40;
const TIGHT: i32 = 14;
const NARROW_PX: i32 = 84;

const FILTERS: [&str; 3] = ["All applications", "Permanent", "Temporary"];

const FILTER_HINT: &str = "Filter rules";

const SEARCH_HINT: &str = "Search rules";

const DURATION_ALWAYS: &str = "always";

const STYLES: [&str; 3] = ["success", "error", "warning"];

const PAGE_ROWS: &str = "rows";
const PAGE_NONE: &str = "none";
const PAGE_EMPTY: &str = "empty";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    All,
    Permanent,
    Temporary,
}

impl From<u32> for Filter {
    fn from(combo: u32) -> Self {
        filter_of(combo)
    }
}

pub fn filter_of(combo: u32) -> Filter {
    match combo {
        1 => Filter::Permanent,
        2 => Filter::Temporary,
        _ => Filter::All,
    }
}

#[derive(Debug, Default)]
struct Criteria {
    filter: Cell<Filter>,
    query: RefCell<String>,
}

impl Criteria {
    fn set(&self, filter: Filter, query: &str) {
        self.filter.set(filter);
        *self.query.borrow_mut() = query.trim().to_string();
    }

    fn keeps(&self, rule: &Rule) -> bool {
        let permanent = rule.duration == DURATION_ALWAYS;
        match self.filter.get() {
            Filter::All => {}
            Filter::Permanent if !permanent => return false,
            Filter::Temporary if permanent => return false,
            Filter::Permanent | Filter::Temporary => {}
        }
        view::rule_matches(rule, &self.query.borrow())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub cells: [String; 9],
    pub rule: Rule,
}

pub fn row(rule: &Rule) -> Row {
    let op = rule.operator.clone().unwrap_or_default();
    let (kind, operand, data) = flatten(&op);
    Row {
        cells: [
            String::new(),
            rule.name.clone(),
            rule.description.clone(),
            rule.action.clone(),
            rule.duration.clone(),
            kind,
            operand,
            data,
            created_text(rule.created),
        ],
        rule: rule.clone(),
    }
}

fn flatten(op: &Operator) -> (String, String, String) {
    if op.r#type != "list" {
        return (op.r#type.clone(), op.operand.clone(), op.data.clone());
    }
    let parts: Vec<String> = op
        .list
        .iter()
        .map(|o| format!("{} {}", o.operand, o.data))
        .collect();
    let first = op.list.first().map_or(String::new(), |o| o.operand.clone());
    (op.r#type.clone(), first, parts.join(", "))
}

pub fn created_text(secs: i64) -> String {
    let (days, secs) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn paint(row: &Row, column: usize) -> Option<&'static str> {
    if column != COL_ACTION {
        return None;
    }
    match row.cells[column].as_str() {
        "allow" => Some("success"),
        "deny" => Some("error"),
        "reject" => Some("warning"),
        _ => None,
    }
}

pub fn menu_model() -> gtk::gio::Menu {
    let root = gtk::gio::Menu::new();
    root.append(Some("_Edit"), Some("rule.edit"));
    root.append(Some("_Duplicate"), Some("rule.duplicate"));
    root.append(Some("_Delete"), Some("rule.delete"));
    root
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

mod row_item {
    use super::Row;
    use gtk4::glib;
    use gtk4::glib::prelude::*;
    use gtk4::glib::subclass::prelude::*;
    use std::cell::RefCell;

    #[derive(Default)]
    pub struct Imp {
        row: RefCell<Option<Row>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Imp {
        const NAME: &'static str = "SnitchRuleRow";
        type Type = RuleRow;
    }

    impl ObjectImpl for Imp {}

    glib::wrapper! {
        pub struct RuleRow(ObjectSubclass<Imp>);
    }

    impl RuleRow {
        pub fn new(row: Row) -> Self {
            let item: Self = glib::Object::builder().build();
            item.imp().row.replace(Some(row));
            item
        }

        pub fn row(&self) -> Option<Row> {
            self.imp().row.borrow().clone()
        }

        pub fn cell(&self, column: usize) -> String {
            self.row()
                .map_or_else(String::new, |r| r.cells[column].clone())
        }
    }

    pub fn of(value: &glib::Object) -> Option<RuleRow> {
        value.downcast_ref::<RuleRow>().cloned()
    }
}

mod rule_sorter {
    use super::row_item;
    use gtk4 as gtk;
    use gtk4::glib;
    use gtk4::subclass::prelude::*;
    use std::cell::Cell;

    #[derive(Default)]
    pub struct Imp {
        column: Cell<usize>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Imp {
        const NAME: &'static str = "SnitchRuleSorter";
        type Type = RuleSorter;
        type ParentType = gtk::Sorter;
    }

    impl ObjectImpl for Imp {}

    impl SorterImpl for Imp {
        fn compare(&self, one: &glib::Object, other: &glib::Object) -> gtk::Ordering {
            let (Some(a), Some(b)) = (row_item::of(one), row_item::of(other)) else {
                return gtk::Ordering::Equal;
            };
            let column = self.column.get();
            match a.cell(column).cmp(&b.cell(column)) {
                std::cmp::Ordering::Less => gtk::Ordering::Smaller,
                std::cmp::Ordering::Equal => gtk::Ordering::Equal,
                std::cmp::Ordering::Greater => gtk::Ordering::Larger,
            }
        }
    }

    glib::wrapper! {
        pub struct RuleSorter(ObjectSubclass<Imp>) @extends gtk::Sorter;
    }

    impl RuleSorter {
        pub fn new(column: usize) -> Self {
            let sorter: Self = glib::Object::builder().build();
            sorter.imp().column.set(column);
            sorter
        }
    }
}

mod rule_filter {
    use super::{Criteria, row_item};
    use gtk4 as gtk;
    use gtk4::glib;
    use gtk4::subclass::prelude::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    pub struct Imp {
        criteria: RefCell<Option<Rc<Criteria>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Imp {
        const NAME: &'static str = "SnitchRuleFilter";
        type Type = RuleFilter;
        type ParentType = gtk::Filter;
    }

    impl ObjectImpl for Imp {}

    impl FilterImpl for Imp {
        fn strictness(&self) -> gtk::FilterMatch {
            gtk::FilterMatch::Some
        }

        fn match_(&self, item: &glib::Object) -> bool {
            let Some(criteria) = self.criteria.borrow().clone() else {
                return true;
            };
            let Some(row) = row_item::of(item).and_then(|item| item.row()) else {
                return true;
            };
            criteria.keeps(&row.rule)
        }
    }

    glib::wrapper! {
        pub struct RuleFilter(ObjectSubclass<Imp>) @extends gtk::Filter;
    }

    impl RuleFilter {
        pub(super) fn new(criteria: Rc<Criteria>) -> Self {
            let filter: Self = glib::Object::builder().build();
            filter.imp().criteria.replace(Some(criteria));
            filter
        }

        pub(super) fn answers_changed(&self) {
            gtk::prelude::FilterExt::changed(self, gtk::FilterChange::Different);
        }
    }
}

thread_local! {
    static OPEN: RefCell<Vec<Rc<Manager>>> = const { RefCell::new(Vec::new()) };
}

pub fn show(app: &adw::Application, updater: Updater) {
    OPEN.with(|open| {
        if let Some(existing) = open.borrow().first() {
            existing.window.present();
            return;
        }
        let manager = Manager::new(app, updater);
        manager.reload();
        open.borrow_mut().push(Rc::clone(&manager));
        let gone = manager.window.clone();
        manager.window.connect_destroy(move |_| {
            OPEN.with(|open| open.borrow_mut().retain(|m| m.window != gone));
        });
        manager.window.present();
    });
}

struct Manager {
    app: adw::Application,
    window: adw::ApplicationWindow,
    store: gtk::gio::ListStore,
    filtered: gtk::FilterListModel,
    selection: gtk::SingleSelection,
    view: gtk::ColumnView,
    toasts: adw::ToastOverlay,
    menu: gtk::PopoverMenu,
    search: gtk::SearchEntry,
    filter: gtk::DropDown,
    menu_rule: RefCell<Option<Rule>>,
    row_filter: rule_filter::RuleFilter,
    stack: gtk::Stack,
    updater: Updater,
    criteria: Rc<Criteria>,
}

impl Manager {
    fn new(app: &adw::Application, updater: Updater) -> Rc<Self> {
        let window = adw::ApplicationWindow::new(app);
        window.set_title(Some("Rules"));
        window.set_default_size(1040, 620);
        window.set_width_request(900);

        let store = gtk::gio::ListStore::new::<row_item::RuleRow>();
        let criteria = Rc::new(Criteria::default());
        let rule_filter = rule_filter::RuleFilter::new(Rc::clone(&criteria));
        let row_filter = rule_filter.clone();
        let filtered = gtk::FilterListModel::new(Some(store.clone()), Some(row_filter));
        let view = gtk::ColumnView::builder().build();
        view.set_show_row_separators(true);
        view.set_show_column_separators(false);
        view.set_hexpand(true);
        let sorted = gtk::SortListModel::new(Some(filtered.clone()), view.sorter());
        let selection = gtk::SingleSelection::new(Some(sorted));
        view.set_model(Some(&selection));

        let scroll = gtk::ScrolledWindow::new();
        scroll.set_child(Some(&view));
        scroll.set_vexpand(true);
        let stack = gtk::Stack::new();
        stack.set_vexpand(true);
        stack.add_named(&scroll, Some(PAGE_ROWS));
        stack.add_named(&empty_page(), Some(PAGE_EMPTY));
        stack.add_named(&no_match_page(), Some(PAGE_NONE));

        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some(SEARCH_HINT));

        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&stack));

        let filter = gtk::DropDown::from_strings(&FILTERS);
        filter.set_tooltip_text(Some(FILTER_HINT));
        let new_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("New Rule")
            .action_name("win.new-rule")
            .build();
        let bar = header_bar(&filter, &search, &new_btn);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&bar);
        toolbar.set_content(Some(&toasts));
        window.set_content(Some(&toolbar));

        let this = Rc::new(Self {
            app: app.clone(),
            window,
            store,
            filtered,
            selection,
            view,
            toasts,
            menu: gtk::PopoverMenu::from_model(Some(&menu_model())),
            search,
            filter,
            menu_rule: RefCell::new(None),
            row_filter: rule_filter.clone(),
            stack,
            updater,
            criteria,
        });
        this.build_columns();
        this.connect_filters();
        this.connect_rows();
        this.connect_actions();
        this
    }

    fn build_columns(self: &Rc<Self>) {
        for (idx, title) in HEADERS.iter().enumerate() {
            let factory = gtk::SignalListItemFactory::new();
            let weak = Rc::downgrade(self);
            let setup_weak = weak.clone();
            factory.connect_setup(move |_, item| setup_cell(item, idx, setup_weak.clone()));
            factory.connect_bind(move |_, item| bind_cell(item, idx, weak.clone()));
            let factory: gtk::ListItemFactory = factory.upcast();
            let column = gtk::ColumnViewColumn::new(Some(title), Some(factory));
            column.set_resizable(true);
            column.set_expand(EXPANDING.contains(&idx));
            column.set_sorter(Some(&rule_sorter::RuleSorter::new(idx)));
            if NARROW.contains(&idx) {
                column.set_fixed_width(NARROW_PX);
            }
            self.view.append_column(&column);
            if idx == COL_NAME {
                self.view
                    .sort_by_column(Some(&column), gtk::SortType::Ascending);
            }
        }
    }

    fn connect_filters(self: &Rc<Self>) {
        let d = self.clone();
        let filter = self.filter.clone();
        self.search.connect_search_changed(move |entry| {
            d.apply(filter.selected(), &entry.text());
        });
        let d = self.clone();
        let search = self.search.clone();
        self.filter.connect_selected_notify(move |drop| {
            d.apply(drop.selected(), &search.text());
        });
    }

    fn apply(self: &Rc<Self>, combo: u32, query: &str) {
        self.criteria.set(filter_of(combo), query);
        self.row_filter.answers_changed();
        self.set_status();
    }

    fn connect_rows(self: &Rc<Self>) {
        self.view.set_single_click_activate(false);
        let d = self.clone();
        self.view.connect_activate(move |view, position| {
            let Some(item) = view.model().and_then(|m| m.item(position)) else {
                return;
            };
            let Some(row) = row_item::of(&item).and_then(|item| item.row()) else {
                return;
            };
            d.edit(Some(&row.rule));
        });
    }

    fn show_row_menu(self: &Rc<Self>, rule: &Rule, cell: &impl IsA<gtk::Widget>, x: f64, y: f64) {
        *self.menu_rule.borrow_mut() = Some(rule.clone());
        self.menu.set_parent(cell);
        self.menu
            .set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        self.menu.popup();
    }

    fn connect_actions(self: &Rc<Self>) {
        let group = gtk::gio::SimpleActionGroup::new();
        add(self, &group, "duplicate", |d, _| d.duplicate());
        add(self, &group, "edit", |d, _| d.edit_selected());
        add(self, &group, "delete", |d, _| d.ask_delete());
        self.window.insert_action_group("rule", Some(&group));
        self.window
            .insert_action_group("win", Some(&self.win_actions()));
    }

    fn win_actions(self: &Rc<Self>) -> gtk::gio::SimpleActionGroup {
        let group = gtk::gio::SimpleActionGroup::new();
        add(self, &group, "new-rule", |d, _| d.edit(None));
        add(self, &group, "search", |d, _| {
            d.search.grab_focus();
        });
        add(self, &group, "refresh", |d, _| d.reload());
        add(self, &group, "edit", |d, _| d.edit_selected());
        add(self, &group, "duplicate", |d, _| d.duplicate());
        add(self, &group, "delete", |d, _| d.ask_delete());
        add(self, &group, "shortcuts", |d, _| d.show_shortcuts());
        add(self, &group, "close", |d, _| d.window.close());
        self.app
            .set_accels_for_action("win.new-rule", &["<Control>n"]);
        self.app
            .set_accels_for_action("win.search", &["<Control>f"]);
        self.app
            .set_accels_for_action("win.refresh", &["<Control>r"]);
        self.app
            .set_accels_for_action("win.duplicate", &["<Control>d"]);
        self.app.set_accels_for_action("win.delete", &["Delete"]);
        self.app
            .set_accels_for_action("win.shortcuts", &["<Control>question"]);
        self.app.set_accels_for_action("win.close", &["<Control>w"]);
        group
    }

    fn target_rule(&self) -> Option<Rule> {
        if let Some(rule) = self.menu_rule.borrow_mut().take() {
            return Some(rule);
        }
        let item = self.selection.item(self.selection.selected())?;
        row_item::of(&item)
            .and_then(|item| item.row())
            .map(|r| r.rule)
    }

    fn reload(self: &Rc<Self>) {
        let rules = self.updater.rules();
        self.store.remove_all();
        for rule in &rules {
            self.store.append(&row_item::RuleRow::new(row(rule)));
        }
        self.filtered.set_filter(Some(&self.row_filter));
        self.set_status();
    }

    fn set_status(self: &Rc<Self>) {
        let page = match (self.store.n_items(), self.filtered.n_items()) {
            (0, _) => PAGE_EMPTY,
            (_, 0) => PAGE_NONE,
            _ => PAGE_ROWS,
        };
        self.stack.set_visible_child_name(page);
    }

    fn set_rule_enabled(self: &Rc<Self>, name: String, on: bool) {
        let d = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = d.updater.set_rule_enabled(name.clone(), on).await {
                d.toast(&format!("{name} was not changed: {err}"));
            }
            d.reload();
        });
    }

    fn save(self: &Rc<Self>, rule: Rule, failure: String) {
        let d = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = d.updater.save_rule(rule).await {
                d.toast(&format!("{failure}: {err}"));
            }
            d.reload();
        });
    }

    fn duplicate(self: &Rc<Self>) {
        let Some(mut rule) = self.target_rule() else {
            return;
        };
        rule.created = now_secs();
        rule.name = format!("{}-copy", rule.name);
        let known = self.updater.rules();
        let created = rule.created;
        rule::make_name_unique(&mut rule, &known, created);
        let name = rule.name.clone();
        self.save(rule, format!("{name} was not saved"));
    }

    fn edit_selected(self: &Rc<Self>) {
        let Some(rule) = self.target_rule() else {
            return;
        };
        self.edit(Some(&rule));
    }

    fn edit(self: &Rc<Self>, rule: Option<&Rule>) {
        let d = self.clone();
        let undone = self.clone();
        let app = self.app.clone();
        crate::rule_edit::open(
            &app,
            &self.window,
            self.updater.clone(),
            rule,
            Rc::new(move || d.reload()),
            Rc::new(move |rule| undone.deleted(rule)),
        );
    }

    /// A rule removed from the editor: refresh the list and offer it back.
    fn deleted(self: &Rc<Self>, rule: Rule) {
        let name = rule.name.clone();
        self.reload();
        self.toast_undo(&format!("{name} deleted"), rule);
    }

    fn ask_delete(self: &Rc<Self>) {
        let Some(rule) = self.target_rule() else {
            return;
        };
        let name = rule.name.clone();
        let d = self.clone();
        glib::spawn_future_local(async move {
            if let Err(err) = d.updater.delete_rule(name.clone()).await {
                d.toast(&format!("{name} was not deleted: {err}"));
                return;
            }
            d.deleted(rule);
        });
    }

    fn toast_undo(self: &Rc<Self>, text: &str, rule: Rule) {
        let toast = adw::Toast::new(text);
        toast.set_button_label(Some("Undo"));
        let d = self.clone();
        toast.connect_button_clicked(move |_| {
            let restored = rule.name.clone();
            d.save(rule.clone(), format!("{restored} was not restored"));
        });
        self.toasts.add_toast(toast);
    }

    fn show_shortcuts(self: &Rc<Self>) {
        let builder = gtk::Builder::new();
        if builder.add_from_string(SHORTCUTS_UI).is_err() {
            self.toast("The shortcuts window could not be built");
            return;
        }
        let Some(win) = builder.object::<gtk::ShortcutsWindow>("shortcuts") else {
            self.toast("The shortcuts window could not be built");
            return;
        };
        win.set_application(Some(&self.app));
        win.set_transient_for(Some(&self.window));
        win.present();
    }

    fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }
}

fn header_bar(
    filter: &gtk::DropDown,
    search: &gtk::SearchEntry,
    new_btn: &gtk::Button,
) -> adw::HeaderBar {
    let bar = adw::HeaderBar::new();
    bar.pack_start(new_btn);
    bar.pack_start(filter);

    search.set_halign(gtk::Align::Center);
    search.set_width_request(300);
    bar.set_title_widget(Some(search));
    bar
}

fn empty_page() -> adw::StatusPage {
    let page = adw::StatusPage::new();
    page.set_title("No Rules");
    page.set_icon_name(Some("list-add-symbolic"));
    let btn = gtk::Button::builder()
        .label("New Rule")
        .css_classes(["suggested-action", "pill"])
        .action_name("win.new-rule")
        .build();
    page.set_child(Some(&btn));
    page
}

fn no_match_page() -> adw::StatusPage {
    let page = adw::StatusPage::new();
    page.set_title("No Matching Rules");
    page.set_icon_name(Some("system-search-symbolic"));
    page
}

const SHORTCUTS_UI: &str = r#"
<?xml version="1.0" encoding="UTF-8"?>
<interface>
  <object class="GtkShortcutsWindow" id="shortcuts">
    <property name="modal">true</property>
    <child>
      <object class="GtkShortcutsSection">
        <property name="section-name">rules</property>
        <property name="title" translatable="yes">Rules</property>
        <child>
          <object class="GtkShortcutsGroup">
            <property name="title" translatable="yes">The list</property>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">New rule</property>
                <property name="accelerator">&lt;ctrl&gt;n</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">Search</property>
                <property name="accelerator">&lt;ctrl&gt;f</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">Reload from the daemon</property>
                <property name="accelerator">&lt;ctrl&gt;r</property>
              </object>
            </child>
          </object>
        </child>
        <child>
          <object class="GtkShortcutsGroup">
            <property name="title" translatable="yes">The selected rule</property>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">Edit</property>
                <property name="accelerator">Return</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">Duplicate</property>
                <property name="accelerator">&lt;ctrl&gt;d</property>
              </object>
            </child>
            <child>
              <object class="GtkShortcutsShortcut">
                <property name="title" translatable="yes">Delete</property>
                <property name="accelerator">Delete</property>
              </object>
            </child>
          </object>
        </child>
      </object>
    </child>
  </object>
</interface>
"#;

fn setup_cell(object: &glib::Object, idx: usize, manager: Weak<Manager>) {
    let Some(item) = object.downcast_ref::<gtk::ListItem>() else {
        return;
    };
    if CHECKED.contains(&idx) {
        return;
    }
    let cell = gtk::Label::new(None);
    cell.set_ellipsize(gtk::pango::EllipsizeMode::End);
    cell.set_max_width_chars(if EXPANDING.contains(&idx) {
        WIDE
    } else {
        TIGHT
    });
    cell.set_xalign(if CENTERED.contains(&idx) { 0.5 } else { 0.0 });
    attach_row_menu(&cell, item, manager);
    item.set_child(Some(&cell));
}

fn attach_row_menu(cell: &impl IsA<gtk::Widget>, item: &gtk::ListItem, manager: Weak<Manager>) {
    let target = cell.upcast_ref::<gtk::Widget>().clone();
    let gesture = gtk::GestureClick::new();
    gesture.set_button(3);
    target.add_controller(gesture.clone());
    let item = item.clone();
    gesture.connect_released(move |_, _, x, y| {
        let Some(manager) = manager.upgrade() else {
            return;
        };
        let Some(row) = item
            .item()
            .and_then(|v| row_item::of(&v))
            .and_then(|item| item.row())
        else {
            return;
        };
        // The gesture reports f64, graphene and the column view work in f32.
        let (x, y) = (x as f32, y as f32);
        let point = manager
            .view
            .compute_point(&target, &gtk::graphene::Point::new(x, y))
            .unwrap_or_else(|| gtk::graphene::Point::new(x, y));
        manager.show_row_menu(
            &row.rule,
            &manager.view,
            f64::from(point.x()),
            f64::from(point.y()),
        );
    });
}

fn bind_cell(object: &glib::Object, idx: usize, manager: Weak<Manager>) {
    let Some(item) = object.downcast_ref::<gtk::ListItem>() else {
        return;
    };
    let Some(row) = item
        .item()
        .and_then(|v| row_item::of(&v))
        .and_then(|item| item.row())
    else {
        return;
    };
    if CHECKED.contains(&idx) {
        let cell = check_cell(&row, idx, manager.clone());
        attach_row_menu(&cell, item, manager);
        item.set_child(Some(&cell));
        return;
    }
    let Some(cell) = item.child().and_downcast::<gtk::Label>() else {
        return;
    };
    let text = row.cells[idx].clone();
    cell.set_text(&text);
    for class in STYLES {
        cell.remove_css_class(class);
    }
    if let Some(class) = paint(&row, idx) {
        cell.add_css_class(class);
    }
}

fn check_cell(row: &Row, idx: usize, manager: Weak<Manager>) -> gtk::Switch {
    let cell = gtk::Switch::new();
    cell.set_valign(gtk::Align::Center);
    cell.set_halign(gtk::Align::Center);
    cell.set_active(row.rule.enabled);
    if idx == COL_ENABLED {
        let rule = row.rule.clone();
        cell.connect_active_notify(move |switch| {
            if let Some(manager) = manager.upgrade() {
                manager.set_rule_enabled(rule.name.clone(), switch.is_active());
            }
        });
    }
    cell
}

fn add<F>(manager: &Rc<Manager>, group: &gtk::gio::SimpleActionGroup, name: &str, f: F)
where
    F: Fn(&Rc<Manager>, &str) + 'static,
{
    let manager = Rc::clone(manager);
    let name = name.to_string();
    let action = gtk::gio::SimpleAction::new(&name, None);
    action.connect_activate(move |_, _| f(&manager, &name));
    group.add_action(&action);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, action: &str, duration: &str) -> Rule {
        Rule {
            created: 1_700_000_000,
            name: name.into(),
            enabled: true,
            action: action.into(),
            duration: duration.into(),
            operator: Some(Operator {
                r#type: "simple".into(),
                operand: "process.path".into(),
                data: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn criteria(filter: Filter, query: &str) -> Criteria {
        let c = Criteria::default();
        c.set(filter, query);
        c
    }

    #[test]
    fn every_column_index_names_the_right_header() {
        assert_eq!(HEADERS[COL_NAME], "Name");
        assert_eq!(HEADERS[COL_ENABLED], "Enabled");
        assert_eq!(HEADERS[COL_ACTION], "Action");
        assert_eq!(HEADERS[COL_DURATION], "Duration");
        assert_eq!(HEADERS[COL_DESCRIPTION], "Description");
        assert_eq!(HEADERS[COL_OP_TYPE], "Type");
        assert_eq!(HEADERS[COL_OP_OPERAND], "Operand");
        assert_eq!(HEADERS[COL_OP_DATA], "Data");
        assert_eq!(HEADERS[COL_CREATED], "Created");
    }

    #[test]
    fn every_column_belongs_to_exactly_one_sizing_group() {
        let mut sized = 0;
        for idx in 0..HEADERS.len() {
            let in_group = [
                CENTERED.contains(&idx),
                EXPANDING.contains(&idx),
                NARROW.contains(&idx),
            ]
            .iter()
            .filter(|hit| **hit)
            .count();
            assert_eq!(in_group, 1, "column {idx} sized by {in_group} groups");
            sized += 1;
        }
        assert_eq!(sized, HEADERS.len());
    }

    #[test]
    fn a_rule_becomes_the_nine_columns() {
        let r = row(&rule("allow-curl", "allow", "always"));
        assert_eq!(
            r.cells,
            [
                "",                    // Enabled: the switch has no text
                "allow-curl",          // Name
                "",                    // Description
                "allow",               // Action
                "always",              // Duration
                "simple",              // Type
                "process.path",        // Operand
                "/usr/bin/curl",       // Data
                "2023-11-14 22:13:20"  // Created
            ]
        );
    }

    #[test]
    fn a_list_operator_shows_its_parts() {
        let mut r = rule("allow-list", "allow", "1h");
        r.operator = Some(Operator {
            r#type: "list".into(),
            list: vec![
                Operator {
                    r#type: "simple".into(),
                    operand: "dest.port".into(),
                    data: "443".into(),
                    ..Default::default()
                },
                Operator {
                    r#type: "regexp".into(),
                    operand: "process.path".into(),
                    data: "^/usr".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        let r = row(&r);
        assert_eq!(r.cells[COL_OP_TYPE], "list");
        assert_eq!(r.cells[COL_OP_OPERAND], "dest.port");
        assert_eq!(r.cells[COL_OP_DATA], "dest.port 443, process.path ^/usr");
    }

    #[test]
    fn the_combo_filters_on_the_always_duration() {
        let perm = rule("perm", "allow", "always");
        let temp = rule("temp", "deny", "1h");
        let reboot = rule("reboot", "allow", "until restart");
        assert!(criteria(Filter::All, "").keeps(&temp));
        assert!(criteria(Filter::Permanent, "").keeps(&perm));
        assert!(!criteria(Filter::Permanent, "").keeps(&temp));
        assert!(!criteria(Filter::Permanent, "").keeps(&reboot));
        assert!(criteria(Filter::Temporary, "").keeps(&reboot));
        assert!(!criteria(Filter::Temporary, "").keeps(&perm));
        assert_eq!(filter_of(0), Filter::All);
        assert_eq!(filter_of(1), Filter::Permanent);
        assert_eq!(filter_of(2), Filter::Temporary);
    }

    #[test]
    fn the_search_narrows_the_rows() {
        let curl = rule("allow-curl", "allow", "always");
        let mut ssh = rule("deny-ssh", "deny", "15m");
        ssh.description = "lab box".into();
        let c = criteria(Filter::All, "");
        assert!(c.keeps(&curl));
        assert!(criteria(Filter::All, "CURL").keeps(&curl));
        assert!(!criteria(Filter::All, "firefox").keeps(&curl));
        assert!(criteria(Filter::All, "lab").keeps(&ssh));
        assert!(criteria(Filter::All, "usr/bin").keeps(&curl));
        assert!(criteria(Filter::All, "  ssh  ").keeps(&ssh));
    }

    #[test]
    fn the_filter_tells_the_model_when_its_answers_change() {
        if gtk::init().is_err() {
            return;
        }
        let criteria = Rc::new(Criteria::default());
        let filter = rule_filter::RuleFilter::new(Rc::clone(&criteria));
        let store = gtk::gio::ListStore::new::<row_item::RuleRow>();
        store.append(&row_item::RuleRow::new(row(&rule(
            "alpha",
            "allow",
            "always",
        ))));
        store.append(&row_item::RuleRow::new(row(&rule("beta", "deny", "1h"))));
        let model = gtk::FilterListModel::new(Some(store), Some(filter.clone()));
        assert_eq!(model.n_items(), 2);
        criteria.set(Filter::Permanent, "");
        filter.answers_changed();
        assert_eq!(model.n_items(), 1, "only the permanent rule is left");
        criteria.set(Filter::All, "beta");
        filter.answers_changed();
        assert_eq!(model.n_items(), 1, "and the search text narrows it too");
    }

    #[test]
    fn only_enabled_is_a_control_in_the_table() {
        assert_eq!(CHECKED, [COL_ENABLED]);
        assert_eq!(row(&rule("a", "allow", "always")).cells[COL_ENABLED], "");
    }

    #[test]
    fn only_the_action_cell_is_coloured() {
        let allow = row(&rule("a", "allow", "always"));
        assert_eq!(paint(&allow, COL_ACTION), Some("success"));
        assert_eq!(paint(&allow, COL_ENABLED), None);
        assert_eq!(paint(&allow, COL_DESCRIPTION), None);
        let deny = row(&rule("d", "deny", "1h"));
        assert_eq!(paint(&deny, COL_ACTION), Some("error"));
        let reject = row(&rule("r", "reject", "1h"));
        assert_eq!(paint(&reject, COL_ACTION), Some("warning"));
    }

    #[test]
    fn dates_use_the_d_b_date_field_format() {
        assert_eq!(created_text(0), "1970-01-01 00:00:00");
        assert_eq!(created_text(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(created_text(-1), "1969-12-31 23:59:59");
    }

    #[test]
    fn the_menu_labels_change_with_the_rule_state() {}
}
