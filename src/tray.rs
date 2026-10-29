
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use adw::prelude::*;
use gtk4 as gtk;
use gtk4::glib;
use libadwaita as adw;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::link::{DaemonState, Interception, Updater};

const RULES_ID: &str = "manage-rules";
const QUIT_ID: &str = "quit";

const ICON_SIZE: i32 = 22;

const ICON_PNG: &[u8] = include_bytes!("../assets/opensnitch-ui.png");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Rules,
    Quit,
}

impl Action {
    fn from_id(id: &str) -> Option<Self> {
        match id {
            RULES_ID => Some(Self::Rules),
            QUIT_ID => Some(Self::Quit),
            _ => None,
        }
    }
}

static PENDING: Mutex<Vec<Action>> = Mutex::new(Vec::new());

thread_local! {
    static TARGETS: RefCell<Option<(adw::Application, Updater)>> = const { RefCell::new(None) };
}

fn describe(state: DaemonState) -> (&'static str, &'static str) {
    match (state.connected, state.interception) {
        (false, _) => (
            "OpenSnitch (offline)",
            "OpenSnitch: the daemon is not connected",
        ),
        (_, Interception::Off) => (
            "OpenSnitch (paused)",
            "OpenSnitch is paused: connections are not filtered",
        ),
        _ => ("OpenSnitch", "OpenSnitch: connections are filtered"),
    }
}

fn menu() -> Menu {
    let menu = Menu::new();
    let rules = MenuItem::with_id(RULES_ID, "Manage Rules", true, None);
    let quit = MenuItem::with_id(QUIT_ID, "Quit", true, None);
    if let Err(err) = menu.append_items(&[&rules, &PredefinedMenuItem::separator(), &quit]) {
        tracing::error!("cannot build the tray menu: {err}");
    }
    menu
}

pub fn show(app: &adw::Application, updater: &Updater) {
    TARGETS.with(|targets| targets.replace(Some((app.clone(), updater.clone()))));
    let (title, tooltip) = describe(updater.status());
    let Some(icon) = tray_icon_image() else {
        tracing::warn!("the compiled-in icon cannot be read; the tray is not shown");
        return;
    };
    let built = TrayIconBuilder::new()
        .with_menu(Box::new(menu()))
        .with_icon(icon)
        .with_title(title)
        .with_tooltip(tooltip)
        .build();
    let tray = match built {
        Ok(tray) => Rc::new(tray),
        Err(err) => {
            tracing::warn!("no system tray: {err}");
            return;
        }
    };
    tracing::info!("system tray ready");

    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let Some(action) = Action::from_id(event.id.as_ref()) else {
            return;
        };
        PENDING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(action);
        glib::idle_add(run_pending);
    }));

    let mut changes = updater.watch();
    glib::spawn_future_local(async move {
        let mut before = *changes.borrow();
        while changes.changed().await.is_ok() {
            let now = *changes.borrow_and_update();
            if now != before {
                before = now;
                refresh(&tray, now);
            }
        }
    });
}

fn run_pending() -> glib::ControlFlow {
    let queued = std::mem::take(&mut *PENDING.lock().unwrap_or_else(|p| p.into_inner()));
    if queued.is_empty() {
        return glib::ControlFlow::Break;
    }
    let Some((app, updater)) = TARGETS.with(|targets| targets.borrow().clone()) else {
        tracing::warn!("tray menu click ignored: the tray has no target yet");
        return glib::ControlFlow::Break;
    };
    for action in queued {
        match action {
            Action::Rules => crate::rules::show(&app, updater.clone()),
            Action::Quit => app.quit(),
        }
    }
    glib::ControlFlow::Break
}

fn refresh(tray: &TrayIcon, state: DaemonState) {
    let (title, tooltip) = describe(state);
    tray.set_title(Some(title));
    if let Err(err) = tray.set_tooltip(Some(tooltip)) {
        tracing::warn!("tray tooltip not updated: {err}");
    }
}

fn tray_icon_image() -> Option<Icon> {
    let decoded = decode_at(ICON_PNG, ICON_SIZE)?;
    let small = if decoded.width() == ICON_SIZE && decoded.height() == ICON_SIZE {
        decoded
    } else {
        decoded.scale_simple(ICON_SIZE, ICON_SIZE, gtk::gdk_pixbuf::InterpType::Bilinear)?
    };
    let rgba = rgba8(&small)?;
    let size = u32::try_from(ICON_SIZE).ok()?;
    Icon::from_rgba(rgba, size, size).ok()
}

fn decode_at(bytes: &[u8], size: i32) -> Option<gtk::gdk_pixbuf::Pixbuf> {
    let loader = gtk::gdk_pixbuf::PixbufLoader::new();
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::set_size(&loader, size, size);
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::write(&loader, bytes).ok()?;
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::close(&loader).ok()?;
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::pixbuf(&loader)
}

#[cfg(test)]
fn decode(bytes: &[u8]) -> Option<gtk::gdk_pixbuf::Pixbuf> {
    let loader = gtk::gdk_pixbuf::PixbufLoader::new();
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::write(&loader, bytes).ok()?;
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::close(&loader).ok()?;
    gtk::gdk_pixbuf::prelude::PixbufLoaderExt::pixbuf(&loader)
}

fn rgba8(pixbuf: &gtk::gdk_pixbuf::Pixbuf) -> Option<Vec<u8>> {
    let (width, height) = (
        usize::try_from(pixbuf.width()).ok()?,
        usize::try_from(pixbuf.height()).ok()?,
    );
    let (channels, stride) = (
        usize::try_from(pixbuf.n_channels()).ok()?,
        usize::try_from(pixbuf.rowstride()).ok()?,
    );
    let has_alpha = pixbuf.has_alpha();
    let src = unsafe { pixbuf.pixels() };
    to_rgba(src, width, height, stride, channels, has_alpha)
}

fn to_rgba(
    src: &[u8],
    width: usize,
    height: usize,
    stride: usize,
    channels: usize,
    has_alpha: bool,
) -> Option<Vec<u8>> {
    if !matches!(channels, 3 | 4) || stride < width.checked_mul(channels)? {
        return None;
    }
    let mut out = Vec::with_capacity(width.checked_mul(height)?.checked_mul(4)?);
    for row in 0..height {
        let start = row.checked_mul(stride)?;
        let line = src.get(start..start.checked_add(width.checked_mul(channels)?)?)?;
        for pixel in line.chunks_exact(channels) {
            out.extend_from_slice(&pixel[..3]);
            out.push(if has_alpha { pixel[3] } else { u8::MAX });
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(connected: bool, interception: Interception) -> DaemonState {
        DaemonState {
            connected,
            interception,
        }
    }

    #[test]
    fn the_menu_maps_to_actions() {
        assert_eq!(Action::from_id(RULES_ID), Some(Action::Rules));
        assert_eq!(Action::from_id(QUIT_ID), Some(Action::Quit));
        assert_eq!(Action::from_id(""), None);
        assert_eq!(Action::from_id("whatever"), None);
    }

    #[test]
    fn each_daemon_state_says_something_different() {
        let on = describe(state(true, Interception::On));
        let paused = describe(state(true, Interception::Off));
        let gone = describe(state(false, Interception::Unknown));
        assert_ne!(on, paused);
        assert_ne!(on, gone);
        assert_ne!(paused, gone);
        assert!(paused.1.contains("paused"), "{}", paused.1);
        assert!(gone.1.contains("not connected"), "{}", gone.1);
        assert!(on.1.contains("filtered"), "{}", on.1);
        assert!(gone.0.contains("offline"), "{}", gone.0);
    }

    #[test]
    fn an_unknown_state_is_not_mistaken_for_paused() {
        let unknown = describe(state(true, Interception::Unknown));
        assert_eq!(unknown, describe(state(true, Interception::On)));
    }

    #[test]
    fn the_compiled_in_logo_is_a_square_rgba_image() {
        let logo = decode(ICON_PNG).expect("the icon must decode with gdk-pixbuf");
        assert_eq!(logo.width(), logo.height(), "the tray is square");
        assert!(
            logo.has_alpha(),
            "the logo must not be boxed in a background"
        );
    }

    #[test]
    fn rgb_pixels_gain_an_opaque_alpha() {
        let rgb = [0, 0, 0, 1, 2, 3];
        let rgba = to_rgba(&rgb, 2, 1, 6, 3, false).unwrap();
        assert_eq!(rgba, [0, 0, 0, 255, 1, 2, 3, 255]);
    }

    #[test]
    fn rows_may_be_longer_than_their_pixels() {
        let src = [9, 8, 7, 6, 0, 0, 1, 1, 1, 1, 0, 0];
        let rgba = to_rgba(&src, 1, 2, 6, 4, true).unwrap();
        assert_eq!(rgba, [9, 8, 7, 6, 1, 1, 1, 1]);
    }

    #[test]
    fn anything_but_8_bit_rgb_or_rgba_is_refused() {
        assert!(to_rgba(&[0, 0], 1, 1, 2, 2, true).is_none());
        assert!(
            to_rgba(&[0, 0, 0], 2, 1, 3, 3, false).is_none(),
            "stride too small"
        );
        assert!(to_rgba(&[0, 0, 0, 0], 1, 2, 4, 4, true).is_none());
    }

    #[test]
    fn an_icon_wider_than_the_buffer_is_refused() {
        assert!(to_rgba(&[], 1_000, 1_000, 0, 4, true).is_none());
    }
}
