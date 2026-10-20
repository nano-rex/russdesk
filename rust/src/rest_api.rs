//! RustDesk Server Pro-compatible REST API. Port of rest_api.py (in progress).
//! Routes are registered here; see MIGRATION.md for status.

use crate::app::App;
use crate::web::Router;

pub fn register(_r: &mut Router<App>) {
    // Ported incrementally in M4; see rest_api.py.
}
