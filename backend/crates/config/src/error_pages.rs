//! Inline static HTML only: no templates, remote fetches or filesystem reads.
use crate::{Snapshot, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_HTML_BYTES: usize = 16 * 1024;
pub const MAX_PAGES: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub status: u16,
    pub html: String,
}

pub fn validate(pages: &[Page]) -> Result<(), Validation> {
    let mut statuses = BTreeSet::new();
    if pages.len() > MAX_PAGES
        || pages.iter().any(|page| {
            !(400..=599).contains(&page.status)
                || !statuses.insert(page.status)
                || page.html.trim().is_empty()
                || page.html.len() > MAX_HTML_BYTES
                || page.html.contains('\0')
        })
    {
        return Err(Validation::ErrorPages);
    }
    Ok(())
}

impl Snapshot {
    /// Exact status: route override, global override, then gateway default.
    /// Borrowed from the request's immutable snapshot for its entire lifetime.
    pub fn error_page(&self, route: Option<usize>, status: u16) -> Option<&str> {
        route
            .and_then(|i| self.document.routes.get(i))
            .into_iter()
            .flat_map(|r| &r.error_pages)
            .chain(&self.document.error_pages)
            .find(|page| page.status == status)
            .map(|page| page.html.as_str())
    }
}
