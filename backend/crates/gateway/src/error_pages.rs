//! Local gateway errors only. Never rewrite an upstream response or a started stream.
pub const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox";

#[derive(Default)]
pub enum Location {
    Country([u8; 2]),
    #[default]
    Unknown,
    Unavailable,
    LookupFailed,
}
impl Location {
    pub fn country(code: &str) -> Self {
        match code.as_bytes() {
            [a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => Self::Country([*a, *b]),
            _ => Self::Unknown,
        }
    }
    fn label(&self) -> String {
        match self {
            Self::Country([a, b]) if a.is_ascii_uppercase() && b.is_ascii_uppercase() => {
                format!("{}{} (GeoIP country)", char::from(*a), char::from(*b))
            }
            Self::Country(_) | Self::Unknown => "Unknown".into(),
            Self::Unavailable => "Unknown (GeoIP unavailable)".into(),
            Self::LookupFailed => "Unknown (GeoIP lookup failed)".into(),
        }
    }
}

pub fn message(status: u16) -> &'static str {
    match status {
        400 => "The request could not be understood. Check the address and try again.",
        403 => "Request blocked by security policy.",
        404 => "No service is configured for this address. Check the URL and try again.",
        405 => "This request method is not supported for this address.",
        408 => "The request took too long to arrive. Please try again.",
        413 => "Request body exceeds the permitted size.",
        415 => "This content type is not supported for this address.",
        429 => "Too many requests. Please retry later.",
        502 => "The upstream service could not complete the request.",
        503 => "The service is temporarily unavailable.",
        504 => "The request deadline was exceeded.",
        508 => "The request could not be routed safely.",
        _ => "The request could not be completed.",
    }
}

pub fn default_html(
    status: u16,
    request_id: &str,
    client_ip: Option<std::net::IpAddr>,
    location: &Location,
) -> String {
    let title = match status {
        403 => "This request was blocked",
        404 => "Nothing here just yet",
        413 => "A little too much to send",
        429 => "Let’s take a short pause",
        502..=504 => "We can’t reach this service",
        _ => "We couldn’t complete your request",
    };
    let page = include_str!("error_page.html")
        .replace("{{status}}", &status.to_string())
        .replace("{{title}}", title)
        .replace("{{message}}", message(status));
    request_metadata_html(&page, request_id, client_ip, location)
}

pub(crate) fn request_metadata_html(
    template: &str,
    request_id: &str,
    client_ip: Option<std::net::IpAddr>,
    location: &Location,
) -> String {
    // Keep both local page renderers safe if future callers supply a non-generated ID.
    let reference = request_id
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    template
        .replace(
            "{{client_ip}}",
            &client_ip
                .map(openwaf_config::normalized_ip)
                .map_or_else(|| "Unknown".into(), |ip| ip.to_string()),
        )
        .replace("{{location}}", &location.label())
        .replace("{{reference}}", &reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_page_is_self_contained_and_escapes_reference() {
        let html = default_html(
            403,
            "<script>\"'&",
            Some("2001:db8::1".parse().expect("IP")),
            &Location::country("GB"),
        );
        assert!(html.contains("This request was blocked"));
        assert!(html.contains("&lt;script&gt;&quot;&#39;&amp;"));
        assert!(!html.contains("{{"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("https://"));
        assert!(html.contains("prefers-color-scheme: dark"));
        assert!(html.contains("2001:db8::1"));
        assert!(html.contains("GB (GeoIP country)"));
    }

    #[test]
    fn missing_location_and_invalid_country_are_explicit() {
        for location in [
            Location::Unknown,
            Location::Unavailable,
            Location::LookupFailed,
            Location::country("<script>"),
        ] {
            let html = default_html(404, &"a".repeat(64), None, &location);
            assert!(html.contains("Unknown"));
            assert!(!html.contains("<script>"));
            assert!(!html.contains("{{"));
        }
    }
}
