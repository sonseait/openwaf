//! Static local maintenance page. Message is plain text, never trusted HTML.
pub fn html(
    message: &str,
    retry_after_seconds: u32,
    request_id: &str,
    client_ip: Option<std::net::IpAddr>,
    location: &crate::error_pages::Location,
) -> String {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    let page =
        include_str!("maintenance.html").replace("{{retry}}", &retry_after_seconds.to_string());
    crate::error_pages::request_metadata_html(&page, request_id, client_ip, location)
        .replace("{{message}}", &escaped)
}
#[cfg(test)]
mod tests {
    #[test]
    fn page_escapes_message_and_contains_no_remote_assets() {
        let page = super::html(
            "<script>alert('x')</script>&",
            300,
            "<reference>&\"'",
            Some("::ffff:192.0.2.1".parse().expect("IP")),
            &crate::error_pages::Location::country("GB"),
        );
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;"));
        assert!(!page.contains("{{"));
        assert!(!page.contains("https://"));
        assert!(page.contains("300"));
        assert!(page.contains("&lt;reference&gt;&amp;&quot;&#39;"));
        assert!(page.contains("<code>192.0.2.1</code>"));
        assert!(page.contains("GB (GeoIP country)"));
        let unknown = super::html(
            "literal {{retry}} {{reference}} {{client_ip}} {{location}}",
            300,
            &"a".repeat(64),
            None,
            &crate::error_pages::Location::Unavailable,
        );
        assert!(unknown.contains("literal {{retry}} {{reference}} {{client_ip}} {{location}}"));
        assert!(unknown.contains("<code>Unknown</code>"));
        assert!(unknown.contains("Unknown (GeoIP unavailable)"));
    }
}
