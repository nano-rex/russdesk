//! Outgoing email over SMTP (Settings > SMTP). Port of mail.py, using our own
//! plaintext SMTP client (crate::smtp). For TLS to external providers, point the
//! SMTP host at a local relay (msmtp/postfix) that does the TLS.

use crate::db::Settings;
use crate::smtp::{self, Mail};
use crate::web::HttpError;

pub fn configured(s: &Settings) -> bool {
    !s.smtp_host.is_empty() && !s.smtp_from.is_empty()
}

/// Send a plain-text message; returns an HttpError with a readable reason.
pub fn send(s: &Settings, to: &str, subject: &str, body: &str) -> Result<(), HttpError> {
    if !configured(s) {
        return Err(HttpError::new(
            400,
            "Email is not set up: fill in Settings > SMTP first",
        ));
    }
    if !to.contains('@') {
        return Err(HttpError::new(400, "Invalid recipient address"));
    }
    let port = if s.smtp_port > 0 {
        s.smtp_port as u16
    } else {
        587
    };
    let mail = Mail {
        host: &s.smtp_host,
        port,
        user: &s.smtp_user,
        password: &s.smtp_password,
        from: &s.smtp_from,
        to,
        subject,
        body,
    };
    smtp::send(&mail).map_err(|e| HttpError::new(502, format!("Could not send email: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_needs_host_and_from() {
        let mut s = Settings::default();
        assert!(!configured(&s));
        s.smtp_host = "smtp.example.com".into();
        assert!(!configured(&s));
        s.smtp_from = "rd@example.com".into();
        assert!(configured(&s));
    }

    #[test]
    fn send_unconfigured_errors() {
        let s = Settings::default();
        assert_eq!(send(&s, "a@b.com", "hi", "body").unwrap_err().status, 400);
    }
}
