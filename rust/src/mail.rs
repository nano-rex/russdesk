//! Outgoing email over SMTP (Settings > SMTP). Port of mail.py.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::db::Settings;
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
    let from: Mailbox = format!("RussDesk <{}>", s.smtp_from)
        .parse()
        .map_err(|_| HttpError::new(400, "Invalid SMTP from address"))?;
    let to_box: Mailbox = to
        .parse()
        .map_err(|_| HttpError::new(400, "Invalid recipient address"))?;
    let email = Message::builder()
        .from(from)
        .to(to_box)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| HttpError::new(500, format!("Could not build email: {e}")))?;

    let host = s.smtp_host.as_str();
    let port = s.smtp_port as u16;
    let mut builder = match s.smtp_security.as_str() {
        "ssl" => SmtpTransport::relay(host)
            .map_err(smtp_err)?
            .port(if port != 0 { port } else { 465 }),
        "starttls" => SmtpTransport::starttls_relay(host)
            .map_err(smtp_err)?
            .port(if port != 0 { port } else { 587 }),
        _ => SmtpTransport::builder_dangerous(host).port(if port != 0 { port } else { 587 }),
    };
    if !s.smtp_user.is_empty() {
        builder = builder.credentials(Credentials::new(
            s.smtp_user.clone(),
            s.smtp_password.clone(),
        ));
    }
    let transport = builder.build();
    transport.send(&email).map_err(smtp_err)?;
    Ok(())
}

fn smtp_err(e: lettre::transport::smtp::Error) -> HttpError {
    HttpError::new(502, format!("Could not send email: {e}"))
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
        let err = send(&s, "a@b.com", "hi", "body").unwrap_err();
        assert_eq!(err.status, 400);
    }
}
