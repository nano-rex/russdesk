//! A minimal plaintext SMTP client, std-only. For self-hosting the recommended
//! setup is a local relay (msmtp/postfix on localhost) that handles TLS to the
//! outside world; this speaks plain SMTP to that relay (or any host that accepts
//! it, optionally with AUTH LOGIN). No TLS is attempted here by design — we do
//! not hand-roll a TLS stack.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::encoding::base64_encode;

pub struct Mail<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub password: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
}

pub fn send(mail: &Mail) -> Result<(), String> {
    let addr = format!("{}:{}", mail.host, mail.port);
    let stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(20))).ok();
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);

    read_reply(&mut reader, 220)?;
    let ehlo = format!("EHLO {}\r\n", local_name());
    send_line(&mut writer, &ehlo)?;
    read_reply(&mut reader, 250)?;

    if !mail.user.is_empty() {
        send_line(&mut writer, "AUTH LOGIN\r\n")?;
        read_reply(&mut reader, 334)?;
        send_line(
            &mut writer,
            &format!("{}\r\n", base64_encode(mail.user.as_bytes())),
        )?;
        read_reply(&mut reader, 334)?;
        send_line(
            &mut writer,
            &format!("{}\r\n", base64_encode(mail.password.as_bytes())),
        )?;
        read_reply(&mut reader, 235)?;
    }

    send_line(&mut writer, &format!("MAIL FROM:<{}>\r\n", mail.from))?;
    read_reply(&mut reader, 250)?;
    send_line(&mut writer, &format!("RCPT TO:<{}>\r\n", mail.to))?;
    read_reply(&mut reader, 250)?;
    send_line(&mut writer, "DATA\r\n")?;
    read_reply(&mut reader, 354)?;

    let message = build_message(mail);
    writer
        .write_all(message.as_bytes())
        .map_err(|e| e.to_string())?;
    send_line(&mut writer, "\r\n.\r\n")?;
    read_reply(&mut reader, 250)?;
    send_line(&mut writer, "QUIT\r\n")?;
    Ok(())
}

fn build_message(mail: &Mail) -> String {
    let mut m = String::new();
    m.push_str(&format!("From: RussDesk <{}>\r\n", mail.from));
    m.push_str(&format!("To: {}\r\n", mail.to));
    m.push_str(&format!("Subject: {}\r\n", sanitize_header(mail.subject)));
    m.push_str("MIME-Version: 1.0\r\n");
    m.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    m.push_str("\r\n");
    // Dot-stuff lines beginning with '.' and normalise newlines to CRLF.
    for line in mail.body.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('.') {
            m.push('.');
        }
        m.push_str(line);
        m.push_str("\r\n");
    }
    m
}

fn sanitize_header(s: &str) -> String {
    s.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

fn local_name() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn send_line(w: &mut TcpStream, line: &str) -> Result<(), String> {
    w.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

fn read_reply(reader: &mut BufReader<TcpStream>, expect: u16) -> Result<(), String> {
    // SMTP multi-line replies: "250-foo" continues, "250 foo" ends.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("SMTP connection closed".to_string());
        }
        if line.len() < 3 {
            return Err(format!("bad SMTP reply: {}", line.trim()));
        }
        let code: u16 = line[..3].parse().map_err(|_| "bad SMTP code".to_string())?;
        let more = line.as_bytes().get(3) == Some(&b'-');
        if !more {
            if code != expect {
                return Err(format!("SMTP expected {expect}, got {}", line.trim()));
            }
            return Ok(());
        }
    }
}
