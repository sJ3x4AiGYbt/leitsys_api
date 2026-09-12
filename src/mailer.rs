use std::env;

use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

pub type Mailer = AsyncSmtpTransport<Tokio1Executor>;

/// Like `env::var`, but treats an unset *or* empty value as missing — an
/// empty placeholder left in a `.env` file should fail the same clear way
/// as an absent one, not surface as a cryptic error from inside `lettre`.
pub fn required_env(key: &str) -> anyhow::Result<String> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => anyhow::bail!("{key} environment variable must be set"),
    }
}

/// Builds the SMTP transport from `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/
/// `SMTP_PASSWORD`. Fails fast at startup rather than discovering a
/// misconfiguration the first time a user tries to register.
pub fn build_mailer() -> anyhow::Result<Mailer> {
    let host = required_env("SMTP_HOST")?;
    let port: u16 = required_env("SMTP_PORT")?
        .parse()
        .map_err(|_| anyhow::anyhow!("SMTP_PORT must be a valid port number"))?;
    let username = required_env("SMTP_USERNAME")?;
    let password = required_env("SMTP_PASSWORD")?;

    let creds = Credentials::new(username, password);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&host)?
        .port(port)
        .credentials(creds)
        .build();

    Ok(mailer)
}

pub async fn send_verification_email(
    mailer: &Mailer,
    from: &str,
    to_email: &str,
    to_username: &str,
    verification_link: &str,
) -> anyhow::Result<()> {
    let body = format!(
        "Hi {to_username},\n\n\
         Please confirm your email address by opening this link:\n\
         {verification_link}\n\n\
         This link expires in 24 hours. If you didn't create this account, \
         you can safely ignore this email.",
    );

    let email = Message::builder()
        .from(from.parse()?)
        .to(format!("{to_username} <{to_email}>").parse()?)
        .subject("Confirm your email address")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    AsyncTransport::send(mailer, email).await?;
    Ok(())
}

pub async fn send_password_reset_email(
    mailer: &Mailer,
    from: &str,
    to_email: &str,
    to_username: &str,
    reset_link: &str,
) -> anyhow::Result<()> {
    let body = format!(
        "Hi {to_username},\n\n\
         We received a request to reset your password. Open this link to choose a new one:\n\
         {reset_link}\n\n\
         This link expires in 1 hour. If you didn't request this, you can safely ignore this email.",
    );

    let email = Message::builder()
        .from(from.parse()?)
        .to(format!("{to_username} <{to_email}>").parse()?)
        .subject("Reset your password")
        .header(ContentType::TEXT_PLAIN)
        .body(body)?;

    AsyncTransport::send(mailer, email).await?;
    Ok(())
}
