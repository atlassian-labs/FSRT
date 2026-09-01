//! Browser-backed harvesting of the `tenant.session.token` cookie.
//!
//! This module is compiled only with the `mint_cookie` feature because it needs
//! an async WebDriver client. The rest of FSRT remains synchronous.

use std::{path::PathBuf, time::Duration};

use clap::{Args, ValueHint};
use thirtyfour::ChromeCapabilities;
use thirtyfour::prelude::*;
use url::Url;

use crate::Result;

const COOKIE_NAME: &str = "tenant.session.token";
const LOGIN_URL: &str = "https://id.atlassian.com/login";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_VERIFY_WAIT_SECS: u64 = 120;

/// Harvest an Atlassian session cookie via a browser login.
#[derive(Args, Debug)]
pub(crate) struct MintCookieArgs {
    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Show the browser window for MFA, bot checks, or other manual steps.
    #[arg(long, default_value_t = false)]
    headed: bool,
}

struct HarvestConfig {
    username: String,
    password: String,
    site_url: String,
    output: PathBuf,
    headed: bool,
    timeout: Duration,
    verify_wait: Duration,
}

impl MintCookieArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        false
    }
}

pub(super) fn run(args: &MintCookieArgs) -> Result<()> {
    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let cookie = config.cookie.as_ref().ok_or_else(|| {
        std::io::Error::other(
            "session-cookie harvesting requires a [cookie] section with username in fsrt-remote.toml",
        )
    })?;
    let password = std::env::var("ATL_PASSWORD").map_err(|_| {
        std::io::Error::other(
            "ATL_PASSWORD is not set; export the account password before running mint-cookie",
        )
    })?;
    if password.is_empty() {
        return Err(std::io::Error::other("ATL_PASSWORD is set but empty").into());
    }

    let harvest = HarvestConfig {
        username: cookie.username.clone(),
        password,
        site_url: config.site.to_string(),
        output: PathBuf::from(&config.auth.raw_cookie_file),
        headed: args.headed || cookie.headed.unwrap_or(false),
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        verify_wait: Duration::from_secs(
            cookie.verify_wait_secs.unwrap_or(DEFAULT_VERIFY_WAIT_SECS),
        ),
    };

    println!("Harvesting a session cookie for {}", harvest.site_url);
    tokio::runtime::Runtime::new()?.block_on(async {
        let output = harvest.output.clone();
        let driver = build_driver(&harvest).await?;
        let value = driver
            .run_and_quit(async move |driver| run_flow(&driver, &harvest).await)
            .await?;
        std::fs::write(&output, format!("{COOKIE_NAME}={value}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!("Wrote {COOKIE_NAME} to {}", output.display());
        eprintln!("Warning: this file is a bearer credential; do not commit or share it.");
        Ok(())
    })
}

async fn build_driver(config: &HarvestConfig) -> Result<WebDriver> {
    let mut capabilities = ChromeCapabilities::new();
    if !config.headed {
        capabilities.add_arg("--headless=new")?;
    }

    let driver = WebDriver::managed(capabilities).match_local().await?;
    driver.set_implicit_wait_timeout(Duration::ZERO).await?;
    Ok(driver)
}

async fn run_flow(driver: &WebDriver, config: &HarvestConfig) -> Result<String> {
    let mut login_url = Url::parse(LOGIN_URL)?;
    login_url
        .query_pairs_mut()
        .append_pair("email", &config.username)
        .append_pair("continue", &config.site_url);
    driver.goto(login_url.as_str()).await?;
    click_continue(driver, config.timeout).await?;

    let password = query_clickable(driver, "input[name='password']", config.timeout).await?;
    type_into(&password, &config.password).await?;
    click_continue(driver, config.timeout).await?;

    let deadline = std::time::Instant::now() + config.timeout;
    while std::time::Instant::now() < deadline {
        if matches!(driver.current_url().await, Ok(url) if !url.as_str().contains("id.atlassian.com"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if config.headed {
        println!("Complete any login step in Chrome, then press ENTER.");
        let read_line = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
        });
        tokio::select! {
            _ = read_line => {},
            _ = tokio::time::sleep(config.verify_wait) => {},
        }
    }

    let deadline = std::time::Instant::now() + config.timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(cookie) = driver.get_named_cookie(COOKIE_NAME).await
            && !cookie.value.is_empty()
        {
            return Ok(cookie.value);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let current_page = driver.current_url().await.ok().map(|mut url| {
        url.set_query(None);
        url.set_fragment(None);
        url
    });
    let current_page = current_page
        .as_ref()
        .map(|url| format!("; current page: {url}"))
        .unwrap_or_default();
    Err(std::io::Error::other(format!(
        "could not obtain {COOKIE_NAME}{current_page}; retry with --headed to complete any interactive login step"
    ))
    .into())
}

async fn click_continue(driver: &WebDriver, timeout: Duration) -> Result<()> {
    let button = query_clickable(
        driver,
        "button[data-testid='login-submit-idf-testid']",
        timeout,
    )
    .await?;
    button.click().await?;
    Ok(())
}

async fn query_clickable(driver: &WebDriver, css: &str, timeout: Duration) -> Result<WebElement> {
    Ok(driver
        .query(By::Css(css))
        .wait(timeout, Duration::from_millis(250))
        .and_clickable()
        .first()
        .await?)
}

async fn type_into(field: &WebElement, text: &str) -> Result<()> {
    field.click().await?;
    field.clear().await?;
    field.send_keys(text).await?;
    Ok(())
}
