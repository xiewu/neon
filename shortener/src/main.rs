//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::Result;
use axum::Form;
use axum::extract::{FromRef, FromRequestParts, Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key};
use base64::decode_config;
use chrono::{Duration, Local, TimeZone, Utc};
use core::num::NonZeroI32;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tracing::{error, info};
use utils::logging;

const OAUTH_BASE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

const SOCKET: &str = "127.0.0.1:12344";
const HOST: &str = "http://127.0.0.1:12344";
const AUTHORIZED_ROUTE: &str = "/authorized";
const AUTH_REDIRECT_URL: &str = "http://127.0.0.1:12344/authorized";

const COOKIE_SID: &str = "sid";
const COOKIE_REDIRECT: &str = "redirect";
const COOKIE_CSRF: &str = "csrf";

const ALLOWED_COOKIE_DOMAIN: &str = ".app.localhost";
const ALLOWED_OAUTH_DOMAIN: &str = "neon.tech";

struct AppState {
    db_client: tokio_postgres::Client,
    oauth_client: BasicClient,
    oauth_client_id: String,
    oauth_client_secret: String,
    cookie_jar_key: Key,
}

// ugly but we need separate type to impl FromRef
#[derive(Clone)]
struct State {
    state: Arc<AppState>,
}

impl FromRef<State> for Key {
    fn from_ref(state: &State) -> Self {
        state.state.cookie_jar_key.clone()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_jar_key.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init(
        logging::LogFormat::Plain,
        logging::TracingErrorLayerEnablement::EnableWithRustLogFilter,
        logging::Output::Stdout,
    )?;

    let oauth_client_id = env::var("OAUTH_CLIENT_ID").expect("Missing OAUTH_CLIENT_ID");
    let oauth_client_secret = env::var("OAUTH_CLIENT_SECRET").expect("Missing OAUTH_CLIENT_SECRET");

    let redirect_url = RedirectUrl::new(AUTH_REDIRECT_URL.to_string()).unwrap();
    let auth_url = AuthUrl::new(OAUTH_BASE_URL.to_string()).unwrap();
    let token_url = TokenUrl::new(OAUTH_TOKEN_URL.to_string()).unwrap();

    let oauth_client = BasicClient::new(
        ClientId::new(oauth_client_id.clone()),
        Some(ClientSecret::new(oauth_client_secret.clone())),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url);
    info!("initialized oauth client");

    let db_connstr = env::var("DB_CONNSTR").expect("Missing DB_CONNSTR");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(cert).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
    info!("initialized TLS");

    let (db_client, db_conn) = tokio_postgres::connect(&db_connstr, tls).await?;
    tokio::spawn(async move {
        if let Err(err) = db_conn.await {
            error!(%err, "connecting to database");
            std::process::exit(1);
        }
    });
    info!("connected to DB");

    let state = Arc::new(AppState {
        db_client,
        cookie_jar_key: Key::generate(),
        oauth_client,
        oauth_client_id,
        oauth_client_secret,
    });
    let state = State { state };

    let router = axum::Router::new()
        .route("/", get(index).post(shorten))
        .route("/authorize", get(authorize))
        .route(AUTHORIZED_ROUTE, get(authorized))
        .route("/{short_url}", get(redirect))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(SOCKET)
        .await
        .expect("failed to bind TcpListener");
    info!("listening on {SOCKET}");
    axum::serve(listener, router).await.unwrap();
    Ok(())
}

#[derive(Deserialize)]
pub struct UserId {
    id: NonZeroI32,
}

impl axum::extract::OptionalFromRequestParts<State> for UserId {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        let jar: PrivateCookieJar =
            PrivateCookieJar::from_request_parts(parts, state.state.as_ref())
                .await
                .unwrap(); // infallible
        let Some(session_id) = jar.get(COOKIE_SID).map(|cookie| cookie.value().to_owned()) else {
            return Ok(None);
        };

        let client = &state.state.db_client;
        let query = client
            .query_opt(
                "SELECT user_id FROM sessions WHERE session_id = $1",
                &[&session_id],
            )
            .await;
        let id = match query {
            Ok(Some(row)) => row.get::<usize, i32>(0),
            Ok(None) => return Ok(None),
            Err(err) => {
                error!(%err, "querying user session");
                return Ok(None);
            }
        };
        let id = NonZeroI32::new(id).unwrap(); // postgres id guaranteed not to be zero
        Ok(Some(Self { id }))
    }
}

#[derive(Deserialize)]
struct LongUrl {
    url: String,
}

fn shorten_form(short_url: &str) -> Html<String> {
    let mut form = r#"
        <div style="margin:auto;width:50%;padding:10px">
            <form method="post">
                <input type="text" name="url" style="width:100%">
                <input type="submit" value="Shorten" style="margin-top:10px">
            </form>"#
        .to_string();
    if !short_url.is_empty() {
        form += &format!(
            r#"
            <p>
                <a id="short" href="{0}">{0}</a>
                <button onclick="copy()">Copy</button>
            </p>
            <script>
                function copy() {{
                    navigator.clipboard.writeText(document.querySelector("\#short").textContent);
                }}
            </script>"#,
            short_url
        );
    }
    form += "</div>";
    Html(form)
}

fn authorize_link(short_url: &str) -> String {
    format!("<a href=\"/authorize?short_url={short_url}\">Authorize</a>")
}

async fn index(user: Option<UserId>) -> Html<String> {
    if user.is_some() {
        return shorten_form("");
    }
    Html(authorize_link(""))
}

async fn shorten(
    state: AxumState<State>,
    user: Option<UserId>,
    Form(LongUrl { url }): Form<LongUrl>,
) -> Response {
    let user_id = match user {
        None => return StatusCode::FORBIDDEN.into_response(),
        Some(user) => user.id,
    };
    if url.is_empty() {
        return shorten_form("").into_response();
    }

    let mut short_url = "".to_string();
    for i in 0..20 {
        short_url = nanoid::nanoid!(6);
        let query = state
            .state
            .db_client
            .query_opt(
                "INSERT INTO urls (user_id, short_url, long_url) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (short_url) DO NOTHING \
                 RETURNING short_url",
                &[&user_id.get(), &short_url, &url],
            )
            .await;
        match query {
            Ok(Some(_)) => break,
            Ok(None) => {
                info!(short_url, "url clash, retry {i}");
                continue;
            }
            Err(err) => {
                error!(%err, "inserting shortened url");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    }
    shorten_form(&format!("{HOST}/{short_url}")).into_response()
}

async fn redirect(
    state: AxumState<State>,
    user: Option<UserId>,
    Path(short_url): Path<String>,
) -> Response {
    let user_id = match user {
        None => return Html(authorize_link(&short_url)).into_response(),
        Some(user) => user.id,
    };

    let query = state
        .state
        .db_client
        .query_opt(
            "SELECT long_url FROM urls WHERE short_url = $1",
            &[&short_url],
        )
        .await;
    let row = match query {
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Some(row)) => row,
        Err(err) => {
            error!(%err, %short_url, %user_id, "querying long url");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Redirect::permanent(row.get(0)).into_response()
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
    id_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct UserInfo {
    hd: String,
    sub: String,
}

fn decode_id_token(id_token: String) -> Option<UserInfo> {
    let id_token = id_token.split(".").skip(1).take(1).collect::<Vec<&str>>();
    let id_token = id_token.get(0)?;
    let id_token = decode_config(*id_token, base64::STANDARD_NO_PAD).ok()?;
    serde_json::from_slice::<UserInfo>(&id_token).ok()
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    short_url: String,
}

async fn authorize(
    state: AxumState<State>,
    jar: PrivateCookieJar,
    Query(AuthorizeQuery { short_url }): Query<AuthorizeQuery>,
) -> (PrivateCookieJar, Redirect) {
    let (auth_url, csrf_token) = state
        .state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .url();

    let redirect_cookie = Cookie::build((COOKIE_REDIRECT, short_url))
        .path("/")
        //.TODO secure(true) not true for localhost
        //.domain(COOKIE_DOMAIN)
        .secure(false)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .http_only(true)
        .build();
    let csrf_cookie = Cookie::build((COOKIE_CSRF, csrf_token.secret().to_string()))
        .path("/")
        //.TODO secure(true) not true for localhost
        //.domain(COOKIE_DOMAIN)
        .secure(false)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .http_only(true)
        .build();
    let jar = jar.add(redirect_cookie).add(csrf_cookie);
    let url = Into::<String>::into(auth_url);
    (jar, Redirect::to(&url))
}

async fn authorized(
    state: AxumState<State>,
    jar: PrivateCookieJar,
    Query(auth_request): Query<AuthRequest>,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    let params = [
        ("grant_type", "authorization_code"),
        ("redirect_uri", AUTH_REDIRECT_URL),
        ("code", &auth_request.code),
        ("client_id", &state.state.oauth_client_id),
        ("client_secret", &state.state.oauth_client_secret),
    ];
    let auth_response = ::reqwest::Client::new()
        .post(OAUTH_TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|err| {
            error!(%err, "exchanging oauth code for token");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?
        .json::<AuthResponse>()
        .await
        .map_err(|err| {
            error!(%err, "deserializing access token response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    let Some(UserInfo { hd, sub }) = decode_id_token(auth_response.id_token) else {
        error!("Failed to decode response id token");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    if hd != ALLOWED_OAUTH_DOMAIN {
        error!(hd, "Domain doesn't match {ALLOWED_OAUTH_DOMAIN}");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    let token_duration = Duration::try_seconds(auth_response.expires_in as i64).unwrap();
    let expires_at = Utc.from_utc_datetime(&(Local::now().naive_local() + token_duration));
    let cookie_max_age = time::Duration::new(token_duration.num_seconds(), 0);

    let session_cookie = Cookie::build((COOKIE_SID, auth_response.access_token.clone()))
        .path("/")
        //.TODO secure(true) not true for localhost
        //.domain(COOKIE_DOMAIN)
        .secure(false)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .http_only(true)
        .max_age(cookie_max_age)
        .build();

    state
        .state
        .db_client
        .query(
            "WITH user_insert AS (\
                INSERT INTO users (sub) VALUES ($1) \
                ON CONFLICT (sub) DO UPDATE SET sub = excluded.sub RETURNING id)\
        INSERT INTO sessions (user_id, session_id, expires_at) \
        SELECT id, $2, $3 FROM user_insert \
        ON CONFLICT (user_id) DO UPDATE SET \
            session_id = excluded.session_id, \
             expires_at = excluded.expires_at",
            &[&sub, &auth_response.access_token, &expires_at],
        )
        .await
        .map_err(|err| {
            error!(%err, %sub, "updating session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        })?;

    let csrf_cookie = jar.get(COOKIE_CSRF).unwrap(); // set in authorize()
    let jar = jar.remove(csrf_cookie).add(session_cookie);
    match jar.get(COOKIE_REDIRECT) {
        Some(redirect_cookie) => {
            let redirect_url = format!("/{}", redirect_cookie.value_trimmed());
            Ok((jar.remove(redirect_cookie), Redirect::to(&redirect_url)))
        }
        None => Ok((jar, Redirect::to("/"))),
    }
}
