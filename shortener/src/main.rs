//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::{Context, Result};
use axum::extract::{FromRef, FromRequestParts, Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{Html, IntoResponse};
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::{Cookie, Key};
use chrono::{Duration, Local};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, TokenUrl};
use oauth2::{TokenResponse, reqwest};
use serde::Deserialize;
use std::env;
use std::process::exit;
use std::sync::Arc;
use tokio_postgres::{Client, NoTls};
use tracing::error;
use utils::logging;

const OAUTH_BASE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const OAUTH_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const OAUTH_TOKEN_INFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

const HOST: &str = "http://localhost:3000";
const AUTHORIZED_ROUTE: &str = "/authorized";
const AUTH_REDIRECT_URL: &str = "http://localhost:3000/authorized";

const SHORT_URL: &str = "short_url";
const COOKIE_SID: &str = "sid";
const COOKIE_DOMAIN: &str = ".app.localhost";

const ALLOWED_OAUTH_DOMAIN: &str = "neon.tech";

struct State {
    db_client: Client,
    oauth_client_id: String,
    oauth_client: BasicClient,
    cookie_jar_key: Key,
}

impl FromRef<State> for Key {
    fn from_ref(state: &State) -> Self {
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

    let oauth_client_id = env::var("OAUTH_CLIENT_ID").context("Missing OAUTH_CLIENT_ID")?;
    let oauth_client_secret =
        env::var("OAUTH_CLIENT_SECRET").context("Missing OAUTH_CLIENT_SECRET")?;
    let auth_url = AuthUrl::new(OAUTH_BASE_URL.to_string()).context("Invalid OAUTH_BASE_URL")?;
    let token_url =
        TokenUrl::new(OAUTH_TOKEN_URL.to_string()).context("Invalid OAUTH_TOKEN_URL")?;
    let oauth_client = BasicClient::new(
        ClientId::new(oauth_client_id),
        Some(ClientSecret::new(oauth_client_secret)),
        auth_url,
        Some(token_url),
    );

    let db_connstr = env::var("DB_CONNSTR").context("Missing DB_CONNSTR")?;
    let (db_client, db_conn) = tokio_postgres::connect(&db_connstr, NoTls).await?;
    tokio::spawn(async move {
        if let Err(err) = db_conn.await {
            error!(%err, "connecting to database");
            exit(1);
        }
    });

    let state = Arc::new(State {
        db_client,
        cookie_jar_key: Key::generate(),
        oauth_client_id,
        oauth_client,
    });

    let router = Router::new()
        .route("/authorized", get(authorized))
        .route("/{short_url}", get(redirect))
        .route("/", get(index).post(shorten))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(HOST)
        .await
        .context("failed to bind TcpListener")
        .unwrap();
    tracing::info!(
        "listening on {}",
        listener
            .local_addr()
            .context("failed to return local address")
            .unwrap()
    );
    axum::serve(listener, router).await.unwrap();
    Ok(())
}

#[derive(Deserialize)]
pub struct User {
    id: i32, // TODO postgres_types::SERIAL ?
}

impl axum::extract::OptionalFromRequestParts<Arc<State>> for User {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<State>,
    ) -> Result<Option<Self>, Self::Rejection> {
        let jar: PrivateCookieJar = PrivateCookieJar::from_request_parts(parts, state.as_ref())
            .await
            .unwrap();
        let Some(cookie) = jar.get(COOKIE_SID).map(|cookie| cookie.value().to_owned()) else {
            return Ok(None);
        };

        let query = state
            .db_client
            .query_opt(
                "FROM sessions SELECT user_id WHERE session_id = $1 LIMIT 1",
                &[&cookie],
            )
            .await;
        let id = match query {
            Ok(Some(row)) => row.get::<usize, i32>(0),
            Ok(None) => return Ok(None),
            Err(err) => {
                error!(%err, "querying user session");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };
        Ok(Some(Self { id }))
    }
}

#[derive(Deserialize)]
struct LongUrl {
    url: String,
}

fn shorten_form(short_url: &str) -> Html<String> {
    Html(format!(
        "<form>\
        <input type=\"text\" name=\"url\"><br>\
        <input type=\"submit\" value=\"Shorten\">\
        </form><br>\
        <p><a href=\"{short_url}\">{short_url}</a></p>"
    ))
}

fn oauth_url(oauth_client_id: &str, short_url: &str) -> String {
    // If we follow short link unauthorized, we want to redirect to Oauth page, then to our
    // auth callback, and then to the target url. For that we need to pass a ?SHORT_URL=
    // parameter to our auth callback, and we need to encode it in Oauth page url.
    // %3F is ?, %3D is =
    format!(
        "{OAUTH_BASE_URL}?scope=email&client_id={oauth_client_id}\
            &hosted_domain=neon.tech\
            &response_type=code&redirect_uri={AUTH_REDIRECT_URL}\
            %3F{SHORT_URL}%3D{short_url}"
    )
}

async fn index(state: AxumState<Arc<State>>, user: Option<User>) -> Html<String> {
    if user.is_some() {
        shorten_form("")
    } else {
        let oauth_url = oauth_url(&state.oauth_client_id, "");
        Html(format!("<a href=\"{oauth_url}\">Authorize</a>"))
    }
}

async fn shorten(
    state: AxumState<Arc<State>>,
    user: Option<User>,
    Form(LongUrl { url }): Form<LongUrl>,
) -> Response {
    let user_id = match user {
        None => return StatusCode::FORBIDDEN.into_response(),
        Some(user) => user.id,
    };
    let short_url = nanoid::nanoid!(6);

    let query = state
        .db_client
        .query_one(
            "INSERT INTO urls (user_id, short_url, long_url) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (long_url) DO NOTHING \
             RETURNING short_url",
            &[&user_id, &short_url, &url],
        )
        .await;
    let row = match query {
        Ok(row) => row,
        Err(err) => {
            error!(%err, "inserting shortened url");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let short_url: &str = row.get(0);
    shorten_form(&format!("{HOST}/{short_url}")).into_response()
}

async fn redirect(
    state: AxumState<Arc<State>>,
    user: Option<User>,
    Path(short_url): Path<String>,
) -> Response {
    if user.is_none() {
        return Redirect::permanent(&oauth_url(&state.oauth_client_id, &short_url)).into_response();
    };
    let user_id = user.unwrap().id;

    let query = state
        .db_client
        .query_one(
            "FROM urls SELECT long_url WHERE short_url = $1",
            &[&short_url],
        )
        .await;
    let row = match query {
        Ok(row) => row,
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
    short_url: Option<String>,
}

#[derive(Deserialize)]
struct AuthResponse {
    hd: String,
    sub: String,
}

// TODO csrf, pkce
async fn authorized(
    state: AxumState<Arc<State>>,
    jar: PrivateCookieJar,
    Query(AuthRequest { code, short_url }): Query<AuthRequest>,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    let token = state
        .oauth_client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(reqwest::async_http_client)
        .await
        .map_err(|err| {
            error!(%err, "exchanging oauth code for token");
            StatusCode::UNAUTHORIZED.into_response()
        })?;
    let secret = token.access_token().secret();

    let AuthResponse { hd, sub } = ::reqwest::Client::new()
        .get(OAUTH_TOKEN_INFO_URL)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|err| {
            error!(%err, "getting user id with token");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?
        .json()
        .await
        .map_err(|err| {
            error!(%err, "deserializing response with used id");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    if hd != ALLOWED_OAUTH_DOMAIN {
        error!(%hd, "Domain doesn't match allowed {ALLOWED_OAUTH_DOMAIN}");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    let Some(secs) = token.expires_in() else {
        error!("Token doesn't include expiration time, rejecting");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let cookie = Cookie::build((COOKIE_SID, secret))
        .domain(COOKIE_DOMAIN)
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(secs);

    let user_id_row = state
        .db_client
        .query_one(
            "INSERT INTO users (sub) VALUES ($1) \
         ON CONFLICT (sub) DO NOTHING \
         RETURNING user_id",
            &[&sub],
        )
        .await
        .map_err(|err| {
            error!(%err, %sub, "inserting or querying user");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        })?;
    let user_id: i32 = user_id_row.get(0);

    let expires_at =
        Local::now().naive_local() + Duration::try_seconds(secs.as_secs() as i64).unwrap();
    state
        .db_client
        .query_opt(
            "INSERT INTO sessions (user_id, session_id, expires_at) VALUES ($1, $2, $3) \
            ON CONFLICT (user_id) DO UPDATE SET \
            session_id = excluded.session_id,\
            expires_at = excluded.expires_at",
            &[&user_id, token.access_token().secret(), &expires_at],
        )
        .await
        .map_err(|err| {
            error!(%err, %user_id, "updating session info");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        })?;

    // we can save one redirect for user by redirecting not to /short_url,
    // but to queried long url directly
    Ok((
        jar.add(cookie),
        Redirect::to(&format!("/{}", short_url.unwrap_or_default())),
    ))
}
