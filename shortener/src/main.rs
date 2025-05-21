//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::Result;
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
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use oauth2::{TokenResponse, reqwest};
use serde::Deserialize;
use std::env;
use std::process::exit;
use std::sync::Arc;
use tokio_postgres::Client;
use tracing::{debug, error, info};
use utils::logging;

const OAUTH_BASE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const OAUTH_USER_INFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

const SOCKET: &str = "127.0.0.1:12344";
const HOST: &str = "http://127.0.0.1:12344";
const AUTHORIZED_ROUTE: &str = "/authorized";
const AUTH_REDIRECT_URL: &str = "http://127.0.0.1:12344/authorized";

const COOKIE_SID: &str = "sid";
const COOKIE_DOMAIN: &str = ".app.localhost";

const ALLOWED_OAUTH_DOMAIN: &str = "neon.tech";

struct AppState {
    db_client: Client,
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
    debug!(redirect_url = AUTH_REDIRECT_URL);
    debug!(base_url = OAUTH_BASE_URL);
    debug!(token_url = OAUTH_TOKEN_URL);

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
            exit(1);
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

    let router = Router::new()
        .route(AUTHORIZED_ROUTE, get(authorized))
        .route("/{short_url}", get(redirect))
        .route("/", get(index).post(shorten))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(SOCKET)
        .await
        .expect("failed to bind TcpListener");
    let addr = listener
        .local_addr()
        .expect("failed to return local address");
    info!("listening on {addr}",);
    axum::serve(listener, router).await.unwrap();
    Ok(())
}

#[derive(Deserialize)]
pub struct User {
    id: i32, // TODO postgres_types::SERIAL ?
}

impl axum::extract::OptionalFromRequestParts<State> for User {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        let jar: PrivateCookieJar =
            PrivateCookieJar::from_request_parts(parts, state.state.as_ref())
                .await
                .unwrap();
        let Some(session_id) = jar.get(COOKIE_SID).map(|cookie| cookie.value().to_owned()) else {
            return Ok(None);
        };

        let client = &state.state.db_client;
        let query = client
            .query_opt(
                "FROM sessions SELECT user_id WHERE session_id = $1",
                &[&session_id],
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

async fn index(state: AxumState<State>, user: Option<User>) -> Html<String> {
    if user.is_some() {
        return shorten_form("");
    }

    let (auth_url, csrf_token) = state
        .state
        .oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        // state=https://stackoverflow.com/questions/7722062/google-oauth-2-0-redirect-uri-with-several-parameters
        .url();

    debug!(%auth_url);

    Html(format!("<a href=\"{auth_url}\">Authorize</a>"))
}

async fn shorten(
    state: AxumState<State>,
    user: Option<User>,
    Form(LongUrl { url }): Form<LongUrl>,
) -> Response {
    let user_id = match user {
        None => return StatusCode::FORBIDDEN.into_response(),
        Some(user) => user.id,
    };
    let short_url = nanoid::nanoid!(6);

    let query = state
        .state
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
    state: AxumState<State>,
    user: Option<User>,
    Path(short_url): Path<String>,
) -> Response {
    if user.is_none() {
        // redirect to oauth page
        return Redirect::permanent("/").into_response();
    };
    let user_id = user.unwrap().id;

    let query = state
        .state
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
    state: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    access_token: String,
    expires_in: u64,
    //id_token: String,
}

#[derive(Deserialize)]
struct UserInfoResponse {
    hd: String,
    sub: String,
}

// TODO csrf, pkce
async fn authorized(
    state: AxumState<State>,
    jar: PrivateCookieJar,
    Query(auth_request): Query<AuthRequest>,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    debug!(code = auth_request.code, "got authorization code");

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

    //let token = state
    //    .state
    //    .oauth_client
    //    .exchange_code(AuthorizationCode::new(auth_request.code))
    //    .request_async(reqwest::async_http_client)
    //    .await
    //    .map_err(|err| {
    //        error!(%err, "exchanging oauth code for token");
    //        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    //    })?;
    //let secret = token.access_token().secret().clone();

    // TODO just use id token?
    let UserInfoResponse { hd, sub } = ::reqwest::Client::new()
        .get(OAUTH_USER_INFO_URL)
        .bearer_auth(&auth_response.access_token)
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
        error!(%hd, "Domain doesn't match {ALLOWED_OAUTH_DOMAIN}");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    let cookie = Cookie::build((COOKIE_SID, auth_response.access_token.clone()))
        .domain(COOKIE_DOMAIN)
        .path("/")
        .secure(true)
        .http_only(true);
    // todo .max_age(time::duration::Duration)

    let user_id_row = state
        .state
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

    let expires_at = Local::now().naive_local()
        + Duration::try_seconds(auth_response.expires_in as i64).unwrap();
    state
        .state
        .db_client
        .query_opt(
            "INSERT INTO sessions (user_id, session_id, expires_at) VALUES ($1, $2, $3) \
            ON CONFLICT (user_id) DO UPDATE SET \
            session_id = excluded.session_id,\
            expires_at = excluded.expires_at",
            &[&user_id, &auth_response.access_token, &expires_at],
        )
        .await
        .map_err(|err| {
            error!(%err, %user_id, "updating session info");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        })?;

    Ok((jar.add(cookie), Redirect::to("/")))
}
