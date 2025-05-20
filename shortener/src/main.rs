//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::{Context, Result};
use axum::extract::{FromRequestParts, Request, State as AxumState};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Form, Router};
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Key;
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tokio_postgres::{Client, Config, Connection, NoTls, Socket};
use tracing::error;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const GOOGLE_TOKEN_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";

const HOST: &str = "http://localhost:3000";
const AUTH_REDIRECT_URL: &str = "http://localhost:3000/auth_callback";
// + nanoid

struct State {
    db_client: Client,
    key: Key,
    oauth_id: String,
    oauth_client: BasicClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    let client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").context("Missing GOOGLE_CLIENT_ID")?);
    let db_connstr = env::var("DB_CONNSTR").context("Missing DB_CONNSTR")?;

    let (db_client, db_conn) = tokio_postgres::connect(&db_connstr, NoTls).await?;
    tokio::spawn(async move {
        if let Err(err) = db_conn.await {
            error!(%err, "connecting to database");
        }
    });

    let state = Arc::new(State {
        db_client,
        key: todo!(),
        oauth_id: todo!(),
        oauth_client: todo!(),
    });

    let router = Router::new()
        .route("/auth_callback", get(auth_callback))
        .route("/{id}", get(redirect))
        .route("/", get(index).post(shorten))
        .with_state(state);

    Ok(())
}

#[derive(Deserialize)]
pub struct User {
    id: String,
}

impl axum::extract::OptionalFromRequestParts<Arc<State>> for User {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<State>,
    ) -> Result<Option<Self>, Self::Rejection> {
        let jar: PrivateCookieJar = PrivateCookieJar::from_request_parts(&mut parts, state)
            .await
            .unwrap();
        let Some(cookie) = jar.get("sid").map(|cookie| cookie.value().to_owned()) else {
            return Ok(None);
        };

        let query = state
            .db_client
            .query_opt(
                "FROM sessions SELECT user_id WHERE session_id = $1 LIMIT 1",
                &[&cookie],
            )
            .await;
        let maybe_row = match query {
            Ok(maybe_row) => maybe_row,
            Err(err) => {
                error!(%err, "querying user session");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };
        if maybe_row.is_none() {
            return Ok(None);
        }
        let row = maybe_row.unwrap();
        let id = row.get::<usize, &str>(0).to_string();
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

async fn index(state: AxumState<Arc<State>>, user: Option<User>) -> Html<String> {
    match user {
        None => Html(format!(
            "<a href=\"{GOOGLE_AUTH_URL}?scope=email&client_id={}\
            &response_type=code&redirect_uri={AUTH_REDIRECT_URL}\">Authorize</a>",
            state.oauth_id
        )),
        Some(_) => shorten_form(""),
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

    let query = state
        .db_client
        .query_one(
            "INSERT INTO urls (user_id, short_url, long_url) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (long_url) DO NOTHING \
             RETURNING short_url",
            &[&user_id, &generated_short_url, &url],
        )
        .await;
    let row = match query {
        Ok(row) => row,
        Err(err) => {
            error!(%err, "inserting shortened url");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
}

async fn main2() -> Result<()> {
    let client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").context("Missing GOOGLE_CLIENT_ID")?);
    let client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").context("Missing GOOGLE_CLIENT_SECRET")?,
    );

    let auth_url =
        AuthUrl::new(GOOGLE_AUTH_URL.to_string()).context("Invalid authorization endpoint URL")?;
    let token_url =
        TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).context("Invalid token endpoint URL")?;
    let redirect_url =
        RedirectUrl::new(AUTH_REDIRECT_URL.to_string()).expect("Invalid redirect URL");
    let revocation_url = RevocationUrl::new(GOOGLE_TOKEN_REVOKE_URL.to_string())
        .expect("Invalid revocation endpoint URL");

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url)
        .set_revocation_uri(revocation_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .add_extra_param("hosted_domain", "neon.tech")
        .url();

    println!("Browse to: {}", auth_url);
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let token_result = client
        .exchange_code(AuthorizationCode::new(
            "some authorization code".to_string(),
        ))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await?;
    println!("Google returned the following token:\n{token_result}\n");

    Ok(())
}
