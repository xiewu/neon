//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{FromRequest, FromRequestParts, Request, State as AxumState};
use axum::response::Html;
use axum::routing::get;
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
use tokio_postgres::Config;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const GOOGLE_TOKEN_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
const AUTH_REDIRECT_URL: &str = "http://localhost:3000/auth_callback";
// + nanoid

#[derive(Clone)]
pub struct State {
    cfg: Config,
    key: Key,
    oauth_id: String,
    oauth_client: BasicClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = Arc::new(State::new());
    let router = Router::new()
        .route("/auth_callback", get(auth_callback))
        .route("/{id}", get(redirect))
        .route("/", get(index).post(shorten))
        .with_state(state);

    Ok(())
}

#[derive(Deserialize, sqlx::FromRow, Clone)]
pub struct User {
    email: String,
}

#[axum::async_trait]
impl FromRequest<State> for User {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &State) -> Result<Self, Self::Rejection> {
        let state = state.to_owned();
        let (mut parts, _body) = req.into_parts();
        let cookiejar = PrivateCookieJar::from_request_parts(&mut parts, &state).await?;

        let Some(cookie) = cookiejar.get("sid").map(|cookie| cookie.value().to_owned()) else {
            return Err(ApiError::Unauthorized);
        };

        let res = sqlx::query_as::<_, UserProfile>(
            "SELECT
        users.email
        FROM sessions
        LEFT JOIN USERS ON sessions.user_id = users.id
        WHERE sessions.session_id = $1
        LIMIT 1",
        )
        .bind(cookie)
        .fetch_one(&state.db)
        .await?;

        Ok(Self { email: res.email })
    }
}

async fn index(state: AxumState<Arc<State>>, user: Option<User>) -> Html<String> {
    match user {
        None => Html(format!(
            "
        <a href=\"https://accounts.google.com/o/oauth2/v2/auth?scope=email\
        &client_id={}\
        &response_type=code\
        &redirect_uri=http://localhost:8000/auth_callback\">\
    Authorize</a>",
            state.oauth_id
        )),
        Some(_) => Html(
            "<form>\
        <input type=\"text\" name=\"url\">\
        <br>\
        <input type=\"submit\" value=\"Shorten\">\
        </form>"
                .to_string(),
        ),
    }
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
