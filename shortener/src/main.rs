//! Shortener is a service to gate access to internal infrastructure
//! URLs behind team authorisation to expose less private information.
use anyhow::{Context, Result};
use axum::extract::{FromRequestParts, Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{Html, IntoResponse};
use axum::response::{Redirect, Response};
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
use std::process::exit;
use std::sync::Arc;
use tokio_postgres::{Client, NoTls};
use tracing::error;
use utils::logging;

const OAUTH_BASE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const GOOGLE_TOKEN_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";

const HOST: &str = "http://localhost:3000";
const AUTH_REDIRECT_URL: &str = "http://localhost:3000/auth_callback";
const SHORT_URL: &str = "short_url";
const COOKIE_SID: &str = "sid";

struct State {
    db_client: Client,
    key: Key,
    oauth_id: String,
    oauth_client: BasicClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init(
        logging::LogFormat::Plain,
        logging::TracingErrorLayerEnablement::EnableWithRustLogFilter,
        logging::Output::Stdout,
    )?;

    let client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").context("Missing GOOGLE_CLIENT_ID")?);
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
        key: todo!(),
        oauth_id: todo!(),
        oauth_client: todo!(),
    });

    let router = Router::new()
        .route("/auth_callback", get(auth_callback))
        .route("/{short_url}", get(redirect))
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

fn oauth_url(oauth_client_id: &str, short_url: &str) -> String {
    // If we follow short link unauthorized, we want to redirect to Oauth page, then to our
    // auth callback, and then to the target url. For that we need to pass a ?SHORT_URL=
    // parameter to our auth callback, and we need to encode it in Oauth page url.
    // %3F is ?, %3D is =
    format!(
        "{OAUTH_BASE_URL}?scope=email&client_id={oauth_client_id}\
            &response_type=code&redirect_uri={AUTH_REDIRECT_URL}\
            %3F{SHORT_URL}%3D{short_url}"
    )
}

async fn index(state: AxumState<Arc<State>>, user: Option<User>) -> Html<String> {
    if user.is_some() {
        shorten_form("")
    } else {
        let oauth_url = oauth_url(&state.oauth_id, "");
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
        return Redirect::permanent(&oauth_url(&state.oauth_id, &short_url)).into_response();
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

async fn auth_callback(
    state: AxumState<Arc<State>>,
    jar: PrivateCookieJar,
    Query(AuthRequest { code, short_url }): Query<AuthRequest>,
) -> Result<Response, Response> {
    let token = state
        .oauth_client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(reqwest::async_http_client)
        .await?;

    let Some(secs) = token.expires_in() else {
        return Err(ApiError::OptionError);
    };
    let secs: i64 = secs.as_secs().try_into()?;
    let max_age = Local::now().naive_local() + Duration::try_seconds(secs).unwrap();

    let cookie = Cookie::build((COOKIE_SID, token.access_token().secret().to_owned()))
        .domain(".app.localhost")
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(TimeDuration::seconds(secs));

    let user_id_row = state.db_client.query_one(
        "INSERT INTO users (email) VALUES ($1) \
         ON CONFLICT (email) DO NOTHING \
         RETURNING user_id", &[&email])
        .await
        .map_err(|err| {
            error!(%err, %email, "inserting or querying user");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        })
        ?;
    let user_id: u64 = user_id_row.get(0);

    state.db_client.query_opt(
        "INSERT INTO sessions (user_id, session_id, expires_at) VALUES (
        ($1, $2, $3)
        ON CONFLICT (user_id) DO UPDATE SET
        session_id = excluded.session_id,
        expires_at = excluded.expires_at",
        &[&user_id, token.access_token.secret(), &max_age]
    )
    .await?;

    // we can save one redirect for user by redirecting not to /short_url,
    // but to queried long url directly
    Ok((jar.add(cookie), Redirect::to(&format!("/{}", short_url.unwrap_or_default()))))
}

async fn main2() -> Result<()> {
    let client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").context("Missing GOOGLE_CLIENT_ID")?);
    let client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").context("Missing GOOGLE_CLIENT_SECRET")?,
    );

    let auth_url =
        AuthUrl::new(OAUTH_BASE_URL.to_string()).context("Invalid authorization endpoint URL")?;
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
