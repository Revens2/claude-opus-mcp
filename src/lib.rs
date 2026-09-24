//! Bibliotheque partagee `claude-opus-mcp` (contrat + politique + assemblage).
//!
//! Miroir de `astra_gateway` Python : validation Bearer + politique explicite
//! 1 lecture / 2 ecritures / 0 admin + proxy vers l'upstream Python
//! (`astra_mcp` en mode Opus, `:8794`, loopback, sans auth — isolation systemd).
//! Metier conserve : delegation de reflexion Claude Opus 5.5 + OAuth Python.
//!
//! Differences assumees vs `build_gateway` du framework (metier local au
//! depot, jamais dans le framework) :
//! * identite acteur : `x-opus-gw-acteur` (client_id du jeton valide) +
//!   `x-astra-gw-mode` (`cli`/`oauth`) injectes vers l'upstream (conserves :
//!   exiges par `mcp_server.py` cote Python, inchanges) ;
//! * challenge 401 vers l'URL PRM exacte du Python.
//!
//! OAuth JWT/Python vs opaque/Rust : canary via Bearer statique dedie
//! (meme famille que les lots precedents, bascule gated).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Router};

use mcp_auth::bearer::{
    extract_bearer, json_response, AccessTokenResolver, StaticBearer, TokenScopes,
};
use mcp_auth::filestore::{ChainedResolver, FileStore};
use mcp_auth::oauth::{
    auth_router, protected_resource_router, MemoryStore, OAuthConfig, OAuthState,
};
use mcp_auth::policy::{decide_body, CallDecision, TablePolicy, ToolClass, ToolPolicy};
use mcp_core::error::{self, codes};

/// Lecture seule : aucun tour Opus consomme (1 outil).
pub const OUTILS_LECTURE: &[&str] = &["opus_health"];

/// Delegation de reflexion + sessions logiques (2 outils).
pub const OUTILS_ECRITURE: &[&str] = &["opus_think", "opus_session"];

pub const READ_SCOPE: &str = "claude-opus:lecture";
pub const WRITE_SCOPE: &str = "claude-opus:ecriture";

/// URLs publiques a l'identique du Python (issuer/resource).
pub const ISSUER_DEFAULT: &str = "https://mymcps.duckdns.org/oauth/claude-opus";
pub const RESOURCE_URL: &str = "https://mymcps.duckdns.org/claude-opus/mcp";
pub const RESOURCE_NAME: &str = "delegation de reflexion Claude Opus 5.5 (passerelle)";
pub const PRM_ALIAS: &str = "/.well-known/oauth-protected-resource/claude-opus/mcp";
/// URL PRM exacte servie par le Python (challenge 401 + document).
pub const PRM_URL: &str =
    "https://mymcps.duckdns.org/.well-known/oauth-protected-resource/claude-opus/mcp";

/// Client statique CLI (mode `cli` ; sinon `oauth`).
pub const STATIC_CLIENT_ID: &str = "claude-opus-mcp-cli-statique";

/// Politique fail-closed du service (1R/2W/0admin, inconnu refuse).
pub fn policy() -> TablePolicy {
    let mut entries: Vec<(&str, ToolClass)> = Vec::with_capacity(3);
    for t in OUTILS_LECTURE {
        entries.push((t, ToolClass::Read));
    }
    for t in OUTILS_ECRITURE {
        entries.push((t, ToolClass::Write));
    }
    TablePolicy::new(READ_SCOPE, WRITE_SCOPE, &entries)
}

/// Identite acteur : client_id du jeton valide (tronque a 128, comme Python).
#[derive(Debug, Clone)]
pub struct ClientIdentity(pub String);

/// Configuration d'assemblage (resolue par le binaire).
pub struct ServiceConfig {
    pub upstream: String,
    pub static_token: String,
    pub static_token_scopes: Vec<String>,
    pub oauth: OAuthConfig,
    pub max_body_bytes: usize,
}

#[derive(Clone)]
struct AuthState {
    static_bearer: StaticBearer,
    resolver: Arc<ChainedResolver>,
    required_scopes: Vec<String>,
    prm_url: String,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: String,
    static_client_id: String,
    policy: Arc<TablePolicy>,
}

fn unauthorized(prm_url: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            format!("Bearer resource_metadata=\"{prm_url}\""),
        )],
        "Unauthorized",
    )
        .into_response()
}

/// Middleware local : comme `bearer_middleware` du framework, mais propage en
/// plus l'identite acteur (`ClientIdentity`) pour l'injection
/// `x-opus-gw-acteur` vers l'upstream.
async fn acteur_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(req.headers()) else {
        return unauthorized(&state.prm_url);
    };
    let (client_id, scopes) = if let Some(found) = state.static_bearer.verify(&token) {
        found
    } else {
        match state.resolver.resolve(&token).await {
            Some(found) => found,
            None => return unauthorized(&state.prm_url),
        }
    };
    if !state.required_scopes.iter().all(|s| scopes.contains(s)) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    req.extensions_mut().insert(TokenScopes(scopes));
    let mut ident = client_id;
    ident.truncate(128);
    req.extensions_mut().insert(ClientIdentity(ident));
    next.run(req).await.into_response()
}

/// Assemble le routeur complet : sante + OAuth + PRM (+ alias) + `/mcp` + 404.
pub fn build_router(cfg: ServiceConfig) -> Result<Router, mcp_core::error::Error> {
    build_router_full(cfg, None)
}

/// Assemble le routeur avec pont fichier optionnel (sessions OAuth Python
/// existantes acceptées sans re-consentement ; `None` = comme
/// [`build_router`]). Validation auth/contrat/relais uniquement : `opus_think`
/// et `opus_session` (délégation modèle) ne sont jamais appelés ici.
pub fn build_router_with_filestore(
    cfg: ServiceConfig,
    mount: Option<mcp_gateway::router::FileStoreMount>,
) -> Result<Router, mcp_core::error::Error> {
    build_router_full(cfg, mount)
}

fn build_router_full(
    cfg: ServiceConfig,
    mount: Option<mcp_gateway::router::FileStoreMount>,
) -> Result<Router, mcp_core::error::Error> {
    let store = Arc::new(MemoryStore::default());
    let file = mount
        .filter(|m| !m.etat_path.trim().is_empty())
        .map(|m| Arc::new(FileStore::new(&m.etat_path)));
    if let Some(f) = &file {
        // Fail-closed par requête si illisible (le magasin naît à la première
        // émission Python) ; le Bearer statique reste disponible.
        if std::fs::metadata(f.etat_path()).is_ok() {
            tracing::info!("pont fichier OAuth (read-only) monte");
        } else {
            tracing::warn!("pont fichier OAuth illisible au boot (fail-closed par requete)");
        }
    }
    let chained = Arc::new(ChainedResolver::new(Arc::clone(&store), file));
    let oauth_state = OAuthState {
        config: Arc::new(cfg.oauth.clone()),
        store,
    };
    let auth_state = AuthState {
        static_bearer: StaticBearer::new(
            &cfg.static_token,
            STATIC_CLIENT_ID,
            &cfg.static_token_scopes,
        ),
        resolver: chained,
        required_scopes: vec![READ_SCOPE.to_string()],
        prm_url: PRM_URL.to_string(),
    };
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(50)
        .build()
        .map_err(|e| mcp_core::error::Error::Upstream(e.to_string()))?;
    let app_state = AppState {
        client,
        upstream: cfg.upstream.trim_end_matches('/').to_string(),
        static_client_id: STATIC_CLIENT_ID.to_string(),
        policy: Arc::new(policy()),
    };

    let mcp_route = Router::new()
        .route(
            "/mcp",
            get(mcp_handler)
                .post(mcp_handler)
                .delete(mcp_handler)
                .route_layer(middleware::from_fn_with_state(
                    auth_state,
                    acteur_middleware,
                )),
        )
        .with_state(app_state);

    let app = Router::new()
        .merge(mcp_http::health::router("claude-opus-mcp", "/mcp"))
        .merge(auth_router(oauth_state.clone()))
        .merge(protected_resource_router(oauth_state, &[PRM_ALIAS]))
        .merge(mcp_route);

    Ok(mcp_http::hardening::harden(app, cfg.max_body_bytes))
}

/// Handler `/mcp` : Bearer edge, politique AVANT envoi, puis relais avec acteur.
async fn mcp_handler(State(state): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let scopes: HashSet<String> = parts
        .extensions
        .get::<TokenScopes>()
        .map(|s| s.0.clone())
        .unwrap_or_default();
    let identite: Option<String> = parts
        .extensions
        .get::<ClientIdentity>()
        .map(|c| c.0.clone());

    let mut body_bytes: Option<Vec<u8>> = None;
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        let bytes =
            match axum::body::to_bytes(body, mcp_http::hardening::DEFAULT_MAX_BODY_BYTES).await {
                Ok(b) => b,
                Err(_) => {
                    return json_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        error::payload_too_large_body(),
                    );
                }
            };
        if !bytes.is_empty() {
            match decide_body(&bytes) {
                CallDecision::ParseError => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            None,
                            codes::PARSE,
                            "corps JSON-RPC illisible (fail-closed)",
                        ),
                    );
                }
                CallDecision::BatchRejected => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            None,
                            codes::BATCH,
                            "requetes par lot non prises en charge",
                        ),
                    );
                }
                CallDecision::Nameless { id } => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            id.as_ref(),
                            codes::APP,
                            "tools/call sans nom d'outil (fail-closed)",
                        ),
                    );
                }
                CallDecision::Call { id, name } => {
                    if let Some(reason) = state.policy.autoriser_call(&name, &scopes) {
                        return json_response(
                            StatusCode::OK,
                            error::jsonrpc_error(id.as_ref(), codes::APP, &reason),
                        );
                    }
                }
                CallDecision::Passthrough => {}
            }
            body_bytes = Some(bytes.to_vec());
        }
    }

    forward(
        &state,
        &method,
        &path,
        query.as_deref(),
        &parts.headers,
        body_bytes,
        &scopes,
        identite,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    state: &AppState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &axum::http::HeaderMap,
    body: Option<Vec<u8>>,
    scopes: &HashSet<String>,
    identite: Option<String>,
) -> Response {
    use mcp_http::proxy as hp;

    let outgoing = hp::forward_request_headers(headers);
    let url = match query {
        Some(q) if !q.is_empty() => format!("{}{}?{q}", state.upstream, path),
        _ => format!("{}{}", state.upstream, path),
    };
    let mut builder = state.client.request(method.clone(), url);
    for (name, value) in outgoing.iter() {
        builder = builder.header(name, value);
    }
    // Acteur propage APRES authentification (jamais lu depuis l'exterieur).
    if let Some(id) = identite.filter(|s| !s.is_empty()) {
        let mode = if id == state.static_client_id {
            "cli"
        } else {
            "oauth"
        };
        builder = builder.header("x-opus-gw-acteur", id);
        builder = builder.header("x-astra-gw-mode", mode);
    }
    if *method == Method::POST {
        // Timeout TOTAL (corps SSE inclus) : 60 s coupait les tours longs -> cancel distant.
        let secs = std::env::var("OPUS_GW_RS_POST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600);
        builder = builder.timeout(Duration::from_secs(secs));
    }
    if let Some(b) = body {
        builder = builder.body(b);
    }
    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(_) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                error::bad_gateway_body("HttpError"),
            );
        }
    };
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let out_headers = hp::forward_response_headers(upstream.headers());

    if *method == Method::GET {
        let stream = upstream.bytes_stream();
        let mut builder = Response::builder().status(status);
        for (name, value) in out_headers.iter() {
            builder = builder.header(name, value);
        }
        return builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    let content_type = out_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut bytes = match upstream.bytes().await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                error::bad_gateway_body("HttpError"),
            );
        }
    };
    if *method == Method::POST {
        let visibles = state.policy.visibles(scopes);
        bytes = hp::filter_tools_list(&bytes, &content_type, &visibles);
    }
    let mut builder = Response::builder().status(status);
    for (name, value) in out_headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}
