//! claude-opus-gateway-rs — facade Rust devant l'upstream Python (`:8794`, mode Opus).
//!
//! Assemble `claude_opus_gateway_rs::build_router` (aucune auth upstream requise,
//! isolation systemd comme le Python ; `x-astra-gw-acteur` injecte apres
//! authentification — header conserve car exige par `mcp_server.py` cote Python).
//!
//! Environnement (prefixe `OPUS_GW_RS_*`, fallback lecture `ASTRA_GW_RS_*`
//! pendant une version) :
//! * `OPUS_GW_RS_ISSUER` (defaut issuer prod, HTTPS requis),
//! * `OPUS_GW_RS_UPSTREAM` (defaut `http://127.0.0.1:8794`, loopback requis),
//! * `OPUS_GW_RS_PORT` (defaut `18996` canary ; `8796` a la bascule),
//! * `OPUS_GW_RS_TOKEN` (>= 32 car.) OU `OPUS_GW_RS_TOKEN_FILE`
//!   (defaut `/opt/claude-opus-gateway-rs/.mcp_token`, repli
//!   `/opt/astra-gateway-rs/.mcp_token`) — fail-closed,
//! * `OPUS_GW_RS_TOKEN_SCOPES` (defaut lecture+ecriture, quoté dans l'unit),
//! * `OPUS_GW_RS_CONSENT_HASH` (empreinte PBKDF2, vide = consentement refuse).
//! * `OPUS_GW_RS_OAUTH_ETAT` (defaut `/srv/astra/gateway-oauth/etat.json` :
//!   pont READ-ONLY vers le magasin Python existant, sessions existantes sans
//!   re-consentement ; vide = pont desactive).

use claude_opus_gateway_rs::{
    ISSUER_DEFAULT, READ_SCOPE, RESOURCE_NAME, RESOURCE_URL, WRITE_SCOPE,
};
use mcp_auth::oauth::OAuthConfig;

/// Recopie `ASTRA_GW_RS_*` vers `OPUS_GW_RS_*` quand ce dernier est absent
/// (transition une version ; le nouveau prefixe gagne toujours).
fn mirror_legacy_env() {
    for suffix in [
        "ISSUER",
        "UPSTREAM",
        "PORT",
        "TOKEN",
        "TOKEN_FILE",
        "TOKEN_SCOPES",
        "CONSENT_HASH",
        "OAUTH_ETAT",
        "OAUTH_EXPECTED_RESOURCE",
        "JWT_SECRET",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
    ] {
        let nouveau = format!("OPUS_GW_RS_{suffix}");
        let ancien = format!("ASTRA_GW_RS_{suffix}");
        let vide = std::env::var(&nouveau)
            .unwrap_or_default()
            .trim()
            .is_empty();
        if vide {
            if let Ok(v) = std::env::var(&ancien) {
                if !v.trim().is_empty() {
                    // `set_var` est `unsafe` sur cette toolchain : init mono-thread.
                    unsafe { std::env::set_var(&nouveau, v) };
                }
            }
        }
    }
}

/// Charge le Bearer statique DEDIE : variable directe, sinon fichier (+ repli
/// ancien chemin). Fail-closed.
fn load_static_token() -> Result<String, String> {
    if let Ok(v) = std::env::var("OPUS_GW_RS_TOKEN") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            if v.len() < 32 {
                return Err("OPUS_GW_RS_TOKEN trop court (<32 car.)".to_string());
            }
            return Ok(v);
        }
    }
    let path = std::env::var("OPUS_GW_RS_TOKEN_FILE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "/opt/claude-opus-gateway-rs/.mcp_token".to_string());
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let tok = raw.trim().to_string();
            if tok.len() < 32 {
                return Err("token Bearer trop court (<32 car.), refuse de demarrer".to_string());
            }
            Ok(tok)
        }
        Err(e) if path == "/opt/claude-opus-gateway-rs/.mcp_token" => {
            // Repli transition : ancien fichier 0600 existant.
            let ancien = "/opt/astra-gateway-rs/.mcp_token";
            let raw = std::fs::read_to_string(ancien)
                .map_err(|_| format!("token Bearer illisible ({path} puis {ancien}) : {e}"))?;
            let tok = raw.trim().to_string();
            if tok.len() < 32 {
                return Err("token Bearer trop court (<32 car.), refuse de demarrer".to_string());
            }
            Ok(tok)
        }
        Err(e) => Err(format!("token Bearer illisible ({path}) : {e}")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    mcp_observe::init("claude-opus-gateway-rs");

    // Transition une version : `ASTRA_GW_RS_*` -> `OPUS_GW_RS_*`.
    mirror_legacy_env();

    if std::env::var("OPUS_GW_RS_ISSUER")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        // `set_var` est `unsafe` sur cette toolchain : init mono-thread.
        unsafe { std::env::set_var("OPUS_GW_RS_ISSUER", ISSUER_DEFAULT) };
    }
    if std::env::var("OPUS_GW_RS_UPSTREAM")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        unsafe { std::env::set_var("OPUS_GW_RS_UPSTREAM", "http://127.0.0.1:8794") };
    }
    // Pont fichier OAuth (transition) : Python = AS/control-plane, Rust =
    // data-plane. Meme utilisateur UNIX que le Python (fichiers 0600).
    // Chemin historique conserve : le magasin existant vit sous /srv/astra.
    if std::env::var("OPUS_GW_RS_OAUTH_ETAT")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        unsafe {
            std::env::set_var(
                "OPUS_GW_RS_OAUTH_ETAT",
                "/srv/astra/gateway-oauth/etat.json",
            )
        };
    }
    // Lecon lot 2 : sans SCOPES explicites, le defaut install ne donne que la
    // lecture. Le canary parite exige lecture+ecriture.
    if std::env::var("OPUS_GW_RS_TOKEN_SCOPES")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        unsafe {
            std::env::set_var(
                "OPUS_GW_RS_TOKEN_SCOPES",
                format!("{READ_SCOPE} {WRITE_SCOPE}"),
            )
        };
    }
    let token = load_static_token().map_err(|e| {
        tracing::error!("fail-closed: pas de Bearer valide");
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
    })?;
    unsafe { std::env::set_var("OPUS_GW_RS_TOKEN", &token) };

    let env = mcp_gateway::config::from_prefix(
        "OPUS_GW_RS",
        18996,
        READ_SCOPE,
        &[READ_SCOPE, WRITE_SCOPE],
    )?;

    let port = env.port;
    let upstream_log = env.upstream.clone();
    let mount = mcp_gateway::config::filestore_mount(&env);
    let app = claude_opus_gateway_rs::build_router_with_filestore(
        claude_opus_gateway_rs::ServiceConfig {
            upstream: env.upstream,
            static_token: env.static_token,
            static_token_scopes: env.token_scopes,
            oauth: OAuthConfig {
                issuer: env.issuer,
                resource_url: RESOURCE_URL.to_string(),
                resource_name: RESOURCE_NAME.to_string(),
                default_scope: READ_SCOPE.to_string(),
                valid_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
                extra_submit_scopes: vec![WRITE_SCOPE.to_string()],
                consent_hash: env.consent_hash,
                static_client_id: claude_opus_gateway_rs::STATIC_CLIENT_ID.to_string(),
            },
            max_body_bytes: mcp_http::hardening::DEFAULT_MAX_BODY_BYTES,
        },
        mount,
    )?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!(
        port,
        upstream = %upstream_log,
        "claude-opus-gateway-rs prete (boucle locale uniquement)"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(mcp_core::lifecycle::shutdown_signal())
        .await?;
    Ok(())
}
