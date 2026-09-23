//! Contrat claude-opus-mcp : politique 1R/2W + acteur + gateway HTTP.
//!
//! Preuves exigibles du lot claude-opus (passerelle) :
//! * `opus_health` autorise en lecture, `opus_think`/`opus_session`
//!   exigent l'ecriture, inconnu refuse meme full scopes ;
//! * `visibles` : 1 en lecture, 3 en lecture+ecriture ;
//! * gateway : 401 + challenge PRM, `/health` framework, PRM exacte,
//!   acteur/mode injectes vers l'upstream, refus locaux avant upstream.

use std::collections::HashSet;

use claude_opus_mcp::{policy, OUTILS_ECRITURE, OUTILS_LECTURE, READ_SCOPE, WRITE_SCOPE};
use mcp_auth::policy::{ToolClass, ToolPolicy};

fn scopes(s: &[&str]) -> HashSet<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn tailles_politique_1r_2w() {
    assert_eq!(OUTILS_LECTURE, &["opus_health"]);
    assert_eq!(OUTILS_ECRITURE, &["opus_think", "opus_session"]);
}

#[test]
fn matrice_autorisation() {
    let p = policy();
    assert_eq!(p.classify("opus_health"), ToolClass::Read);
    assert!(p
        .autoriser_call("opus_health", &scopes(&[READ_SCOPE]))
        .is_none());
    for tool in OUTILS_ECRITURE {
        assert_eq!(p.classify(tool), ToolClass::Write, "outil {tool}");
        assert!(p.autoriser_call(tool, &scopes(&[READ_SCOPE])).is_some());
        assert!(p
            .autoriser_call(tool, &scopes(&[READ_SCOPE, WRITE_SCOPE]))
            .is_none());
    }
    assert_eq!(p.classify("opus_admin"), ToolClass::Unknown);
    assert!(p
        .autoriser_call("opus_admin", &scopes(&[READ_SCOPE, WRITE_SCOPE]))
        .is_some());
}

#[test]
fn visibles_1_3() {
    let p = policy();
    assert_eq!(p.visibles(&scopes(&[READ_SCOPE])).len(), 1);
    assert_eq!(p.visibles(&scopes(&[READ_SCOPE, WRITE_SCOPE])).len(), 3);
    assert!(p.visibles(&scopes(&[])).is_empty());
}

fn oauth_cfg() -> mcp_auth::oauth::OAuthConfig {
    mcp_auth::oauth::OAuthConfig {
        issuer: "https://mymcps.duckdns.org/oauth/claude-opus".to_string(),
        resource_url: claude_opus_mcp::RESOURCE_URL.to_string(),
        resource_name: claude_opus_mcp::RESOURCE_NAME.to_string(),
        default_scope: READ_SCOPE.to_string(),
        valid_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        extra_submit_scopes: vec![WRITE_SCOPE.to_string()],
        consent_hash: String::new(),
        static_client_id: claude_opus_mcp::STATIC_CLIENT_ID.to_string(),
    }
}

fn gateway_test() -> axum::Router {
    use claude_opus_mcp::{build_router, ServiceConfig};

    build_router(ServiceConfig {
        upstream: "http://127.0.0.1:9".to_string(),
        static_token: "x".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .expect("gateway de test")
}

#[tokio::test]
async fn mcp_sans_bearer_401_avec_prm_opus() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test();
    let res = app
        .oneshot(Request::post("/mcp").body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let challenge = res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        challenge.contains("oauth-protected-resource/claude-opus/mcp"),
        "{challenge}"
    );
}

#[tokio::test]
async fn health_et_prm_opus() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test();
    let res = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["service"], "claude-opus-mcp");

    let app = gateway_test();
    let res = app
        .oneshot(
            Request::get(claude_opus_mcp::PRM_ALIAS)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["resource"], claude_opus_mcp::RESOURCE_URL);
}

#[tokio::test]
async fn ecriture_sans_portee_refusee_avant_upstream() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use claude_opus_mcp::{build_router, ServiceConfig};
    let app = build_router(ServiceConfig {
        upstream: "http://127.0.0.1:9".to_string(),
        static_token: "y".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .unwrap();
    let body = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"opus_think","arguments":{}}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "y".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32000);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("claude-opus:ecriture"),
        "{v}"
    );
}

/// Le relais injecte l'acteur (jamais d'`Authorization` client) : le mock
/// exige `x-astra-gw-acteur: claude-opus-mcp-cli-statique` + `mode: cli`.
#[tokio::test]
async fn relais_injecte_acteur() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let mock = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|req: axum::extract::Request| async move {
            let h = req.headers();
            let acteur = h
                .get("x-astra-gw-acteur")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            assert_eq!(acteur, claude_opus_mcp::STATIC_CLIENT_ID);
            assert_eq!(
                h.get("x-astra-gw-mode").and_then(|v| v.to_str().ok()),
                Some("cli")
            );
            assert!(h.get("authorization").is_none());
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"opus_health","description":"d","inputSchema":{"type":"object"}}]}}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    use claude_opus_mcp::{build_router, ServiceConfig};
    let app = build_router(ServiceConfig {
        upstream: format!("http://127.0.0.1:{}", addr.port()),
        static_token: "x".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .unwrap();

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "x".repeat(32)))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["result"]["tools"][0]["name"], "opus_health");
}

/// Pont fichier : une session Python existante (synthetique) passe le
/// Bearer (sante/contrat uniquement — `opus_think`/`opus_session`
/// JAMAIS appelés) ; un opaque inconnu reste 401.
#[tokio::test]
async fn pont_fichier_session_existante_passe_bearer() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use claude_opus_mcp::{build_router_with_filestore, ServiceConfig};
    use tower::ServiceExt;

    let dir = std::env::temp_dir().join(format!(
        "opus-pont-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let etat = dir.join("etat.json");
    let tok = "synthetique-opus-pont-0123456789001";
    let doc = serde_json::json!({
        "demandes": {}, "codes": {},
        "acces": { tok: {
            "jeton": tok, "client_id": "client-synth",
            "scopes": ["claude-opus:lecture"], "resource": serde_json::Value::Null,
            "expire_a": 9_999_999_999i64 } },
        "rafraichissements": {},
    });
    std::fs::write(&etat, doc.to_string()).unwrap();
    let app = build_router_with_filestore(
        ServiceConfig {
            upstream: "http://127.0.0.1:9".to_string(),
            static_token: "x".repeat(32),
            static_token_scopes: vec![READ_SCOPE.to_string()],
            oauth: oauth_cfg(),
            max_body_bytes: 1024 * 1024,
        },
        Some(mcp_gateway::router::FileStoreMount {
            etat_path: etat.to_string_lossy().to_string(),
            expected_resource: None,
        }),
    )
    .expect("gateway de test");
    // Outil inconnu : le refus local -32000 prouve l'auth OK (pas 401),
    // sans aucun appel modèle.
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"outil-x"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], -32000);
    let _ = std::fs::remove_dir_all(&dir);
}
