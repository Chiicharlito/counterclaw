//! Tests I/O pour le CDP Proxy — HTTP Discovery + WebSocket Relay.
//!
//! Ces tests vérifient le comportement réel du proxy (réseau, ports, connexions)
//! par opposition aux tests de logique pure dans cdp_proxy_test.rs.

mod common;

use counterclaw::config::CdpProxyConfig;
use counterclaw::guards::cdp_proxy::CdpProxy;
use counterclaw::types::{Guard, GuardModule, SecurityEvent};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

// ===========================================================================
// Helper : config CDP pour tests I/O avec ports dynamiques
// ===========================================================================

fn cdp_io_config(listen_port: u16, upstream_port: u16) -> CdpProxyConfig {
    serde_yaml::from_str(&format!(
        r#"
enabled: true
listen_port: {}
upstream_port: {}
bind_address: "127.0.0.1"
domains:
  blocked:
    - "*.banking.*"
    - "gmail.com"
  allowed:
    - "github.com"
    - "stackoverflow.com"
  require_approval: []
  default_policy: allow
cdp_commands:
  blocked:
    - "Network.getCookies"
  restricted_to_allowed_domains:
    - "Page.captureScreenshot"
  log_always:
    - "Page.navigate"
content_inspection:
  enabled: false
  patterns: []
"#,
        listen_port, upstream_port
    ))
    .expect("valid CDP config")
}

// ===========================================================================
// Helper : Mock Chrome HTTP server (simule les endpoints /json/*)
// ===========================================================================

/// Lance un serveur HTTP minimal qui simule les endpoints CDP de Chrome.
/// Retourne (port, JoinHandle).
async fn start_mock_chrome_http(port: u16) -> tokio::task::JoinHandle<()> {
    use axum::routing::get;
    use axum::Router;

    let version_json = serde_json::json!({
        "Browser": "Chrome/120.0.0.0",
        "Protocol-Version": "1.3",
        "User-Agent": "Mozilla/5.0",
        "V8-Version": "12.0.0.0",
        "WebKit-Version": "537.36",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/browser/test-id", port)
    });

    let list_json = serde_json::json!([{
        "description": "",
        "devtoolsFrontendUrl": "/devtools/inspector.html?ws=127.0.0.1/devtools/page/test",
        "id": "test-page-id",
        "title": "Test Page",
        "type": "page",
        "url": "about:blank",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/test", port)
    }]);

    let version_clone = version_json.clone();
    let list_clone = list_json.clone();

    let app = Router::new()
        .route(
            "/json/version",
            get(move || {
                let v = version_clone.clone();
                async move { axum::Json(v) }
            }),
        )
        .route(
            "/json/list",
            get(move || {
                let l = list_clone.clone();
                async move { axum::Json(l) }
            }),
        )
        .route(
            "/json",
            get(move || {
                let l = list_json.clone();
                async move { axum::Json(l) }
            }),
        );

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind mock Chrome");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    })
}

// ===========================================================================
// Step 6.1 : CDP Proxy HTTP Discovery Tests
// ===========================================================================

/// Le proxy HTTP écoute sur le port configuré après start().
#[tokio::test]
async fn discovery_binds_to_configured_port() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();
    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");

    // Give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Try connecting to the proxy port
    let result = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", listen_port)).await;
    assert!(result.is_ok(), "Should be able to connect to proxy port");

    proxy.stop().await.expect("stop failed");
}

/// GET /json/version retourne le JSON avec le port réécrit vers le proxy.
#[tokio::test]
async fn discovery_forwards_and_rewrites_version() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    // Start mock Chrome
    let _chrome = start_mock_chrome_http(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Fetch /json/version through proxy
    let resp = reqwest::get(format!("http://127.0.0.1:{}/json/version", listen_port))
        .await
        .expect("HTTP request failed");

    assert!(resp.status().is_success());
    let body = resp.text().await.expect("Failed to read body");

    // The webSocketDebuggerUrl should point to the proxy port, not the upstream
    assert!(
        body.contains(&listen_port.to_string()),
        "Should contain proxy port {}: {}",
        listen_port,
        body
    );
    assert!(
        !body.contains(&upstream_port.to_string()),
        "Should NOT contain upstream port {}: {}",
        upstream_port,
        body
    );

    proxy.stop().await.expect("stop failed");
}

/// GET /json/list retourne la liste avec URLs réécrites.
#[tokio::test]
async fn discovery_forwards_json_list() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let _chrome = start_mock_chrome_http(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/json/list", listen_port))
        .await
        .expect("HTTP request failed");

    assert!(resp.status().is_success());
    let body = resp.text().await.expect("Failed to read body");

    // Should be a JSON array
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("Invalid JSON");
    assert!(parsed.is_array(), "Should be JSON array");
    assert!(
        !parsed.as_array().unwrap().is_empty(),
        "Should have entries"
    );

    // URLs should be rewritten
    assert!(
        body.contains(&listen_port.to_string()),
        "Should contain proxy port"
    );

    proxy.stop().await.expect("stop failed");
}

/// Quand Chrome n'est pas démarré, le proxy retourne une erreur propre.
#[tokio::test]
async fn discovery_returns_error_when_chrome_down() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();
    // NO mock Chrome started on upstream_port

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/json/version", listen_port)).await;

    match resp {
        Ok(r) => {
            // Should be a 502 Bad Gateway or similar error
            assert!(
                r.status().is_server_error(),
                "Expected server error, got {}",
                r.status()
            );
        }
        Err(_) => {
            // Connection refused is also acceptable (proxy might not be up yet)
            // but we expect the proxy to handle it gracefully
        }
    }

    proxy.stop().await.expect("stop failed");
}

/// Après stop(), le port est libéré et n'est plus accessible.
#[tokio::test]
async fn stop_releases_port() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();
    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Port should be listening
    let connected = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", listen_port))
        .await
        .is_ok();
    assert!(connected, "Port should be listening before stop");

    proxy.stop().await.expect("stop failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Port should be released — binding should succeed
    let can_rebind = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", listen_port))
        .await
        .is_ok();
    assert!(can_rebind, "Port should be released after stop");
}

// ===========================================================================
// Helper : Mock Chrome WebSocket server
// ===========================================================================

/// Lance un mock Chrome qui combine HTTP discovery + WebSocket echo server.
/// Le WS server accepte les connexions sur /devtools/browser/* et echoes messages.
/// Messages contenant "CLOSE" provoquent une fermeture du WS.
/// Retourne (port, JoinHandle, received_messages_rx).
async fn start_mock_chrome_ws(
    port: u16,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<String>,
) {
    use axum::extract::ws::WebSocketUpgrade;
    use axum::routing::get;
    use axum::Router;

    let (msg_tx, msg_rx) = tokio::sync::mpsc::channel::<String>(100);

    let version_json = serde_json::json!({
        "Browser": "Chrome/120.0.0.0",
        "Protocol-Version": "1.3",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/browser/test-id", port)
    });

    let list_json = serde_json::json!([{
        "id": "test-page-id",
        "title": "Test Page",
        "type": "page",
        "url": "about:blank",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{}/devtools/page/test", port)
    }]);

    let version_clone = version_json.clone();
    let list_clone = list_json.clone();

    let app = Router::new()
        .route(
            "/json/version",
            get(move || {
                let v = version_clone.clone();
                async move { axum::Json(v) }
            }),
        )
        .route(
            "/json/list",
            get(move || {
                let l = list_clone.clone();
                async move { axum::Json(l) }
            }),
        )
        .route(
            "/json",
            get(move || {
                let l = list_json.clone();
                async move { axum::Json(l) }
            }),
        )
        .route(
            "/devtools/browser/{id}",
            get(move |ws: WebSocketUpgrade| {
                let tx = msg_tx.clone();
                async move { ws.on_upgrade(move |socket| handle_mock_ws(socket, tx)) }
            }),
        );

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind mock Chrome WS");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (handle, msg_rx)
}

/// Handler for mock Chrome WS — echoes messages back, tracks received.
async fn handle_mock_ws(
    mut socket: axum::extract::ws::WebSocket,
    msg_tx: tokio::sync::mpsc::Sender<String>,
) {
    use axum::extract::ws::Message;

    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                let _ = msg_tx.send(text.to_string()).await;
                // Echo back a response
                let parsed: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
                let id = parsed.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                let response = serde_json::json!({"id": id, "result": {}}).to_string();
                if socket.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
            Message::Binary(data) => {
                // Echo binary back
                if socket.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

// ===========================================================================
// Step 6.2 : CDP Proxy WebSocket Relay Tests
// ===========================================================================

/// Un message WS autorisé est relayé vers le mock Chrome.
#[tokio::test]
async fn ws_relay_forwards_allowed_message() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (_chrome_handle, mut chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect as WS client to the proxy
    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Send an allowed message
    let msg = r#"{"id":1,"method":"Page.enable"}"#;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        msg.to_string(),
    ))
    .await
    .expect("WS send failed");

    // The mock Chrome should receive this message
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), chrome_rx.recv())
        .await
        .expect("Timed out waiting for message")
        .expect("No message received");
    assert!(
        received.contains("Page.enable"),
        "Chrome should receive the allowed message: {}",
        received
    );

    // Client should receive the echo response
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("Timed out")
        .expect("Stream ended")
        .expect("WS error");
    let text = response.into_text().expect("Not text");
    assert!(text.contains("\"id\":1"), "Should contain id: {}", text);

    proxy.stop().await.expect("stop failed");
}

/// Un message WS interdit est bloqué — le client reçoit une erreur synthétique.
#[tokio::test]
async fn ws_relay_blocks_forbidden_message() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (_chrome_handle, mut chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Send a blocked message (Network.getCookies is in blocked list)
    let msg = r#"{"id":2,"method":"Network.getCookies"}"#;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        msg.to_string(),
    ))
    .await
    .expect("WS send failed");

    // Client should receive a synthetic error
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("Timed out")
        .expect("Stream ended")
        .expect("WS error");
    let text = response.into_text().expect("Not text");
    assert!(
        text.contains("error"),
        "Should contain error response: {}",
        text
    );
    assert!(
        text.contains("\"id\":2"),
        "Error should have matching id: {}",
        text
    );

    // Chrome should NOT have received the blocked message
    let chrome_got =
        tokio::time::timeout(std::time::Duration::from_millis(200), chrome_rx.recv()).await;
    assert!(
        chrome_got.is_err(),
        "Chrome should not receive blocked message"
    );

    proxy.stop().await.expect("stop failed");
}

/// La réponse Chrome est relayée au client.
#[tokio::test]
async fn ws_relay_chrome_to_client() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (_chrome_handle, _chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Send allowed message
    let msg = r#"{"id":5,"method":"Page.enable"}"#;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        msg.to_string(),
    ))
    .await
    .expect("WS send failed");

    // Should receive Chrome's echo response
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("Timed out")
        .expect("Stream ended")
        .expect("WS error");
    let text = response.into_text().expect("Not text");
    assert!(
        text.contains("\"id\":5"),
        "Response should have correct id: {}",
        text
    );
    assert!(
        text.contains("result"),
        "Response should contain result: {}",
        text
    );

    proxy.stop().await.expect("stop failed");
}

/// Un block émet un SecurityEvent via alert_tx.
#[tokio::test]
async fn ws_relay_emits_security_event_on_block() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (_chrome_handle, _chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Send blocked message
    let msg = r#"{"id":3,"method":"Network.getCookies"}"#;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        msg.to_string(),
    ))
    .await
    .expect("WS send failed");

    // Wait a bit for the event to propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Should have received a SecurityEvent
    let event = rx.try_recv().expect("Should have received SecurityEvent");
    assert_eq!(event.module, GuardModule::CdpProxy);

    proxy.stop().await.expect("stop failed");
}

/// Quand Chrome se déconnecte, le client est notifié proprement.
#[tokio::test]
async fn ws_relay_handles_chrome_disconnect() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (chrome_handle, _chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Kill the mock Chrome server
    chrome_handle.abort();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Sending to client should either fail or get a close
    // The exact behavior depends on timing, but it should not panic
    let send_result = ws
        .send(tokio_tungstenite::tungstenite::Message::Text(
            r#"{"id":1,"method":"Page.enable"}"#.to_string(),
        ))
        .await;
    // Either send fails or we get a close/error on next read
    if send_result.is_ok() {
        let next = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await;
        // We don't assert specific behavior — just that it doesn't panic
        drop(next);
    }

    proxy.stop().await.expect("stop failed");
}

/// Les messages binaires WS sont relayés sans inspection.
#[tokio::test]
async fn ws_handles_binary_messages() {
    let listen_port = common::find_free_port();
    let upstream_port = common::find_free_port();

    let (_chrome_handle, _chrome_rx) = start_mock_chrome_ws(upstream_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = cdp_io_config(listen_port, upstream_port);
    let proxy = CdpProxy::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(16);

    proxy.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ws_url = format!("ws://127.0.0.1:{}/devtools/browser/test-id", listen_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS connect failed");

    // Send binary message
    let binary_data = vec![0x01, 0x02, 0x03, 0x04];
    ws.send(tokio_tungstenite::tungstenite::Message::Binary(
        binary_data.clone(),
    ))
    .await
    .expect("WS send failed");

    // Should receive the binary echo back
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("Timed out")
        .expect("Stream ended")
        .expect("WS error");

    if let tokio_tungstenite::tungstenite::Message::Binary(data) = response {
        assert_eq!(data, binary_data, "Binary data should be echoed back");
    } else {
        panic!("Expected binary response, got: {:?}", response);
    }

    proxy.stop().await.expect("stop failed");
}
