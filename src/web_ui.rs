use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_files as fs;
use handlebars::Handlebars;
use serde_json::json;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use log::{info, error};

use crate::{WifiNetwork, scan_networks, detect_wifi_interface};
use crate::security;
use crate::packet_capture::{self, HandshakeCapture};

// Shared state for the web application
pub struct AppState {
    networks: Mutex<Vec<WifiNetwork>>,
    scanning: Mutex<bool>,
    interface: Mutex<String>,
    handshakes: Mutex<Vec<HandshakeCapture>>,
    testing: Mutex<bool>,
    test_results: Mutex<Vec<String>>,
}

// Initialize the web server
pub async fn start_server(port: u16) -> Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Create shared state
    let app_state = web::Data::new(AppState {
        networks: Mutex::new(Vec::new()),
        scanning: Mutex::new(false),
        interface: Mutex::new(detect_wifi_interface()),
        handshakes: Mutex::new(Vec::new()),
        testing: Mutex::new(false),
        test_results: Mutex::new(Vec::new()),
    });

    // Load existing handshakes
    match packet_capture::list_handshakes() {
        Ok(handshakes) => {
            let mut app_handshakes = app_state.handshakes.lock().unwrap();
            *app_handshakes = handshakes;
            info!("Loaded {} existing handshakes", app_handshakes.len());
        },
        Err(e) => {
            error!("Failed to load handshakes: {}", e);
        }
    };

    // Initialize Handlebars templates
    let mut handlebars = Handlebars::new();
    handlebars.register_templates_directory(".hbs", "templates").unwrap_or_else(|e| {
        error!("Failed to register templates: {}", e);
    });
    let handlebars_ref = web::Data::new(handlebars);

    info!("Starting web server on http://localhost:{}", port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(handlebars_ref.clone())
            // Static files
            .service(fs::Files::new("/static", "static").show_files_listing())
            // API routes
            .route("/api/scan", web::get().to(scan_api))
            .route("/api/networks", web::get().to(get_networks))
            .route("/api/security", web::post().to(check_security))
            .route("/api/handshakes", web::get().to(get_handshakes))
            .route("/api/capture-handshake", web::post().to(capture_handshake_api))
            .route("/api/real-world-test", web::post().to(real_world_test_api))
            .route("/api/test-results", web::get().to(get_test_results))
            // Page routes
            .route("/", web::get().to(index))
            .route("/dashboard", web::get().to(dashboard))
            .route("/security", web::get().to(security_page))
            .route("/handshakes", web::get().to(handshakes_page))
            .route("/testing", web::get().to(testing_page))
            .route("/about", web::get().to(about))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await?;

    Ok(())
}

// Route handlers
async fn index(hb: web::Data<Handlebars<'_>>) -> impl Responder {
    let data = json!({
        "title": "WiFi Scanner",
        "welcome_message": "Welcome to WiFi Scanner - A Security Testing Tool"
    });

    let body = hb.render("index", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

async fn dashboard(hb: web::Data<Handlebars<'_>>, app_state: web::Data<AppState>) -> impl Responder {
    let networks = app_state.networks.lock().unwrap();
    let interface = app_state.interface.lock().unwrap();

    let data = json!({
        "title": "Dashboard - WiFi Scanner",
        "interface": interface.to_string(),
        "networks": networks.to_vec(),
        "networks_count": networks.len()
    });

    let body = hb.render("dashboard", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

async fn security_page(hb: web::Data<Handlebars<'_>>) -> impl Responder {
    let data = json!({
        "title": "Security Analysis - WiFi Scanner"
    });

    let body = hb.render("security", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

async fn about(hb: web::Data<Handlebars<'_>>) -> impl Responder {
    let data = json!({
        "title": "About - WiFi Scanner",
        "version": env!("CARGO_PKG_VERSION"),
        "authors": env!("CARGO_PKG_AUTHORS"),
        "description": env!("CARGO_PKG_DESCRIPTION")
    });

    let body = hb.render("about", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

async fn handshakes_page(hb: web::Data<Handlebars<'_>>, app_state: web::Data<AppState>) -> impl Responder {
    let handshakes = app_state.handshakes.lock().unwrap();
    let interface = app_state.interface.lock().unwrap();

    let data = json!({
        "title": "Handshakes - WiFi Scanner",
        "interface": interface.to_string(),
        "handshakes": handshakes.to_vec(),
        "handshakes_count": handshakes.len()
    });

    let body = hb.render("handshakes", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

async fn testing_page(hb: web::Data<Handlebars<'_>>, app_state: web::Data<AppState>) -> impl Responder {
    let networks = app_state.networks.lock().unwrap();
    let interface = app_state.interface.lock().unwrap();
    let test_results = app_state.test_results.lock().unwrap();
    let testing = app_state.testing.lock().unwrap();

    let data = json!({
        "title": "Real-World Testing - WiFi Scanner",
        "interface": interface.to_string(),
        "networks": networks.to_vec(),
        "networks_count": networks.len(),
        "testing": *testing,
        "test_results": test_results.to_vec(),
        "results_count": test_results.len()
    });

    let body = hb.render("testing", &data).unwrap_or_else(|e| {
        error!("Template error: {}", e);
        "Template error".to_string()
    });

    HttpResponse::Ok().body(body)
}

// API handlers
async fn scan_api(app_state: web::Data<AppState>) -> impl Responder {
    let mut scanning = app_state.scanning.lock().unwrap();

    if *scanning {
        return HttpResponse::TooManyRequests().json(json!({
            "status": "error",
            "message": "Scan already in progress"
        }));
    }

    *scanning = true;
    drop(scanning); // Release the lock

    let interface = app_state.interface.lock().unwrap().clone();

    // Perform scan in a separate thread to not block the web server
    let app_state_clone = app_state.clone();
    tokio::spawn(async move {
        match scan_networks(&interface) {
            Ok(networks) => {
                let mut app_networks = app_state_clone.networks.lock().unwrap();
                *app_networks = networks;
                info!("Scan completed, found {} networks", app_networks.len());
            },
            Err(e) => {
                error!("Scan failed: {}", e);
            }
        }

        let mut scanning = app_state_clone.scanning.lock().unwrap();
        *scanning = false;
    });

    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Scan started"
    }))
}

async fn get_networks(app_state: web::Data<AppState>) -> impl Responder {
    let networks = app_state.networks.lock().unwrap();
    let scanning = app_state.scanning.lock().unwrap();

    HttpResponse::Ok().json(json!({
        "status": "success",
        "scanning": *scanning,
        "networks": networks.to_vec()
    }))
}

async fn check_security(
    app_state: web::Data<AppState>,
    params: web::Json<serde_json::Value>,
) -> impl Responder {
    let ssid = match params.get("ssid") {
        Some(val) => val.as_str().unwrap_or(""),
        None => ""
    };

    let bssid = match params.get("bssid") {
        Some(val) => val.as_str().unwrap_or(""),
        None => ""
    };

    if ssid.is_empty() || bssid.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "error",
            "message": "SSID and BSSID are required"
        }));
    }

    match security::check_network_security(ssid, bssid) {
        Ok(vulnerabilities) => {
            HttpResponse::Ok().json(json!({
                "status": "success",
                "ssid": ssid,
                "bssid": bssid,
                "vulnerabilities": vulnerabilities,
                "vulnerabilities_count": vulnerabilities.len()
            }))
        },
        Err(e) => {
            error!("Security check failed: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": format!("Security check failed: {}", e)
            }))
        }
    }
}

async fn get_handshakes(app_state: web::Data<AppState>) -> impl Responder {
    // Refresh handshakes list
    match packet_capture::list_handshakes() {
        Ok(handshakes) => {
            let mut app_handshakes = app_state.handshakes.lock().unwrap();
            *app_handshakes = handshakes;
        },
        Err(e) => {
            error!("Failed to refresh handshakes: {}", e);
        }
    };

    let handshakes = app_state.handshakes.lock().unwrap();

    HttpResponse::Ok().json(json!({
        "status": "success",
        "handshakes": handshakes.to_vec(),
        "handshakes_count": handshakes.len()
    }))
}

async fn capture_handshake_api(
    app_state: web::Data<AppState>,
    params: web::Json<serde_json::Value>,
) -> impl Responder {
    let bssid = match params.get("bssid") {
        Some(val) => val.as_str().unwrap_or(""),
        None => ""
    };

    let channel = match params.get("channel") {
        Some(val) => val.as_u64().unwrap_or(1) as u8,
        None => 1
    };

    if bssid.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "error",
            "message": "BSSID and channel are required"
        }));
    }

    let interface = app_state.interface.lock().unwrap().clone();

    // Capture handshake in a separate thread
    let app_state_clone = app_state.clone();
    tokio::spawn(async move {
        match packet_capture::capture_handshake(&interface, bssid, channel) {
            Ok(handshake) => {
                let mut app_handshakes = app_state_clone.handshakes.lock().unwrap();
                app_handshakes.push(handshake.clone());
                info!("Handshake captured for {}", bssid);
            },
            Err(e) => {
                error!("Handshake capture failed: {}", e);
            }
        }
    });

    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Handshake capture started"
    }))
}

async fn real_world_test_api(
    app_state: web::Data<AppState>,
    params: web::Json<serde_json::Value>,
) -> impl Responder {
    let ssid = match params.get("ssid") {
        Some(val) => val.as_str().unwrap_or(""),
        None => ""
    };

    let bssid = match params.get("bssid") {
        Some(val) => val.as_str().unwrap_or(""),
        None => ""
    };

    let channel = match params.get("channel") {
        Some(val) => val.as_u64().unwrap_or(1) as u8,
        None => 1
    };

    if ssid.is_empty() || bssid.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "error",
            "message": "SSID, BSSID, and channel are required"
        }));
    }

    let mut testing = app_state.testing.lock().unwrap();

    if *testing {
        return HttpResponse::TooManyRequests().json(json!({
            "status": "error",
            "message": "Test already in progress"
        }));
    }

    *testing = true;
    drop(testing);

    let interface = app_state.interface.lock().unwrap().clone();

    // Run test in a separate thread
    let app_state_clone = app_state.clone();
    let ssid_clone = ssid.to_string();
    let bssid_clone = bssid.to_string();

    tokio::spawn(async move {
        match packet_capture::real_world_test(&interface, &bssid_clone, &ssid_clone, channel) {
            Ok(findings) => {
                let mut test_results = app_state_clone.test_results.lock().unwrap();
                *test_results = findings;
                info!("Real-world test completed for {}", ssid_clone);
            },
            Err(e) => {
                error!("Real-world test failed: {}", e);
                let mut test_results = app_state_clone.test_results.lock().unwrap();
                test_results.push(format!("Test failed: {}", e));
            }
        }

        let mut testing = app_state_clone.testing.lock().unwrap();
        *testing = false;
    });

    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Real-world test started"
    }))
}

async fn get_test_results(app_state: web::Data<AppState>) -> impl Responder {
    let test_results = app_state.test_results.lock().unwrap();
    let testing = app_state.testing.lock().unwrap();

    HttpResponse::Ok().json(json!({
        "status": "success",
        "testing": *testing,
        "results": test_results.to_vec(),
        "results_count": test_results.len()
    }))
}
