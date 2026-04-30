use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    /// Path to config JSON
    #[arg(long, default_value = "config.example.json")]
    config: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    lab_cidr: String,
    seed_node: String,
    hop_limit: u32,
    max_hosts: usize,
    controller_bind: String,
    audit_log: String,
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize)]
struct Node {
    id: String,
    ip: String,
    neighbors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeTarget {
    target_id: String,
    target_ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Task {
    task_id: Uuid,
    kind: String,
    hop: u32,
    probes: Vec<ProbeTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterRequest {
    node_id: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterResponse {
    accepted: bool,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeResult {
    target_id: String,
    target_ip: String,
    port: u16,
    reachable: bool,
    latency_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportRequest {
    node_id: String,
    task_id: Uuid,
    hop: u32,
    findings: Vec<ProbeResult>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    registered: HashSet<String>,
    activated: HashSet<String>,
    completed_tasks: HashSet<Uuid>,
    hop_by_node: HashMap<String, u32>,
    task_queue: HashMap<String, Vec<Task>>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    nodes_by_id: Arc<HashMap<String, Node>>,
    runtime: Arc<Mutex<RuntimeState>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args = Args::parse();
    let config_str = std::fs::read_to_string(&args.config)
        .expect("failed to read config file");
    let config: Config = serde_json::from_str(&config_str)
        .expect("failed to parse config JSON");

    validate_config(&config).expect("config validation failed");

    let nodes_by_id: HashMap<String, Node> = config
        .nodes
        .iter()
        .cloned()
        .map(|n| (n.id.clone(), n))
        .collect();

    let app_state = AppState {
        config: Arc::new(config.clone()),
        nodes_by_id: Arc::new(nodes_by_id),
        runtime: Arc::new(Mutex::new(RuntimeState::default())),
    };

    seed_initial_task(&app_state).await;

    let app = Router::new()
        .route("/register", post(register))
        .route("/task/:node_id", get(get_tasks))
        .route("/report", post(report))
        .route("/status", get(status))
        .with_state(app_state.clone());

    info!("controller listening on {}", config.controller_bind);
    let listener = tokio::net::TcpListener::bind(&config.controller_bind)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

fn validate_config(config: &Config) -> Result<(), String> {
    if config.lab_cidr != "192.168.0.0/24" {
        return Err("This sample only supports lab_cidr = 192.168.0.0/24".into());
    }

    let mut ids = HashSet::new();

    for n in &config.nodes {
        if !ids.insert(n.id.clone()) {
            return Err(format!("duplicate node id: {}", n.id));
        }
        if n.id != n.ip {
            return Err(format!("for simplicity, node.id must equal node.ip: {}", n.id));
        }
        if !in_lab_cidr(&n.ip) {
            return Err(format!("node outside lab CIDR: {}", n.ip));
        }
    }

    if !ids.contains(&config.seed_node) {
        return Err(format!("seed_node not found in nodes: {}", config.seed_node));
    }

    for n in &config.nodes {
        for neighbor in &n.neighbors {
            if !ids.contains(neighbor) {
                return Err(format!("neighbor {} referenced by {} not found", neighbor, n.id));
            }
        }
    }

    Ok(())
}

fn in_lab_cidr(ip: &str) -> bool {
    let addr: Ipv4Addr = match ip.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let octets = addr.octets();
    octets[0] == 192 && octets[1] == 168 && octets[2] == 0
}

async fn seed_initial_task(app: &AppState) {
    let Some(seed_node) = app.nodes_by_id.get(&app.config.seed_node) else {
        error!("seed node not found");
        return;
    };

    let probes: Vec<ProbeTarget> = seed_node
        .neighbors
        .iter()
        .filter_map(|nid| app.nodes_by_id.get(nid))
        .map(|n| ProbeTarget {
            target_id: n.id.clone(),
            target_ip: n.ip.clone(),
            port: 445,
        })
        .collect();

    let task = Task {
        task_id: Uuid::new_v4(),
        kind: "probe_neighbors".to_string(),
        hop: 0,
        probes,
    };

    let mut rt = app.runtime.lock().await;
    rt.activated.insert(seed_node.id.clone());
    rt.hop_by_node.insert(seed_node.id.clone(), 0);
    rt.task_queue
        .entry(seed_node.id.clone())
        .or_default()
        .push(task.clone());

    append_audit(
        &app.config.audit_log,
        json!({
            "event": "seeded",
            "seed_node": seed_node.id,
            "task": task,
        }),
    );
}

async fn register(
    State(app): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    if !app.nodes_by_id.contains_key(&req.node_id) {
        return Err((StatusCode::FORBIDDEN, "node_id not in allowlist".into()));
    }

    {
        let mut rt = app.runtime.lock().await;
        rt.registered.insert(req.node_id.clone());
    }

    append_audit(
        &app.config.audit_log,
        json!({
            "event": "register",
            "node_id": req.node_id,
            "version": req.version,
        }),
    );

    Ok(Json(RegisterResponse {
        accepted: true,
        message: "registered".into(),
    }))
}

async fn get_tasks(
    Path(node_id): Path<String>,
    State(app): State<AppState>,
) -> Result<Json<Vec<Task>>, (StatusCode, String)> {
    if !app.nodes_by_id.contains_key(&node_id) {
        return Err((StatusCode::FORBIDDEN, "node_id not in allowlist".into()));
    }

    let tasks = {
        let mut rt = app.runtime.lock().await;
        rt.task_queue.remove(&node_id).unwrap_or_default()
    };

    append_audit(
        &app.config.audit_log,
        json!({
            "event": "task_fetch",
            "node_id": node_id,
            "task_count": tasks.len(),
        }),
    );

    Ok(Json(tasks))
}

async fn report(
    State(app): State<AppState>,
    Json(req): Json<ReportRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !app.nodes_by_id.contains_key(&req.node_id) {
        return Err((StatusCode::FORBIDDEN, "node_id not in allowlist".into()));
    }

    {
        let mut rt = app.runtime.lock().await;
        if rt.completed_tasks.contains(&req.task_id) {
            return Ok(Json(json!({"accepted": true, "duplicate": true})));
        }
        rt.completed_tasks.insert(req.task_id);
    }

    append_audit(
        &app.config.audit_log,
        json!({
            "event": "report",
            "node_id": req.node_id,
            "task_id": req.task_id,
            "hop": req.hop,
            "findings": req.findings,
        }),
    );

    let mut newly_enqueued = Vec::<String>::new();

    for finding in &req.findings {
        if !finding.reachable {
            continue;
        }

        if !app.nodes_by_id.contains_key(&finding.target_id) {
            continue;
        }

        let next_hop = req.hop + 1;
        if next_hop > app.config.hop_limit {
            continue;
        }

        let mut rt = app.runtime.lock().await;

        if rt.activated.len() >= app.config.max_hosts {
            break;
        }

        if rt.activated.contains(&finding.target_id) {
            continue;
        }

        let Some(target_node) = app.nodes_by_id.get(&finding.target_id) else {
            continue;
        };

        let probes: Vec<ProbeTarget> = target_node
            .neighbors
            .iter()
            .filter_map(|nid| app.nodes_by_id.get(nid))
            .map(|n| ProbeTarget {
                target_id: n.id.clone(),
                target_ip: n.ip.clone(),
                port: 445,
            })
            .collect();

        let task = Task {
            task_id: Uuid::new_v4(),
            kind: "probe_neighbors".to_string(),
            hop: next_hop,
            probes,
        };

        rt.activated.insert(target_node.id.clone());
        rt.hop_by_node.insert(target_node.id.clone(), next_hop);
        rt.task_queue
            .entry(target_node.id.clone())
            .or_default()
            .push(task.clone());

        newly_enqueued.push(target_node.id.clone());

        append_audit(
            &app.config.audit_log,
            json!({
                "event": "activated",
                "node_id": target_node.id,
                "hop": next_hop,
                "task": task,
            }),
        );
    }

    Ok(Json(json!({
        "accepted": true,
        "newly_enqueued": newly_enqueued
    })))
}

async fn status(State(app): State<AppState>) -> Json<Value> {
    let rt = app.runtime.lock().await;

    Json(json!({
        "registered": rt.registered,
        "activated": rt.activated,
        "completed_tasks": rt.completed_tasks.len(),
        "queued_nodes": rt.task_queue.keys().cloned().collect::<Vec<_>>(),
        "hop_by_node": rt.hop_by_node,
        "max_hosts": app.config.max_hosts,
        "hop_limit": app.config.hop_limit
    }))
}

fn append_audit(path: &str, value: Value) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", value);
    }
}
