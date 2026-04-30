use clap::Parser;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::{net::TcpStream, time::timeout};
use tracing::{error, info};
use uuid::Uuid;

#[derive(Parser, Debug)]
struct Args {
    /// This node's ID (must match an allowlisted node ID, e.g., 192.168.0.10)
    #[arg(long)]
    node_id: String,

    /// Controller base URL, e.g. http://192.168.0.5:8080
    #[arg(long)]
    controller: String,

    /// Poll interval in seconds
    #[arg(long, default_value_t = 5)]
    poll_secs: u64,

    /// Agent version tag for auditing
    #[arg(long, default_value = "0.1.0")]
    version: String,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args = Args::parse();

    if !in_lab_cidr(&args.node_id) {
        error!("refusing to start: node_id outside lab CIDR");
        std::process::exit(2);
    }

    let client = Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build client");

    register(&client, &args).await;

    loop {
        match fetch_tasks(&client, &args).await {
            Ok(tasks) => {
                if !tasks.is_empty() {
                    info!("received {} task(s)", tasks.len());
                }

                for task in tasks {
                    let findings = execute_task(&task).await;
                    if let Err(e) = submit_report(&client, &args, &task, findings).await {
                        error!("failed to submit report: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("task fetch failed: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(args.poll_secs)).await;
    }
}

async fn register(client: &Client, args: &Args) {
    let req = RegisterRequest {
        node_id: args.node_id.clone(),
        version: args.version.clone(),
    };

    let url = format!("{}/register", args.controller);
    match client.post(url).json(&req).send().await {
        Ok(resp) => match resp.json::<RegisterResponse>().await {
            Ok(r) => info!("registered: accepted={}, message={}", r.accepted, r.message),
            Err(e) => error!("register response parse error: {}", e),
        },
        Err(e) => error!("register failed: {}", e),
    }
}

async fn fetch_tasks(client: &Client, args: &Args) -> Result<Vec<Task>, String> {
    let url = format!("{}/task/{}", args.controller, args.node_id);
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("controller returned HTTP {}", resp.status()));
    }
    resp.json::<Vec<Task>>()
        .await
        .map_err(|e| e.to_string())
}

async fn execute_task(task: &Task) -> Vec<ProbeResult> {
    let mut findings = Vec::new();

    for p in &task.probes {
        if !in_lab_cidr(&p.target_ip) {
            findings.push(ProbeResult {
                target_id: p.target_id.clone(),
                target_ip: p.target_ip.clone(),
                port: p.port,
                reachable: false,
                latency_ms: 0,
                error: Some("target outside lab CIDR".into()),
            });
            continue;
        }

        let start = Instant::now();
        let addr = format!("{}:{}", p.target_ip, p.port);

        let result = timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await;

        match result {
            Ok(Ok(_stream)) => {
                findings.push(ProbeResult {
                    target_id: p.target_id.clone(),
                    target_ip: p.target_ip.clone(),
                    port: p.port,
                    reachable: true,
                    latency_ms: start.elapsed().as_millis(),
                    error: None,
                });
            }
            Ok(Err(e)) => {
                findings.push(ProbeResult {
                    target_id: p.target_id.clone(),
                    target_ip: p.target_ip.clone(),
                    port: p.port,
                    reachable: false,
                    latency_ms: start.elapsed().as_millis(),
                    error: Some(e.to_string()),
                });
            }
            Err(_) => {
                findings.push(ProbeResult {
                    target_id: p.target_id.clone(),
                    target_ip: p.target_ip.clone(),
                    port: p.port,
                    reachable: false,
                    latency_ms: start.elapsed().as_millis(),
                    error: Some("timeout".into()),
                });
            }
        }
    }

    findings
}

async fn submit_report(
    client: &Client,
    args: &Args,
    task: &Task,
    findings: Vec<ProbeResult>,
) -> Result<(), String> {
    let req = ReportRequest {
        node_id: args.node_id.clone(),
        task_id: task.task_id,
        hop: task.hop,
        findings,
    };

    let url = format!("{}/report", args.controller);
    let resp = client.post(url).json(&req).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("controller returned HTTP {}", resp.status()));
    }

    Ok(())
}

fn in_lab_cidr(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(v) => {
            let o = v.octets();
            o[0] == 192 && o[1] == 168 && o[2] == 0
        }
        Err(_) => false,
    }
}