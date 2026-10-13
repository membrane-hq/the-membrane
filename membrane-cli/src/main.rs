use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use chrono::Duration;
use clap::{Parser, Subcommand, ValueEnum};
use membrane_core::{
    build_ocsf_inspired_pack, build_rollup_bundle, day_bounds_utc, fetch_membrane_bus_events,
    fetch_membrane_events, fetch_session_chain_bootstrap, keys_from_nsec, membrane_kind_for,
    npub_from_keys, render_jsonl, subscribe_and_compute_bus_root, validate_rollup_bundle,
    BusPublisher, BusPublisherConfig, EventType, HttpOtsStamper, IntentAuthorizationCredential,
    MembraneEvent, MembranePayload, MockOtsStamper, OtsStamper, RollupBundle, SessionChainState,
    SiemEvent, SiemWebhookShipper, SignedRollupBundle, ENV_WEBHOOK_URL,
};
use membrane_gate::{
    demo_registry, run_demo_dashboard, run_gate_server, ChannelRegistry, DemoRuntime,
    DemoServerState, Gate, GateServerState, GitHubConnector, GitHubConnectorConfig, LlmProxy,
    RouterSessionRequest, ENV_TOKEN_FALLBACK, ENV_TOKEN_PRIMARY,
};

mod chat;
mod config;

use chat::ChatClient;
use config::{config_path, write_example_config, MembraneConfig};

#[derive(Parser)]
#[command(
    name = "membrane",
    about = "The Membrane Phase 0 prototype — Nostr attestation bus"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Attestation bus operations
    Bus {
        #[command(subcommand)]
        command: BusCommands,
    },
    /// IAC gate and pluggable model API proxy
    Gate {
        #[command(subcommand)]
        command: GateCommands,
    },
    /// Daily rollup export, sign, and OTS stamp
    Rollup {
        #[command(subcommand)]
        command: RollupCommands,
    },
    /// Evidence and SIEM/SOC export operations
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },
    /// Intent Authorization Credential tools
    Iac {
        #[command(subcommand)]
        command: IacCommands,
    },
    /// Invoke an allowlisted tool through the production gate
    Tools {
        #[command(subcommand)]
        command: ToolsCommands,
    },
    /// Local LLM chat through the gate (auto IAC + receipts)
    Chat {
        #[arg(long)]
        message: Option<String>,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        gate_url: Option<String>,
        #[arg(long, env = "MEMBRANE_RELAY_URL")]
        relay_url: Option<String>,
        #[arg(long)]
        model: Option<String>,
    },
    /// Session chain status and bus receipts
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// Sever the active session (publish degraded alert, invalidate IAC)
    Sever {
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, env = "MEMBRANE_RELAY_URL")]
        relay_url: Option<String>,
        #[arg(long)]
        scope_id: Option<String>,
    },
    /// Write default config to ~/.config/membrane/config.yaml
    Init,
    /// Launch the local interactive dashboard (no secrets or relay required)
    Demo {
        #[arg(long, default_value = "127.0.0.1:8790")]
        listen: String,
    },
    /// Technical IAC/relay smoke test for operators
    IacSmoke {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, default_value = "tools/channel-registry.example.yaml")]
        registry: PathBuf,
    },
}

#[derive(Subcommand)]
enum BusCommands {
    /// Publish a test MembraneEvent (kind 31990)
    PublishTest {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
    },
    /// Subscribe to bus events and recompute bus_root
    Subscribe {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long)]
        since: Option<i64>,
    },
}

#[derive(Subcommand)]
enum GateCommands {
    /// Start gate HTTP server (validates IAC before proxying to the model API)
    Start {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, default_value = "tools/channel-registry.example.yaml")]
        registry: PathBuf,
        #[arg(long, default_value = "tools/demo-iac.json")]
        iac: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
    },
}

#[derive(Subcommand)]
enum RollupCommands {
    /// Export RollupBundle for a UTC day from the attestation bus
    Export {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, value_name = "YYYY-MM-DD")]
        day: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a RollupBundle and write signed JSON
    Sign {
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Stamp ots_digest with OpenTimestamps and publish membrane.anchor.ots
    Stamp {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        ots_out: PathBuf,
        #[arg(long)]
        mock: bool,
    },
    /// Export, sign, and stamp rollup for a UTC day (default: yesterday)
    Daily {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, value_name = "YYYY-MM-DD")]
        day: Option<String>,
        #[arg(long, default_value = "/var/lib/membrane/rollup")]
        work_dir: PathBuf,
        #[arg(long)]
        mock: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SiemFormat {
    /// OCSF-inspired JSON pack (no certified class identifiers claimed)
    Ocsf,
    /// Newline-delimited vendor-neutral Membrane records
    Jsonl,
}

#[derive(Subcommand)]
enum EvidenceCommands {
    /// Export attestation-bus receipts and alerts for SIEM file or HTTP ingestion
    Export {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, value_enum, default_value = "jsonl")]
        format: SiemFormat,
        #[arg(long, default_value = "86400")]
        since_secs: i64,
        /// Restrict export to one public agent/subject identifier
        #[arg(long)]
        subject_pubkey: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// Show chain head, active IAC, and recent activity
    Status {
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, env = "MEMBRANE_RELAY_URL")]
        relay_url: Option<String>,
        #[arg(long)]
        gate_url: Option<String>,
    },
    /// List router CP events from the attestation bus
    Receipts {
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long, env = "MEMBRANE_RELAY_URL")]
        relay_url: Option<String>,
        #[arg(long, default_value = "86400")]
        since_secs: i64,
    },
}

#[derive(Subcommand)]
enum IacCommands {
    /// Issue a short-lived session IAC bound to the current CP chain head
    Issue {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        model: String,
        #[arg(long)]
        scope_id: Option<String>,
        #[arg(long, default_value = "3600")]
        ttl_secs: i64,
        #[arg(long)]
        parent_cp_hash: Option<String>,
        #[arg(long, default_value = "local-llm")]
        channel: Vec<String>,
        /// Public key of caller this operator-issued IAC is bound to.
        #[arg(long)]
        caller_pubkey: String,
        /// Allowed tool ids (repeatable), e.g. `--tool github.comment`
        #[arg(long = "tool")]
        tools: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Re-issue an expired or mismatched IAC under the same operator key. Copies the
    /// previous credential, changes only expiry and chain head, lists every difference.
    Reissue {
        #[arg(
            long,
            env = "MEMBRANE_RELAY_URL",
            default_value = "ws://127.0.0.1:7777"
        )]
        relay: String,
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        /// Previous operator-signed IAC (may be expired)
        #[arg(long)]
        previous: PathBuf,
        #[arg(long, default_value = "3600")]
        ttl_secs: i64,
        #[arg(long)]
        parent_cp_hash: Option<String>,
        /// Only needed when the previous IAC has no caller binding
        #[arg(long)]
        caller_pubkey: Option<String>,
        /// Add one model id (repeatable). Nothing is added unless named here.
        #[arg(long = "add-model")]
        add_models: Vec<String>,
        /// Add one tool id (repeatable)
        #[arg(long = "add-tool")]
        add_tools: Vec<String>,
        /// Add one channel (repeatable)
        #[arg(long = "add-channel")]
        add_channels: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an IAC JSON file with NOSTR_NSEC
    Sign {
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify IAC signature against a subject pubkey
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
}

#[derive(Subcommand)]
enum ToolsCommands {
    /// POST /v1/tools/invoke on a running gate (connector execution; separate from the demo)
    Invoke {
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        gate_url: String,
        #[arg(long)]
        iac: PathBuf,
        /// Caller signing key (not the operator issuing key).
        #[arg(long, env = "NOSTR_NSEC")]
        nsec: Option<String>,
        #[arg(long)]
        gate_pubkey: String,
        #[arg(long)]
        tool: String,
        /// Stable write ID. Reuse on retry; reconcile an uncertain result first.
        #[arg(long)]
        operation_id: Option<String>,
        #[arg(long)]
        model: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        issue_number: Option<u64>,
        #[arg(long)]
        pull_number: Option<u64>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        commit_title: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("membrane=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Bus { command } => match command {
            BusCommands::PublishTest { relay, nsec } => bus_publish_test(&relay, nsec).await,
            BusCommands::Subscribe { relay, since } => bus_subscribe(&relay, since).await,
        },
        Commands::Gate { command } => match command {
            GateCommands::Start {
                relay,
                nsec,
                registry,
                iac,
                listen,
            } => gate_start(&relay, nsec, &registry, &iac, &listen).await,
        },
        Commands::Rollup { command } => match command {
            RollupCommands::Export {
                relay,
                nsec,
                day,
                out,
            } => rollup_export(&relay, nsec, &day, &out).await,
            RollupCommands::Sign { nsec, input, out } => rollup_sign(nsec, &input, &out),
            RollupCommands::Stamp {
                relay,
                nsec,
                input,
                ots_out,
                mock,
            } => rollup_stamp(&relay, nsec, &input, &ots_out, mock).await,
            RollupCommands::Daily {
                relay,
                nsec,
                day,
                work_dir,
                mock,
            } => rollup_daily(&relay, nsec, day.as_deref(), &work_dir, mock).await,
        },
        Commands::Evidence { command } => match command {
            EvidenceCommands::Export {
                relay,
                format,
                since_secs,
                subject_pubkey,
                out,
            } => evidence_export(&relay, format, since_secs, subject_pubkey.as_deref(), &out).await,
        },
        Commands::Iac { command } => match command {
            IacCommands::Issue {
                relay,
                nsec,
                model,
                scope_id,
                ttl_secs,
                parent_cp_hash,
                channel,
                tools,
                caller_pubkey,
                out,
            } => {
                iac_issue(IacIssueArgs {
                    relay: &relay,
                    nsec,
                    model: &model,
                    scope_id: scope_id.as_deref(),
                    ttl_secs,
                    parent_cp_hash: parent_cp_hash.as_deref(),
                    channels: &channel,
                    tools: &tools,
                    caller_pubkey: &caller_pubkey,
                    out: &out,
                })
                .await
            }
            IacCommands::Reissue {
                relay,
                nsec,
                previous,
                ttl_secs,
                parent_cp_hash,
                caller_pubkey,
                add_models,
                add_tools,
                add_channels,
                out,
            } => {
                iac_reissue(
                    &relay,
                    nsec,
                    &previous,
                    ttl_secs,
                    parent_cp_hash.as_deref(),
                    caller_pubkey,
                    add_models,
                    add_tools,
                    add_channels,
                    &out,
                )
                .await
            }
            IacCommands::Sign { nsec, input, out } => iac_sign(nsec, &input, &out),
            IacCommands::Verify { input, pubkey } => iac_verify(&input, &pubkey),
        },
        Commands::Tools { command } => match command {
            ToolsCommands::Invoke {
                gate_url,
                iac,
                nsec,
                gate_pubkey,
                tool,
                operation_id,
                model,
                owner,
                repo,
                issue_number,
                pull_number,
                body,
                commit_title,
            } => {
                tools_invoke(ToolsInvokeArgs {
                    gate_url: &gate_url,
                    iac_path: &iac,
                    nsec,
                    gate_pubkey: &gate_pubkey,
                    tool: &tool,
                    operation_id: operation_id.as_deref(),
                    model: &model,
                    owner: &owner,
                    repo: &repo,
                    issue_number,
                    pull_number,
                    body: body.as_deref(),
                    commit_title: commit_title.as_deref(),
                })
                .await
            }
        },
        Commands::Demo { listen } => run_local_demo(&listen).await,
        Commands::IacSmoke {
            relay,
            nsec,
            registry,
        } => run_iac_smoke(&relay, nsec, &registry).await,
        Commands::Chat {
            message,
            nsec,
            gate_url,
            relay_url,
            model,
        } => run_chat(nsec, gate_url, relay_url, model, message).await,
        Commands::Session { command } => match command {
            SessionCommands::Status {
                nsec,
                relay_url,
                gate_url,
            } => run_session_status(nsec, relay_url, gate_url).await,
            SessionCommands::Receipts {
                nsec,
                relay_url,
                since_secs,
            } => run_session_receipts(nsec, relay_url, since_secs).await,
        },
        Commands::Sever {
            nsec,
            relay_url,
            scope_id,
        } => run_sever(nsec, relay_url, scope_id).await,
        Commands::Init => run_init(),
    }
}

async fn run_chat(
    nsec: Option<String>,
    gate_url: Option<String>,
    relay_url: Option<String>,
    model: Option<String>,
    message: Option<String>,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let mut cfg = MembraneConfig::load()?;
    if let Some(u) = gate_url {
        cfg.gate_url = u;
    }
    if let Some(u) = relay_url {
        cfg.relay_url = u;
    }
    if let Some(m) = model {
        cfg.model = m;
    }

    let mut client = ChatClient::new(cfg, keys).await?;
    if let Some(msg) = message {
        let reply = client.send_once(&msg).await?;
        println!("{reply}");
    } else {
        client.run_repl().await?;
    }
    Ok(())
}

async fn run_session_status(
    nsec: Option<String>,
    relay_url: Option<String>,
    gate_url: Option<String>,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let mut cfg = MembraneConfig::load()?;
    if let Some(u) = relay_url {
        cfg.relay_url = u;
    }
    if let Some(u) = gate_url {
        cfg.gate_url = u;
    }
    chat::session_status(&cfg, &keys).await
}

async fn run_session_receipts(
    nsec: Option<String>,
    relay_url: Option<String>,
    since_secs: i64,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let mut cfg = MembraneConfig::load()?;
    if let Some(u) = relay_url {
        cfg.relay_url = u;
    }
    chat::list_receipts(&cfg, &keys, since_secs).await
}

async fn run_sever(
    nsec: Option<String>,
    relay_url: Option<String>,
    scope_id: Option<String>,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let mut cfg = MembraneConfig::load()?;
    if let Some(u) = relay_url {
        cfg.relay_url = u;
    }
    chat::sever_session(&cfg, &keys, scope_id.as_deref()).await
}

fn run_init() -> Result<()> {
    let path = config_path().context("HOME not set")?;
    if path.exists() {
        println!("config already exists: {}", path.display());
        return Ok(());
    }
    write_example_config(&path)?;
    println!("wrote {}", path.display());
    println!("edit gate_url / relay_url / model for your setup");
    Ok(())
}

fn load_keys(nsec: Option<String>) -> Result<nostr::Keys> {
    let nsec = nsec.context("NOSTR_NSEC required (set env or --nsec)")?;
    keys_from_nsec(&nsec)
}

async fn bus_publish_test(relay: &str, nsec: Option<String>) -> Result<()> {
    let keys = load_keys(nsec)?;
    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });

    let now = now_secs();
    let mut event = MembraneEvent::new(
        EventType::CpLiveness,
        keys.public_key().to_hex(),
        "0".repeat(64),
        now,
        MembranePayload::Generic(serde_json::json!({
            "note": "phase-0 publish-test",
            "bus_probe": true
        })),
    );

    let id = publisher.publish(&mut event, None).await?;
    println!(
        "published kind {} event {}",
        membrane_kind_for(event.event_type),
        id.to_hex()
    );
    println!("npub: {}", npub_from_keys(&keys)?);
    Ok(())
}

async fn bus_subscribe(relay: &str, since: Option<i64>) -> Result<()> {
    let (events, root) = subscribe_and_compute_bus_root(relay, since).await?;
    println!("events: {}", events.len());
    for event in &events {
        println!(
            "  {} @ {} type={}",
            event.timestamp,
            event.subject_pubkey,
            event.event_type.as_str()
        );
    }
    println!("bus_root: {}", root.unwrap_or_else(|| "<empty>".into()));
    Ok(())
}

async fn gate_start(
    relay: &str,
    nsec: Option<String>,
    registry_path: &PathBuf,
    iac_path: &PathBuf,
    listen: &str,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let registry = ChannelRegistry::load(registry_path)?;
    let default_iac: IntentAuthorizationCredential =
        serde_json::from_str(&std::fs::read_to_string(iac_path)?)?;

    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });
    let mut gate =
        Gate::new(registry.clone(), publisher).with_identity_registry_path(registry_path.clone());
    if let Some(path) = std::env::var_os("MEMBRANE_OPERATOR_OIDC_CONFIG") {
        let config = serde_yaml::from_str::<membrane_gate::oidc::OidcConfig>(
            &std::fs::read_to_string(path).context("read operator OIDC config")?,
        )
        .context("parse operator OIDC config")?;
        gate = gate.with_operator_oidc(config)?;
    }
    let siem_export_config = std::env::var_os(membrane_gate::siem_export::ENV_EXPORT_CONFIG);
    if let Some(path) = &siem_export_config {
        if std::env::var_os(ENV_WEBHOOK_URL).is_some() {
            bail!(
                "{} and {ENV_WEBHOOK_URL} are both set; use only the hardened export",
                membrane_gate::siem_export::ENV_EXPORT_CONFIG
            );
        }
        let operation_dir = std::env::var_os("MEMBRANE_OPERATION_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(".membrane/tool-operations"));
        let exporter = membrane_gate::siem_export::SiemExporter::start_from_file(
            std::path::Path::new(path),
            &operation_dir,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let status = exporter.status();
        println!(
            "gate: SIEM export enabled (failure_mode={:?}, pending={})",
            status.failure_mode, status.pending
        );
        gate = gate.with_siem_export(exporter);
    } else if let Some(shipper) =
        SiemWebhookShipper::from_env().map_err(|e| anyhow::anyhow!("{e}"))?
    {
        println!(
            "gate: SIEM webhook enabled (format={}, fail_open={}, urls={})",
            shipper.config().format.as_str(),
            shipper.config().fail_open,
            shipper.config().urls.len()
        );
        gate = gate.with_siem_shipper(Arc::new(shipper));
    } else {
        println!("gate: SIEM webhook disabled (set {ENV_WEBHOOK_URL} to enable live shipping)");
    }
    let gate = Arc::new(gate);

    gate.validate_iac(Some(&default_iac), now_secs())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let pubkey = keys.public_key().to_hex();
    let operations = Arc::new(membrane_gate::operations::OperationJournal::from_env());
    let bus_events = fetch_membrane_bus_events(relay, None, 5_000).await?;
    let session_chain = operations.import_relay(&bus_events, &pubkey)?;
    println!(
        "gate: chain head cp_hash={} session_nonce={}",
        session_chain.last_cp_hash, session_chain.session_nonce
    );
    if let Some(scope) = &session_chain.degraded_scope_id {
        println!(
            "gate: degraded scope={scope} reason={}",
            session_chain.degraded_reason.as_deref().unwrap_or("?")
        );
    }
    println!("gate: Δt={}s", registry.delta_t_secs);

    let github_cfg = GitHubConnectorConfig::from_env(registry.github_repo_allowlist.clone());
    let model_api = registry.model_api_url.as_deref().unwrap_or("<mock>");
    println!("gate: IAC ok, model_api={model_api}, listen={listen}");
    println!(
        "gate: GitHub connector repos={:?} token_env={}/{} configured={}",
        registry.github_repo_allowlist,
        ENV_TOKEN_PRIMARY,
        ENV_TOKEN_FALLBACK,
        github_cfg.has_token()
    );
    if registry.github_repo_allowlist.is_empty() {
        println!(
            "gate: github_repo_allowlist empty - GitHub invokes will fail closed until configured"
        );
    }

    let proxy = Arc::new(LlmProxy::new(registry.model_api_url.clone()).with_dev_mock_from_env());
    let approvals = match &registry.approval {
        Some(policy) => {
            policy.validate().map_err(anyhow::Error::msg)?;
            let path = std::env::var("MEMBRANE_APPROVAL_STORE").context(
                "approval gates are configured: set MEMBRANE_APPROVAL_STORE to a durable file path",
            )?;
            println!(
                "gate: approval gates holdable_tools={:?} ttl={}s store={path}",
                policy.holdable_tools, policy.ttl_secs
            );
            Some(Arc::new(membrane_gate::approval::ApprovalStore::open(
                path,
            )?))
        }
        None => None,
    };
    let state = GateServerState {
        gate,
        proxy,
        default_iac: Some(default_iac),
        session_chain: Arc::new(tokio::sync::Mutex::new(session_chain)),
        operations,
        github: Arc::new(GitHubConnector::new(github_cfg)),
        audit: Arc::new(membrane_gate::audit::AuditLog::default()),
        spend: membrane_gate::routstr::SpendService::from_env()?.map(Arc::new),
        approvals,
    };

    run_gate_server(state, listen).await
}

async fn evidence_export(
    relay: &str,
    format: SiemFormat,
    since_secs: i64,
    subject_pubkey: Option<&str>,
    out: &PathBuf,
) -> Result<()> {
    if since_secs < 0 {
        bail!("--since-secs must be zero or greater");
    }
    let since = now_secs().saturating_sub(since_secs);
    let bus_events = fetch_membrane_bus_events(relay, Some(since), 10_000).await?;
    let events: Vec<_> = bus_events
        .iter()
        .filter(|bus_event| {
            subject_pubkey
                .map(|subject| bus_event.event.subject_pubkey == subject)
                .unwrap_or(true)
        })
        .map(|bus_event| {
            let id = bus_event.id.to_hex();
            SiemEvent::from_membrane_event(&bus_event.event, Some(&id))
        })
        .collect();

    let body = match format {
        SiemFormat::Ocsf => {
            serde_json::to_string_pretty(&build_ocsf_inspired_pack(&events, now_secs()))?
        }
        SiemFormat::Jsonl => render_jsonl(&events)?,
    };
    std::fs::write(out, body)?;
    println!(
        "SIEM export: {} event(s), format={}, out={}",
        events.len(),
        match format {
            SiemFormat::Ocsf => "ocsf-inspired",
            SiemFormat::Jsonl => "jsonl",
        },
        out.display()
    );
    Ok(())
}

async fn rollup_export(relay: &str, nsec: Option<String>, day: &str, out: &PathBuf) -> Result<()> {
    let keys = load_keys(nsec)?;
    let (period_start, period_end) = day_bounds_utc(day)?;
    let events = fetch_membrane_events(relay, Some(period_start), 5_000).await?;
    let bundle = build_rollup_bundle(
        &events,
        &keys.public_key().to_hex(),
        period_start,
        period_end,
    )?;
    validate_rollup_bundle(&bundle)?;

    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(out, json)?;
    println!("rollup exported for {day}");
    println!("  period: {period_start} .. {period_end}");
    println!("  cp_chain_root: {}", bundle.cp_chain_root);
    println!("  last_bus_root: {}", bundle.last_bus_root);
    println!("  out: {}", out.display());
    Ok(())
}

fn rollup_sign(nsec: Option<String>, input: &PathBuf, out: &PathBuf) -> Result<()> {
    let keys = load_keys(nsec)?;
    let bundle: RollupBundle =
        serde_json::from_str(&std::fs::read_to_string(input)?).context("parse rollup bundle")?;
    validate_rollup_bundle(&bundle)?;
    let signed = SignedRollupBundle::sign(bundle, &keys)?;
    let json = serde_json::to_string_pretty(&signed)?;
    std::fs::write(out, json)?;
    println!("signed rollup written to {}", out.display());
    println!("  ots_digest: {}", signed.ots_digest_hex()?);
    Ok(())
}

async fn rollup_stamp(
    relay: &str,
    nsec: Option<String>,
    input: &PathBuf,
    ots_out: &PathBuf,
    mock: bool,
) -> Result<()> {
    let keys = load_keys(nsec)?;
    let signed: SignedRollupBundle =
        serde_json::from_str(&std::fs::read_to_string(input)?).context("parse signed rollup")?;
    validate_rollup_bundle(&signed.bundle)?;

    let digest = signed.ots_digest()?;
    let digest_hex = hex::encode(digest);
    println!("ots_digest: {digest_hex}");

    let stamp = if mock {
        MockOtsStamper.stamp_digest(digest).await?
    } else {
        HttpOtsStamper::new(HttpOtsStamper::default_calendars())?
            .stamp_digest(digest)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
    };

    std::fs::write(ots_out, &stamp.proof_bytes)?;
    println!(
        "OTS proof written to {} (calendar: {})",
        ots_out.display(),
        stamp.calendar_url
    );

    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });

    let now = now_secs();
    let mut anchor = MembraneEvent::new(
        EventType::AnchorOts,
        keys.public_key().to_hex(),
        signed.bundle.last_cp_hash.clone(),
        now,
        MembranePayload::Generic(serde_json::json!({
            "target": digest_hex,
            "ots_b64": stamp.proof_b64(),
            "period_end": signed.bundle.period_end,
            "cp_chain_root": signed.bundle.cp_chain_root,
            "last_bus_root": signed.bundle.last_bus_root,
        })),
    );

    let id = publisher.publish(&mut anchor, None).await?;
    println!(
        "published membrane.anchor.ots kind {} event {}",
        membrane_kind_for(EventType::AnchorOts),
        id.to_hex()
    );
    Ok(())
}

struct IacIssueArgs<'a> {
    relay: &'a str,
    nsec: Option<String>,
    model: &'a str,
    scope_id: Option<&'a str>,
    ttl_secs: i64,
    parent_cp_hash: Option<&'a str>,
    channels: &'a [String],
    tools: &'a [String],
    caller_pubkey: &'a str,
    out: &'a PathBuf,
}

async fn iac_issue(args: IacIssueArgs<'_>) -> Result<()> {
    let IacIssueArgs {
        relay,
        nsec,
        model,
        scope_id,
        ttl_secs,
        parent_cp_hash,
        channels,
        tools,
        caller_pubkey,
        out,
    } = args;
    let keys = load_keys(nsec)?;
    let now = now_secs();
    let scope_id = scope_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("session-{}", now));

    let parent = match parent_cp_hash {
        Some(hash) => hash.to_string(),
        None => {
            let (head, _, _) =
                fetch_session_chain_bootstrap(relay, &keys.public_key().to_hex()).await?;
            head
        }
    };

    let mut iac = IntentAuthorizationCredential::new_session_with_tools(
        scope_id.clone(),
        model,
        parent.clone(),
        now + ttl_secs,
        channels.to_vec(),
        vec!["cloud-telemetry".into(), "training-retention".into()],
        tools.to_vec(),
    );
    nostr::PublicKey::from_hex(caller_pubkey).context("caller public key")?;
    iac.caller_pubkey = Some(caller_pubkey.to_ascii_lowercase());
    iac.sign(&keys).map_err(|e| anyhow::anyhow!("{e}"))?;
    let iac_hash = iac.hash_hex()?;

    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });
    let mut issued_event = MembraneEvent::new(
        EventType::Iac,
        keys.public_key().to_hex(),
        parent.clone(),
        now,
        MembranePayload::Generic(serde_json::json!({
            "scope_id": scope_id,
            "model_allowlist": iac.model_allowlist,
            "tool_allowlist": iac.tool_allowlist,
            "iac_hash": iac_hash,
            "parent_cp_hash": parent,
            "valid_until": iac.valid_until,
        })),
    );
    let issued_event_id = publisher.publish(&mut issued_event, None).await?;

    if let Some(shipper) = SiemWebhookShipper::from_env().map_err(|e| anyhow::anyhow!("{e}"))? {
        let mapped = SiemEvent::from_membrane_event(&issued_event, Some(&issued_event_id.to_hex()));
        shipper
            .deliver_respecting_fail_open(&mapped)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "  siem webhook: shipped authorization_issued ({})",
            shipper.config().format.as_str()
        );
    }

    let json = serde_json::to_string_pretty(&iac)?;
    std::fs::write(out, json)?;
    println!("session IAC written to {}", out.display());
    println!("  scope_id: {scope_id}");
    println!("  model: {model}");
    println!("  tools: {:?}", iac.tool_allowlist);
    println!("  valid_until: {} (+{ttl_secs}s)", iac.valid_until);
    println!("  parent_cp_hash: {parent}");
    println!("  signer: {}", keys.public_key().to_hex());
    println!("  authorization_event: {}", issued_event_id.to_hex());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn iac_reissue(
    relay: &str,
    nsec: Option<String>,
    previous: &PathBuf,
    ttl_secs: i64,
    parent_cp_hash: Option<&str>,
    caller_pubkey: Option<String>,
    add_models: Vec<String>,
    add_tools: Vec<String>,
    add_channels: Vec<String>,
    out: &PathBuf,
) -> Result<()> {
    if previous == out {
        bail!("--out must differ from --previous; the old credential is kept as evidence");
    }
    let keys = load_keys(nsec)?;
    let now = now_secs();
    let old: IntentAuthorizationCredential =
        serde_json::from_str(&std::fs::read_to_string(previous).context("read previous IAC")?)
            .context("parse previous IAC")?;
    let old_hash = old.hash_hex()?;
    if let Some(pk) = caller_pubkey.as_deref() {
        nostr::PublicKey::from_hex(pk).context("caller public key")?;
    }
    let parent = match parent_cp_hash {
        Some(hash) => hash.to_string(),
        None => {
            let (head, _, _) =
                fetch_session_chain_bootstrap(relay, &keys.public_key().to_hex()).await?;
            head
        }
    };
    let (mut iac, changes) = old
        .reissue(
            &keys.public_key().to_hex(),
            &membrane_core::iac::ReissueRequest {
                now,
                ttl_secs,
                parent_cp_hash: parent.clone(),
                caller_pubkey,
                add_models,
                add_tools,
                add_channels,
            },
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    iac.sign(&keys).map_err(|e| anyhow::anyhow!("{e}"))?;
    let iac_hash = iac.hash_hex()?;

    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });
    let mut event = MembraneEvent::new(
        EventType::Iac,
        keys.public_key().to_hex(),
        parent.clone(),
        now,
        MembranePayload::Generic(serde_json::json!({
            "scope_id": iac.scope_id,
            "model_allowlist": iac.model_allowlist,
            "tool_allowlist": iac.tool_allowlist,
            "iac_hash": iac_hash,
            "supersedes_iac_hash": old_hash,
            "parent_cp_hash": parent,
            "valid_until": iac.valid_until,
            "reissued": true,
        })),
    );
    let event_id = publisher.publish(&mut event, None).await?;

    std::fs::write(out, serde_json::to_string_pretty(&iac)?)?;
    println!("re-issued IAC written to {}", out.display());
    println!("  previous: {old_hash}");
    println!("  new:      {iac_hash}");
    println!("  changes:");
    for c in &changes {
        println!("    {}: {} -> {}", c.field, c.from, c.to);
    }
    println!("  authorization_event: {}", event_id.to_hex());
    println!(
        "  The gate loads the new file at start; restart it with --iac {}",
        out.display()
    );
    Ok(())
}

struct ToolsInvokeArgs<'a> {
    gate_url: &'a str,
    iac_path: &'a PathBuf,
    nsec: Option<String>,
    gate_pubkey: &'a str,
    tool: &'a str,
    operation_id: Option<&'a str>,
    model: &'a str,
    owner: &'a str,
    repo: &'a str,
    issue_number: Option<u64>,
    pull_number: Option<u64>,
    body: Option<&'a str>,
    commit_title: Option<&'a str>,
}

async fn tools_invoke(args: ToolsInvokeArgs<'_>) -> Result<()> {
    let ToolsInvokeArgs {
        gate_url,
        iac_path,
        nsec,
        gate_pubkey,
        tool,
        operation_id,
        model,
        owner,
        repo,
        issue_number,
        pull_number,
        body,
        commit_title,
    } = args;
    let iac_raw = std::fs::read_to_string(iac_path).context("read IAC")?;
    let url = format!("{}/v1/tools/invoke", gate_url.trim_end_matches('/'));
    let payload = serde_json::json!({
        "tool": tool,
        "operation_id": operation_id,
        "model": model,
        "owner": owner,
        "repo": repo,
        "issue_number": issue_number,
        "pull_number": pull_number,
        "body": body,
        "commit_title": commit_title,
    });
    let client = reqwest::Client::new();
    let keys = load_keys(nsec)?;
    let iac: IntentAuthorizationCredential = serde_json::from_str(&iac_raw)?;
    iac.verify_signature(gate_pubkey)?;
    anyhow::ensure!(
        iac.caller_pubkey.as_deref() == Some(keys.public_key().to_hex().as_str()),
        "IAC caller does not match caller key"
    );
    let health: serde_json::Value = client
        .get(format!("{}/health", gate_url.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let audience = health["caller_audience"]
        .as_str()
        .context("gate lacks caller challenge")?;
    anyhow::ensure!(
        audience.starts_with(&format!("{gate_pubkey}:")),
        "foreign gate challenge"
    );
    let typed: membrane_gate::ToolInvokeRequest = serde_json::from_value(payload.clone())?;
    let proof = membrane_core::caller::CallerProof::sign(
        &keys,
        audience,
        "/v1/tools/invoke",
        &typed,
        &iac,
        now_secs(),
        nostr::Keys::generate().public_key().to_hex(),
    )?;
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Membrane-IAC", serde_json::to_string(&iac)?)
        .header("X-Membrane-Caller-Proof", serde_json::to_string(&proof)?)
        .json(&payload)
        .send()
        .await
        .context("POST /v1/tools/invoke")?;
    let status = resp.status();
    let cp = resp
        .headers()
        .get("x-membrane-cp-hash")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let text = resp.text().await.context("read response body")?;
    println!("HTTP {status}");
    if let Some(cp) = cp {
        println!("x-membrane-cp-hash: {cp}");
    }
    println!("{text}");
    if !status.is_success() {
        bail!("tool invoke blocked or failed");
    }
    Ok(())
}

fn iac_sign(nsec: Option<String>, input: &PathBuf, out: &PathBuf) -> Result<()> {
    let keys = load_keys(nsec)?;
    let mut iac: IntentAuthorizationCredential =
        serde_json::from_str(&std::fs::read_to_string(input)?).context("parse IAC")?;
    iac.sign(&keys).map_err(|e| anyhow::anyhow!("{e}"))?;
    let json = serde_json::to_string_pretty(&iac)?;
    std::fs::write(out, json)?;
    println!("signed IAC written to {}", out.display());
    println!("  signer: {}", keys.public_key().to_hex());
    Ok(())
}

fn iac_verify(input: &PathBuf, pubkey: &str) -> Result<()> {
    let iac: IntentAuthorizationCredential =
        serde_json::from_str(&std::fs::read_to_string(input)?).context("parse IAC")?;
    iac.verify_signature(pubkey)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("IAC signature valid for pubkey {pubkey}");
    Ok(())
}

async fn rollup_daily(
    relay: &str,
    nsec: Option<String>,
    day: Option<&str>,
    work_dir: &PathBuf,
    mock: bool,
) -> Result<()> {
    let day = match day {
        Some(d) => d.to_string(),
        None => {
            let yesterday = chrono::Utc::now() - chrono::Duration::days(1);
            yesterday.format("%Y-%m-%d").to_string()
        }
    };

    std::fs::create_dir_all(work_dir)?;
    let rollup_path = work_dir.join(format!("rollup-{day}.json"));
    let signed_path = work_dir.join(format!("rollup-{day}.signed.json"));
    let ots_path = work_dir.join(format!("rollup-{day}.ots"));

    rollup_export(relay, nsec.clone(), &day, &rollup_path).await?;
    rollup_sign(nsec.clone(), &rollup_path, &signed_path)?;
    rollup_stamp(relay, nsec, &signed_path, &ots_path, mock).await?;
    println!("daily rollup complete for {day}");
    Ok(())
}

async fn run_local_demo(listen: &str) -> Result<()> {
    // Ephemeral local keys — never requires NOSTR_NSEC or production secrets.
    let keys = nostr::Keys::generate();
    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: "memory://demo".into(),
        keys: keys.clone(),
    });
    let registry = demo_registry();
    let mut gate = Gate::new(registry, publisher);
    // Optional: only when the operator exports a webhook URL into the demo env.
    // Public sandbox must leave this unset. Simulation events stay marked simulation=true.
    match SiemWebhookShipper::from_env() {
        Ok(Some(shipper)) => {
            println!(
                "  siem webhook: optional local shipper enabled (format={})",
                shipper.config().format.as_str()
            );
            gate = gate.with_siem_shipper(Arc::new(shipper));
        }
        Ok(None) => {}
        Err(err) => bail!("invalid SIEM webhook env: {err}"),
    }
    let gate = Arc::new(gate);

    println!("Membrane demo (local, simulation-only)");
    println!("  listen:      http://{listen}/");
    println!("  issuer:      {}", keys.public_key().to_hex());
    println!("  bus:         memory://demo (no relay required)");
    println!("  demo APIs:   /demo/api/* (disabled in production gate start)");
    println!("  scope:       gateway-routed traffic only; tools are simulated");
    println!();
    println!("Open the dashboard, then: issue → allowed → block → sever → evidence");

    let state = DemoServerState {
        gate,
        session_chain: Arc::new(tokio::sync::Mutex::new(SessionChainState::genesis())),
        runtime: Arc::new(tokio::sync::Mutex::new(DemoRuntime::new())),
    };
    run_demo_dashboard(state, listen).await
}

async fn run_iac_smoke(relay: &str, nsec: Option<String>, registry_path: &PathBuf) -> Result<()> {
    let keys = load_keys(nsec)?;
    let registry = ChannelRegistry::load(registry_path)?;
    let publisher = BusPublisher::new(BusPublisherConfig {
        relay_url: relay.to_string(),
        keys: keys.clone(),
    });
    let gate = Gate::new(registry.clone(), publisher);

    let now = now_secs();
    let req = RouterSessionRequest {
        model_id: "sha256:demo-model".into(),
        context_chunks: vec![b"demo prompt chunk".to_vec()],
        session_nonce: 42,
        parent_cp_hash: "0".repeat(64),
        scope_id: None,
        tool_id: None,
    };

    println!("=== Step 1: open router without IAC (expect fail-closed) ===");
    match gate.open_router_session(None, req.clone(), now, None).await {
        Ok(_) => bail!("expected fail-closed without IAC"),
        Err(err) => println!("FAIL-CLOSED: {err}"),
    }

    let iac = demo_iac(&keys, now);
    println!("\n=== Step 2: open router with valid IAC (expect bus event) ===");
    let outcome = gate
        .open_router_session(Some(&iac), req.clone(), now, None)
        .await?;
    println!("OK: membrane.cp.router published");
    println!(
        "  bus_event_id: {}",
        outcome.bus_event_id.as_deref().unwrap_or_default()
    );
    println!("  context_merkle_root: {}", outcome.context_merkle_root);
    println!("  cp_hash: {}", outcome.cp_hash);

    let req2 = RouterSessionRequest {
        model_id: "sha256:demo-model".into(),
        context_chunks: vec![b"second turn".to_vec()],
        session_nonce: 43,
        parent_cp_hash: outcome.cp_hash.clone(),
        scope_id: None,
        tool_id: None,
    };
    println!("\n=== Step 2b: chained router CP (parent = prior cp_hash) ===");
    let outcome2 = gate
        .open_router_session(Some(&iac), req2, now + 1, outcome.bus_event_id.as_deref())
        .await?;
    println!("  cp_hash: {}", outcome2.cp_hash);
    if outcome.cp_hash == outcome2.cp_hash {
        bail!("expected distinct cp hashes across chain");
    }

    let events = fetch_membrane_events(relay, Some(now - 60), 100).await?;
    let root = membrane_core::bus_root_from_events(&events)?;
    println!("\n=== Step 3: recompute bus_root from relay ===");
    println!("  events fetched: {}", events.len());
    println!("  bus_root: {}", root.unwrap_or_else(|| "<empty>".into()));

    println!("\n=== Step 4: model API proxy ===");
    if registry.model_api_url.is_some() {
        let proxy = LlmProxy::new(registry.model_api_url.clone());
        let llm = proxy.complete("sha256:demo-model", "membrane demo").await?;
        println!("  {llm}");
    } else {
        println!("  skipped: no model_api_url in the channel registry");
    }

    Ok(())
}

fn demo_iac(keys: &nostr::Keys, now: i64) -> IntentAuthorizationCredential {
    let mut iac = IntentAuthorizationCredential {
        version: IntentAuthorizationCredential::SCHEMA_VERSION.to_string(),
        caller_pubkey: None,
        scope_id: "demo-session-001".into(),
        permitted_channels: vec!["local-llm".into()],
        model_allowlist: vec!["sha256:demo-model".into()],
        tool_allowlist: Vec::new(),
        decoder_version: None,
        stimulation_policy: None,
        context_merkle_bound: "f".repeat(64),
        forbidden_exports: vec!["cloud-telemetry".into(), "training-retention".into()],
        valid_until: now + Duration::minutes(5).num_seconds(),
        parent_cp_hash: "0".repeat(64),
        signature: None,
    };
    iac.sign(keys).expect("demo IAC sign");
    iac
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn demo_is_the_local_dashboard() {
        let cli = Cli::try_parse_from(["membrane", "demo"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Demo { listen } if listen == "127.0.0.1:8790"
        ));
    }

    #[test]
    fn iac_smoke_keeps_the_operator_test() {
        let cli = Cli::try_parse_from(["membrane", "iac-smoke"]).unwrap();
        assert!(matches!(cli.command, Commands::IacSmoke { .. }));
    }

    #[test]
    fn evidence_export_supports_standard_formats() {
        for format in ["ocsf", "jsonl"] {
            let cli = Cli::try_parse_from([
                "membrane", "evidence", "export", "--format", format, "--out", "siem.out",
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Commands::Evidence {
                    command: EvidenceCommands::Export { .. }
                }
            ));
        }
    }

    #[test]
    fn iac_issue_accepts_tool_flags() {
        let cli = Cli::try_parse_from([
            "membrane",
            "iac",
            "issue",
            "--model",
            "sha256:demo-model",
            "--caller-pubkey",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "--tool",
            "github.comment",
            "--out",
            "session-iac.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Iac {
                command: IacCommands::Issue { tools, .. },
            } => assert_eq!(tools, vec!["github.comment".to_string()]),
            _ => panic!("expected iac issue"),
        }
    }

    #[test]
    fn tools_invoke_parses() {
        let cli = Cli::try_parse_from([
            "membrane",
            "tools",
            "invoke",
            "--iac",
            "session-iac.json",
            "--gate-pubkey",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "--tool",
            "github.comment",
            "--model",
            "demo",
            "--owner",
            "acme",
            "--repo",
            "pilot",
            "--issue-number",
            "1",
            "--body",
            "hi",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Tools {
                command: ToolsCommands::Invoke { .. }
            }
        ));
    }

    #[test]
    fn landing_demo_is_not_a_command() {
        assert!(Cli::try_parse_from(["membrane", "landing-demo"]).is_err());
    }
}
