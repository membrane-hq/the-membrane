pub mod bus;
pub mod canonical;
pub mod event;
pub mod iac;
pub mod merkle;
pub mod nostr_bus;
#[cfg(feature = "ots")]
pub mod ots;
pub mod rollup;
pub mod session;
pub mod siem;
pub mod siem_webhook;

pub use bus::bus_root_from_events;
pub use bus::{BusSubscriber, BusSubscriberConfig};
pub use event::{EventType, MembraneEvent, MembranePayload, RouterSessionPayload, SCHEMA_VERSION};
#[cfg(feature = "ots")]
pub use iac::RollupBundle;
pub use iac::{IacVerifyError, IntentAuthorizationCredential};
pub use merkle::{Domain, MerkleTree};
pub use nostr_bus::{
    fetch_membrane_bus_events, fetch_membrane_events, fetch_session_chain_bootstrap,
    keys_from_nsec, last_bus_event_id, membrane_kind_for, npub_from_keys,
    subscribe_and_compute_bus_root, BusPublisher, BusPublisherConfig, MembraneBusEvent,
};
#[cfg(feature = "ots")]
pub use ots::{HttpOtsStamper, MockOtsStamper, OtsError, OtsStampResult, OtsStamper};
#[cfg(feature = "ots")]
pub use rollup::{
    build_rollup_bundle, cp_chain_root_from_events, day_bounds_utc, filter_events_in_period,
    validate_rollup_bundle, SignedRollupBundle,
};
pub use rollup::{cp_hash_hex, is_cp_event, last_cp_hash_from_events, GENESIS_CP_HASH};
pub use session::{
    alert_degraded_fields, alert_degraded_payload, SessionChainState,
    ALERT_REASON_DELTA_T_EXCEEDED, ALERT_REASON_SUBJECT_SEVER,
};
pub use siem::{
    build_ocsf_inspired_pack, render_jsonl, OcsfInspiredPack, SiemEvent, OCSF_INSPIRED_SCHEMA,
    SIEM_SCHEMA_VERSION,
};
pub use siem_webhook::{
    map_and_spawn_siem_ship, spawn_siem_ship, ReqwestWebhookPoster, SiemWebhookConfig,
    SiemWebhookError, SiemWebhookFormat, SiemWebhookShipper, WebhookPoster, DEFAULT_SECRET_HEADER,
    ENV_WEBHOOK_URL,
};

pub mod caller;
