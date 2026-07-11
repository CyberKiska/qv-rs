use std::env;

use qvault_core::error::{QvCode, QvError};
use serde_json::Value;

#[derive(Debug)]
struct ReportedExit(i32);

impl std::fmt::Display for ReportedExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "command already reported unsuccessful status {}", self.0)
    }
}

impl std::error::Error for ReportedExit {}

pub(crate) fn reported_exit(status: i32) -> anyhow::Error {
    ReportedExit(status).into()
}

fn reported_exit_status(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ReportedExit>().map(|exit| exit.0))
}

/// Maps `QvCode` to process exit status per
/// `quantum-vault/src/core/cli/lib/exit.js` (`QV_CODE_TO_EXIT`).
pub(crate) fn map_qv_code_to_exit(code: QvCode) -> i32 {
    match code {
        QvCode::PolicyNotSatisfied | QvCode::VerificationFailed | QvCode::RestoreFailed => 1,
        QvCode::EntropyFailed => 3,
        QvCode::InvalidFormat | QvCode::UnsupportedFormat => 4,
        QvCode::KeyRejected => 5,
        QvCode::AeadFailed => 6,
        QvCode::NotEnoughShards | QvCode::IntegrityMismatch => 7,
        QvCode::SignatureImportFailed => 8,
        QvCode::InvalidSelection | QvCode::AmbiguousInputs => 9,
        QvCode::ReshareContractViolation => 10,
        QvCode::RestoredIntegrityFailed => 11,
        QvCode::RestoreLifecycleVariantAckRequired => 12,
    }
}

pub(crate) fn exit_code(error: &anyhow::Error) -> i32 {
    if let Some(status) = reported_exit_status(error) {
        return status;
    }
    for cause in error.chain() {
        if let Some(qv_error) = cause.downcast_ref::<QvError>() {
            if let Some(code) = qv_error.qv_code() {
                return map_qv_code_to_exit(code);
            }
        }
    }
    if qv_code_string(error) == "USAGE" {
        2
    } else {
        1
    }
}

pub(crate) fn emit_error(error: &anyhow::Error) {
    if reported_exit_status(error).is_some() {
        return;
    }
    if json_requested() {
        let report = serde_json::json!({
            "command": command_name_from_args(),
            "ok": false,
            "cliSchemaVersion": 1,
            "qvCode": qv_code_string(error),
            "error": format!("{error:#}")
        });
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(_) => println!(
                r#"{{"command":null,"ok":false,"cliSchemaVersion":1,"qvCode":"UNEXPECTED","error":"failed to serialize error"}}"#
            ),
        }
    } else {
        eprintln!("Error: {error:#}");
    }
}

pub(crate) fn qv_code_string(error: &anyhow::Error) -> String {
    for cause in error.chain() {
        if let Some(qv_error) = cause.downcast_ref::<QvError>() {
            if let Some(code) = qv_error.qv_code() {
                return code.as_str().to_string();
            }
        }
    }
    let text = format!("{error:#}");
    if text.contains("Refusing")
        || text.contains("requires")
        || text.contains("must")
        || text.contains("not wired")
    {
        "USAGE".to_string()
    } else {
        "UNEXPECTED".to_string()
    }
}

pub(crate) fn json_requested() -> bool {
    env::args_os().any(|arg| arg == "--json")
}

pub(crate) fn command_name_from_args() -> Value {
    let commands = [
        "keygen",
        "encrypt",
        "decrypt",
        "split",
        "attach",
        "reshare",
        "signer-keygen",
        "sign",
        "sig-verify",
        "inspect",
        "canonicalize",
        "verify",
        "restore",
        "selftest",
        "version",
    ];
    env::args_os()
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .find(|arg| commands.contains(&arg.as_str()))
        .map(Value::String)
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qvault_core::error::coded;

    #[test]
    fn qv_code_exit_golden_bytes_match_exit_js() {
        let mut entries = vec![serde_json::json!({"qvCode":"USAGE","exitCode":2})];
        for code in [
            QvCode::VerificationFailed,
            QvCode::EntropyFailed,
            QvCode::InvalidFormat,
            QvCode::KeyRejected,
            QvCode::AeadFailed,
            QvCode::NotEnoughShards,
            QvCode::SignatureImportFailed,
            QvCode::AmbiguousInputs,
            QvCode::ReshareContractViolation,
            QvCode::RestoredIntegrityFailed,
            QvCode::PolicyNotSatisfied,
            QvCode::RestoreLifecycleVariantAckRequired,
        ] {
            let error: anyhow::Error = coded(code, "fixture").into();
            entries.push(serde_json::json!({
                "qvCode": qv_code_string(&error),
                "exitCode": exit_code(&error)
            }));
        }

        let bytes = serde_json::to_string(&entries).expect("golden JSON");
        assert_eq!(
            bytes,
            r#"[{"exitCode":2,"qvCode":"USAGE"},{"exitCode":1,"qvCode":"UNEXPECTED"},{"exitCode":3,"qvCode":"ENTROPY_FAILED"},{"exitCode":4,"qvCode":"FORMAT_POLICY_REJECT"},{"exitCode":5,"qvCode":"KEY_REJECTED"},{"exitCode":6,"qvCode":"AEAD_FAILED"},{"exitCode":7,"qvCode":"QUORUM_UNREACHABLE"},{"exitCode":8,"qvCode":"SIGNATURE_IMPORT_FAILED"},{"exitCode":9,"qvCode":"AMBIGUOUS_INPUTS"},{"exitCode":10,"qvCode":"RESHARE_CONTRACT_VIOLATION"},{"exitCode":11,"qvCode":"RESTORED_INTEGRITY_FAILED"},{"exitCode":1,"qvCode":"POLICY_NOT_SATISFIED"},{"exitCode":12,"qvCode":"RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED"}]"#
        );
    }

    #[test]
    fn already_reported_exit_preserves_status_without_error_envelope() {
        let error = reported_exit(7);
        assert_eq!(reported_exit_status(&error), Some(7));
        assert_eq!(exit_code(&error), 7);
    }
}
