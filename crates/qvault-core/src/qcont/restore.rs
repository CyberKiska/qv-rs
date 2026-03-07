use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bytes::bytes_equal;
use crate::erasure;
use crate::error::{err, Result};
use crate::hash::sha3_512_hex;
use crate::manifest::{parse_archive_manifest_bytes, ArchiveManifest, ParsedArchiveManifest};
use crate::policy::validate_container_policy_metadata;
use crate::qcont::shard::QcontShard;
use crate::qenc::build_qenc_header;
use crate::sss::combine_shares;
use zeroize::Zeroize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreQcontOptions {
    pub manifest_bytes: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RestoredQcont {
    pub qenc_bytes: Vec<u8>,
    pub priv_key: Vec<u8>,
    pub container_id: String,
    pub container_hash: String,
    pub private_key_hash: Option<String>,
    pub recovered_qenc_hash: String,
    pub recovered_priv_hash: String,
    pub rejected_shard_indices: Vec<u16>,
    pub qenc_ok: bool,
    pub qkey_ok: bool,
    pub manifest: ArchiveManifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest_hex: String,
    pub manifest_source: String,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for RestoredQcont {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredQcont")
            .field("qenc_bytes_len", &self.qenc_bytes.len())
            .field("priv_key_len", &self.priv_key.len())
            .field("container_id", &self.container_id)
            .field("container_hash", &self.container_hash)
            .field("private_key_hash", &self.private_key_hash)
            .field("recovered_qenc_hash", &self.recovered_qenc_hash)
            .field("recovered_priv_hash", &self.recovered_priv_hash)
            .field("rejected_shard_indices", &self.rejected_shard_indices)
            .field("qenc_ok", &self.qenc_ok)
            .field("qkey_ok", &self.qkey_ok)
            .field("manifest_digest_hex", &self.manifest_digest_hex)
            .field("manifest_source", &self.manifest_source)
            .field("warnings", &self.warnings)
            .finish()
    }
}

pub fn restore_from_shards(
    shards: &[QcontShard],
    options: &RestoreQcontOptions,
) -> Result<RestoredQcont> {
    if shards.is_empty() {
        return Err(err("No shards provided"));
    }

    let manifest_context = resolve_manifest_context(shards, options.manifest_bytes.as_deref())?;
    let manifest = &manifest_context.parsed.manifest;
    let manifest_digest_hex = manifest_context.parsed.digest_hex.clone();

    let group = shards
        .iter()
        .filter(|shard| shard.manifest_digest_hex == manifest_digest_hex)
        .cloned()
        .collect::<Vec<_>>();
    let rejected_shard_indices = shards
        .iter()
        .filter(|shard| shard.manifest_digest_hex != manifest_digest_hex)
        .map(|shard| shard.shard_index)
        .collect::<Vec<_>>();
    if group.is_empty() {
        return Err(err("No shard matches selected manifest digest"));
    }

    let n = ensure_positive_integer(
        manifest.sharding.reed_solomon.n as usize,
        "manifest.sharding.reedSolomon.n",
        2,
    )?;
    let k = ensure_positive_integer(
        manifest.sharding.reed_solomon.k as usize,
        "manifest.sharding.reedSolomon.k",
        2,
    )?;
    let m = ensure_positive_integer(
        manifest.sharding.reed_solomon.parity as usize,
        "manifest.sharding.reedSolomon.parity",
        0,
    )?;
    let t = ensure_positive_integer(
        manifest.sharding.shamir.threshold as usize,
        "manifest.sharding.shamir.threshold",
        2,
    )?;
    let share_count = ensure_positive_integer(
        manifest.sharding.shamir.share_count as usize,
        "manifest.sharding.shamir.shareCount",
        2,
    )?;
    if share_count != n {
        return Err(err(format!(
            "Invalid manifest sharding: Shamir shareCount {share_count} must equal RS n {n}"
        )));
    }
    if (m % 2) != 0 {
        return Err(err("Invalid manifest sharding: RS parity must be even"));
    }
    if k >= n {
        return Err(err("Invalid manifest sharding: expected k < n"));
    }
    let allowed_failures = m / 2;
    let expected_threshold = k + allowed_failures;
    if t != expected_threshold {
        return Err(err(format!(
            "Invalid manifest threshold: expected {expected_threshold}, got {t}"
        )));
    }

    let chunk_size = ensure_positive_integer(
        manifest.qenc.chunk_size as usize,
        "manifest.qenc.chunkSize",
        1,
    )? as u64;
    let chunk_count = ensure_positive_integer(
        manifest.qenc.chunk_count as usize,
        "manifest.qenc.chunkCount",
        1,
    )? as u64;
    let payload_length = ensure_positive_integer(
        manifest.qenc.payload_length as usize,
        "manifest.qenc.payloadLength",
        1,
    )? as u64;
    let container_id = manifest.qenc.container_id.clone();
    if container_id.is_empty() {
        return Err(err("Manifest is missing qenc.containerId"));
    }

    let base = &group[0];
    let base_key_commit = base.key_commit;
    let mut shard_by_index = BTreeMap::new();
    for shard in &group {
        if usize::from(shard.shard_index) >= n {
            return Err(err(format!("Invalid shardIndex {}", shard.shard_index)));
        }
        if shard_by_index.insert(shard.shard_index, shard).is_some() {
            return Err(err(format!(
                "Duplicate shardIndex {} detected",
                shard.shard_index
            )));
        }
        ensure_equal(&shard.meta_json.container_id, &container_id, "containerId")?;
        ensure_equal(&(shard.meta_json.n as usize), &n, "n")?;
        ensure_equal(&(shard.meta_json.k as usize), &k, "k")?;
        ensure_equal(&(shard.meta_json.m as usize), &m, "m")?;
        ensure_equal(&(shard.meta_json.t as usize), &t, "t")?;
        if !shard.meta_json.manifest_digest.is_empty() {
            ensure_equal(
                &normalize_hex_string(&shard.meta_json.manifest_digest),
                &manifest_digest_hex,
                "manifestDigest",
            )?;
        }
        if !bytes_equal(&shard.encapsulated_key, &base.encapsulated_key) {
            return Err(err(format!(
                "Shard header mismatch: encapsulatedKey differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.iv, &base.iv) {
            return Err(err(format!(
                "Shard header mismatch: iv differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.salt, &base.salt) {
            return Err(err(format!(
                "Shard header mismatch: salt differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.qenc_meta_bytes, &base.qenc_meta_bytes) {
            return Err(err(format!(
                "Shard header mismatch: qenc metadata differs for shard {}",
                shard.shard_index
            )));
        }
        if !bytes_equal(&shard.key_commit, &base_key_commit) {
            return Err(err(format!(
                "Shard header mismatch: key commitment differs for shard {}",
                shard.shard_index
            )));
        }
    }

    let missing_indices = (0..n)
        .filter(|index| !shard_by_index.contains_key(&(*index as u16)))
        .map(|index| index as u16)
        .collect::<HashSet<_>>();

    let qenc_meta_json = &base.qenc_meta_json;
    validate_container_policy_metadata(qenc_meta_json, false)?;
    assert_manifest_matches_qenc_metadata(&manifest_context.parsed, qenc_meta_json)?;

    let ciphertext_length = ensure_positive_integer(
        base.meta_json.ciphertext_length as usize,
        "ciphertextLength",
        1,
    )? as u64;
    for shard in &group {
        ensure_equal(
            &(shard.meta_json.ciphertext_length as u64),
            &ciphertext_length,
            "ciphertextLength",
        )?;
        ensure_equal(
            &(shard.meta_json.chunk_count as u64),
            &chunk_count,
            "chunkCount",
        )?;
        ensure_equal(
            &(shard.meta_json.chunk_size as u64),
            &chunk_size,
            "chunkSize",
        )?;
    }

    let is_per_chunk_mode = match qenc_meta_json.aead_mode.as_str() {
        "per-chunk-aead" => true,
        "single-container-aead" => false,
        other => return Err(err(format!("Unsupported AEAD mode: {other}"))),
    };
    let expected_ciphertext_length = if is_per_chunk_mode {
        payload_length + (16 * chunk_count)
    } else {
        ciphertext_length
    };
    if is_per_chunk_mode && ciphertext_length != expected_ciphertext_length {
        return Err(err(format!(
            "Ciphertext length mismatch for per-chunk mode (expected {expected_ciphertext_length}, got {ciphertext_length})"
        )));
    }

    let encap_hash = sha3_512_hex(&base.encapsulated_key);
    if !base.meta_json.encap_blob_hash.is_empty()
        && normalize_hex_string(&base.meta_json.encap_blob_hash)
            != normalize_hex_string(&encap_hash)
    {
        return Err(err("encapBlobHash mismatch"));
    }
    if group.len() < t {
        return Err(err(format!(
            "Need at least {t} matching shards for selected manifest, got {}",
            group.len()
        )));
    }

    let share_commitments = manifest_context
        .parsed
        .manifest
        .shard_binding
        .as_ref()
        .and_then(|binding| binding.share_commitments.clone())
        .or_else(|| base.meta_json.share_commitments.clone());
    let fragment_body_hashes = manifest_context
        .parsed
        .manifest
        .shard_binding
        .as_ref()
        .and_then(|binding| binding.shard_body_hashes.clone())
        .or_else(|| base.meta_json.fragment_body_hashes.clone());

    let mut warnings = manifest_context.warnings;
    let mut valid_share_shards = group.clone();
    if let Some(share_commitments) = share_commitments {
        if share_commitments.len() != n {
            return Err(err("Invalid shareCommitments length"));
        }
        valid_share_shards = Vec::new();
        let mut invalid_share_indices = Vec::new();
        for shard in &group {
            let expected = normalize_hex_string(&share_commitments[usize::from(shard.shard_index)]);
            let actual = normalize_hex_string(&sha3_512_hex(&shard.share));
            if actual != expected {
                invalid_share_indices.push(shard.shard_index);
                continue;
            }
            valid_share_shards.push(shard.clone());
        }
        if valid_share_shards.len() < t {
            return Err(err(format!(
                "Not enough valid shards for Shamir reconstruction: need {t}, have {}",
                valid_share_shards.len()
            )));
        }
        if !invalid_share_indices.is_empty() {
            warnings.push(format!(
                "Share commitment failures: {} shard(s) rejected.",
                invalid_share_indices.len()
            ));
        }
    }

    let mut corrupted_shard_indices = HashSet::new();
    if let Some(fragment_body_hashes) = fragment_body_hashes {
        if fragment_body_hashes.len() != n {
            return Err(err("Invalid shardBodyHashes length"));
        }
        for shard in &group {
            let expected =
                normalize_hex_string(&fragment_body_hashes[usize::from(shard.shard_index)]);
            let actual = normalize_hex_string(&sha3_512_hex(&shard.fragments));
            if actual != expected {
                corrupted_shard_indices.insert(shard.shard_index);
            }
        }
    }

    let total_bad = missing_indices.len() + corrupted_shard_indices.len();
    if total_bad > allowed_failures {
        return Err(err(format!(
            "Too many missing/corrupted shards for RS reconstruction: allowed {allowed_failures}, got {total_bad}"
        )));
    }

    let mut sorted_shares = valid_share_shards;
    sorted_shares.sort_by_key(|shard| shard.shard_index);
    let mut selected_shares = sorted_shares
        .iter()
        .take(t)
        .map(|shard| shard.share.clone())
        .collect::<Vec<_>>();
    let priv_key = combine_shares(&selected_shares)?;
    for share in &mut selected_shares {
        share.zeroize();
    }

    let rs_encode_base = if base.meta_json.rs_encode_base > 0 {
        base.meta_json.rs_encode_base as usize
    } else {
        255
    };
    let mut cipher_chunks = Vec::new();
    let mut shard_offsets = vec![0usize; n];

    for i in 0..chunk_count {
        let plain_len = chunk_size.min(payload_length - (i * chunk_size)) as usize;
        let this_len = if is_per_chunk_mode {
            plain_len + 16
        } else {
            ciphertext_length as usize
        };

        let encode_size = (rs_encode_base / n) * n;
        if encode_size == 0 {
            return Err(err("RS parameters too large"));
        }
        let input_size = (encode_size * k) / n;
        let symbol_size = input_size / k;
        let blocks = this_len.div_ceil(input_size);
        let expected_frag_len = blocks * symbol_size;

        let mut encoded = Vec::with_capacity(n);
        for j in 0..n {
            let shard = shard_by_index.get(&(j as u16));
            if shard.is_none() || corrupted_shard_indices.contains(&(j as u16)) {
                encoded.push(vec![0u8; expected_frag_len]);
                continue;
            }
            let shard = *shard.unwrap();
            let stream_offset = shard_offsets[j];
            if stream_offset + 4 > shard.fragments.len() {
                return Err(err("Fragment stream underflow"));
            }
            let frag_len = u32::from_be_bytes([
                shard.fragments[stream_offset],
                shard.fragments[stream_offset + 1],
                shard.fragments[stream_offset + 2],
                shard.fragments[stream_offset + 3],
            ]) as usize;
            let frag_start = stream_offset + 4;
            let frag_end = frag_start + frag_len;
            if frag_end > shard.fragments.len() {
                return Err(err("Fragment length overflow"));
            }
            let mut fragment = shard.fragments[frag_start..frag_end].to_vec();
            if fragment.len() < expected_frag_len {
                fragment.resize(expected_frag_len, 0);
            } else if fragment.len() > expected_frag_len {
                fragment.truncate(expected_frag_len);
            }
            encoded.push(fragment);
            shard_offsets[j] = frag_end;
        }

        let recombined = erasure::recombine(&encoded, this_len, k, m / 2, rs_encode_base)
            .map_err(|error| err(format!("RS recombination failed on chunk {i}: {error}")))?;
        cipher_chunks.push(recombined);
        if !is_per_chunk_mode {
            break;
        }
    }

    for j in 0..n {
        if corrupted_shard_indices.contains(&(j as u16)) {
            continue;
        }
        let Some(shard) = shard_by_index.get(&(j as u16)) else {
            continue;
        };
        if shard_offsets[j] != shard.fragments.len() {
            return Err(err(format!(
                "Fragment stream has trailing or missing data in shard {j}"
            )));
        }
    }

    let ciphertext = if is_per_chunk_mode {
        let total = cipher_chunks.iter().map(Vec::len).sum::<usize>();
        let mut out = Vec::with_capacity(total);
        for chunk in &cipher_chunks {
            out.extend_from_slice(chunk);
        }
        out
    } else {
        cipher_chunks[0].clone()
    };
    if ciphertext.len() != ciphertext_length as usize {
        return Err(err("Reconstructed ciphertext length mismatch"));
    }

    let header = build_qenc_header(
        &base.encapsulated_key,
        &base.iv,
        &base.salt,
        &base.qenc_meta_bytes,
        &base.key_commit,
    )?;
    let mut qenc_bytes = Vec::with_capacity(header.len() + ciphertext.len());
    qenc_bytes.extend_from_slice(&header);
    qenc_bytes.extend_from_slice(&ciphertext);

    let recovered_qenc_hash = normalize_hex_string(&sha3_512_hex(&qenc_bytes));
    let expected_qenc_hash = normalize_hex_string(&manifest.qenc.qenc_hash);
    if recovered_qenc_hash != expected_qenc_hash {
        return Err(err(
            "Reconstructed .qenc hash does not match signed manifest",
        ));
    }

    let recovered_priv_hash = normalize_hex_string(&sha3_512_hex(&priv_key));
    let private_key_hash = normalize_hex_string(&base.meta_json.private_key_hash);
    let qkey_ok = private_key_hash.is_empty() || private_key_hash == recovered_priv_hash;
    if !qkey_ok {
        warnings.push("Recovered secret key hash does not match shard metadata.".to_string());
    }

    Ok(RestoredQcont {
        qenc_bytes,
        priv_key,
        container_id,
        container_hash: expected_qenc_hash,
        private_key_hash: if private_key_hash.is_empty() {
            None
        } else {
            Some(private_key_hash)
        },
        recovered_qenc_hash,
        recovered_priv_hash,
        rejected_shard_indices,
        qenc_ok: true,
        qkey_ok,
        manifest: manifest.clone(),
        manifest_bytes: manifest_context.parsed.bytes,
        manifest_digest_hex,
        manifest_source: manifest_context.source.to_string(),
        warnings,
    })
}

#[derive(Debug, Clone)]
struct ManifestContext {
    parsed: ParsedArchiveManifest,
    source: &'static str,
    warnings: Vec<String>,
}

fn resolve_manifest_context(
    shards: &[QcontShard],
    uploaded_manifest_bytes: Option<&[u8]>,
) -> Result<ManifestContext> {
    let mut by_digest = HashMap::<String, Vec<&QcontShard>>::new();
    for shard in shards {
        by_digest
            .entry(shard.manifest_digest_hex.clone())
            .or_default()
            .push(shard);
    }
    let mut candidates = Vec::new();
    for (digest_hex, cohort) in by_digest {
        let manifest_bytes = &cohort[0].manifest_bytes;
        if cohort
            .iter()
            .any(|shard| !bytes_equal(&shard.manifest_bytes, manifest_bytes))
        {
            return Err(err(format!(
                "Manifest bytes mismatch inside digest cohort {digest_hex}"
            )));
        }
        let parsed = parse_archive_manifest_bytes(manifest_bytes)?;
        if parsed.digest_hex != digest_hex {
            return Err(err("Embedded manifest digest mismatch"));
        }
        candidates.push(parsed);
    }
    if candidates.is_empty() {
        return Err(err("No embedded manifests found in shard set"));
    }

    if let Some(uploaded_manifest_bytes) = uploaded_manifest_bytes {
        let parsed = parse_archive_manifest_bytes(uploaded_manifest_bytes)?;
        if !candidates
            .iter()
            .any(|item| item.digest_hex == parsed.digest_hex)
        {
            return Err(err(
                "Uploaded manifest does not match any provided shard cohort",
            ));
        }
        return Ok(ManifestContext {
            parsed,
            source: "uploaded",
            warnings: vec!["The content is correct, but may not be authentic.".to_string()],
        });
    }

    if candidates.len() != 1 {
        return Err(err(
            "Multiple manifest cohorts detected. Provide manifest file to select a cohort.",
        ));
    }

    Ok(ManifestContext {
        parsed: candidates.remove(0),
        source: "embedded",
        warnings: vec!["The content is correct, but may not be authentic.".to_string()],
    })
}

fn assert_manifest_matches_qenc_metadata(
    parsed_manifest: &ParsedArchiveManifest,
    qenc_meta_json: &crate::qenc::QencMetadata,
) -> Result<()> {
    let manifest = &parsed_manifest.manifest;
    ensure_equal(
        &manifest.qenc.hash_alg,
        &"SHA3-512".to_string(),
        "qenc.hashAlg",
    )?;
    ensure_equal(
        &manifest.qenc.primary_anchor,
        &"qencHash".to_string(),
        "qenc.primaryAnchor",
    )?;
    ensure_equal(
        &manifest.qenc.container_id_role,
        &"secondary-header-id".to_string(),
        "qenc.containerIdRole",
    )?;
    ensure_equal(
        &manifest.qenc.container_id_alg,
        &"SHA3-512(qenc-header-bytes)".to_string(),
        "qenc.containerIdAlg",
    )?;

    ensure_equal(&qenc_meta_json.fmt, &manifest.qenc.format, "qenc.format")?;
    ensure_equal(
        &qenc_meta_json.aead_mode,
        &manifest.qenc.aead_mode,
        "qenc.aeadMode",
    )?;
    ensure_equal(
        &qenc_meta_json.iv_strategy,
        &manifest.qenc.iv_strategy,
        "qenc.ivStrategy",
    )?;
    ensure_equal(
        &(qenc_meta_json.chunk_size.unwrap_or_default()),
        &manifest.qenc.chunk_size,
        "qenc.chunkSize",
    )?;
    ensure_equal(
        &(qenc_meta_json.chunk_count.unwrap_or_default()),
        &manifest.qenc.chunk_count,
        "qenc.chunkCount",
    )?;
    ensure_equal(
        &(qenc_meta_json.payload_length.unwrap_or_default()),
        &manifest.qenc.payload_length,
        "qenc.payloadLength",
    )?;
    ensure_equal(
        qenc_meta_json
            .crypto_profile_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.crypto_profile_id,
        "cryptoProfileId",
    )?;
    ensure_equal(
        qenc_meta_json
            .kdf_tree_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.kdf_tree_id,
        "kdfTreeId",
    )?;
    ensure_equal(
        &qenc_meta_json.nonce_policy_id,
        &manifest.nonce_policy_id,
        "noncePolicyId",
    )?;
    ensure_equal(
        &qenc_meta_json.nonce_mode,
        &manifest.nonce_mode,
        "nonceMode",
    )?;
    ensure_equal(
        &qenc_meta_json.counter_bits,
        &manifest.counter_bits,
        "counterBits",
    )?;
    ensure_equal(
        &qenc_meta_json.max_chunk_count,
        &manifest.max_chunk_count,
        "maxChunkCount",
    )?;
    ensure_equal(
        qenc_meta_json
            .aad_policy_id
            .as_ref()
            .unwrap_or(&String::new()),
        &manifest.aad_policy_id,
        "aadPolicyId",
    )?;
    Ok(())
}

fn normalize_hex_string(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn ensure_positive_integer(value: usize, field: &str, min: usize) -> Result<usize> {
    if value < min {
        return Err(err(format!("Invalid {field}")));
    }
    Ok(value)
}

fn ensure_equal<T: PartialEq + std::fmt::Display>(
    actual: &T,
    expected: &T,
    field: &str,
) -> Result<()> {
    if actual != expected {
        return Err(err(format!(
            "{field} mismatch (expected {expected}, got {actual})"
        )));
    }
    Ok(())
}
