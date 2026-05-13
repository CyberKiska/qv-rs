#!/usr/bin/env node

/**
 * Successor fixture generation placeholder.
 *
 * The pre-successor generator used removed oracle modules:
 *   - src/core/crypto/qcont/build.js
 *   - src/core/crypto/qcont/attach.js
 *   - src/core/crypto/manifest/archive-manifest.js
 *   - src/core/crypto/manifest/manifest-bundle.js
 *
 * Those paths produced manifest-v2 / QVqcont-6 fixtures and must not be used
 * during the successor migration. The replacement generator should write only
 * under fixtures/successor/ and should use the current JS oracle modules:
 *   - src/core/crypto/qcont/lifecycle-shard.js
 *       buildLifecycleQcontShards, reshareSameState
 *   - src/core/crypto/qcont/lifecycle-attach.js
 *       attachLifecycleBundleToShards
 *   - src/core/crypto/lifecycle/artifacts.js
 *       canonicalizeArchiveStateDescriptor, canonicalizeCohortBinding,
 *       canonicalizeLifecycleBundle, canonicalizeTransitionRecord,
 *       canonicalizeSourceEvidence
 *
 * Stage 0 intentionally does not implement lifecycle artifact generation.
 */

console.error(
  [
    'tools/gen-js-fixtures.mjs is disabled for the successor migration.',
    'The old predecessor fixture generator targeted removed JS modules and QVqcont-6.',
    'Implement the successor generator against lifecycle-shard.js, lifecycle-attach.js, and lifecycle/artifacts.js before writing fixtures/successor/.',
  ].join('\n')
);
process.exit(1);
