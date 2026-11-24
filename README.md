# Owner Identity & Authentication (OIA) & Transport Security

## What It Is (In Plain English)

**OIA** (`source/src/oia/`) is Lila's dedicated **"prove you are actually the human owner"** security boundary. It checks your identity before sensitive actions are allowed to proceed.

OIA separates **proving who you are** from **approving or executing actions**:
- **OIA (`src/oia/`):** Verifies the owner's credential and emits challenge-bound cryptographic proof (`AuthenticationEvidence`). It has **no policy engine, grant store, or tool execution path**.
- **Harness / Daemon (`src/daemon/oia_harness.py` + `src/harness/`):** Binds exact file/process target metadata into an immutable digest, verifies OIA's proof against that challenge, consumes the single-use grant, and runs the action safely.
- **The LLM (`LilaCore`) never holds the owner secret and cannot approve its own tool calls.** *(Note: there is no monolithic `ApprovalManager` or `src/harness/oia.py`; approval orchestration lives across `src/oia/` and `src/harness/{permissions,pending_invocations,approval_grants,approval_authentication,approval_continuation}.py`.)*

---

## How Owner Authentication Works

### 1. Enrollment & Cryptography (`OwnerProfileStore`, `OIAConfig`, `OwnerCredentialFile`)
- Profile storage path: `${XDG_DATA_HOME:-~/.local/share}/<application_id>/owner/credential.json` (`LILA_APPLICATION_ID` defaults to `"lila"`, overridable via `LILA_OWNER_PROFILE_PATH`).
- Directory is enforced POSIX `0o700` (no symlinks); credential file is written with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW` at `0o600` (reads reject symlinks, size `> 16,384` bytes, or permissive file modes).
- Stores only an encrypted 32-byte random `owner_secret` (format `"lila-oia-credential-v1"`):
  - Key derivation: **Argon2id** (`Type.ID`, `t=3`, `65,536 KiB` / `64 MiB`, `p=2`, `16-byte` salt -> `32-byte` key).
  - AEAD encryption: **AES-256-GCM** (`12-byte` nonce, `48-byte` ciphertext+tag, AAD `b"lila-oia-owner-secret-v1\x00" + owner_id + b"\x00" + key_id`).
  - Plaintext passphrase `bytearray`, derived key, and unwrapped secret buffers are wiped in `finally` blocks. Missing `argon2-cffi` or `cryptography` fails closed (`CredentialUnavailable`).
- Phrase normalization: Unicode `NFKC` + `casefold` + whitespace collapsing (`<= 512` chars, no control chars, reserves `"approve"`, `"reject"`, `"challenge"`).
- Lockout & verification: **5 consecutive failed attempts** trigger a **60-second lockout** (`failure_limit = 5`, `lockout_seconds = 60.0`), reset on success. `authenticate()` / `authenticate_spoken()` require the Owner Phrase for each decision (presence sessions on `GET /owner/status` last `300s` but do not skip per-decision phrase checks).
- CLI enrollment (interactive WSL terminal required):
  ```bash
  /home/ticket/workspaces/lila/environment/.venv/bin/python -m src.oia.cli status
  /home/ticket/workspaces/lila/environment/.venv/bin/python -m src.oia.cli enroll
  ```

### 2. Six-Step Approval Continuation Flow
1. Model requests an approval-gated tool (`REQUIRE_APPROVAL`).
2. `TargetBindingResolverRegistry` snapshots exact target identity (device, inode, mode, size, nanosecond `mtime`/`ctime`, canonical path) into a SHA-256 operation digest inside `PendingInvocationRegistry` (`lifetime_seconds = 120.0`, default capacity `128`).
3. Client polls `GET /approvals/{id}` (`ApprovalRequestView`, free-text args redacted) to inspect `voice_challenge_code` and `remaining_seconds`.
4. Owner submits `POST /owner/approvals/{id}/decision` (`{"phrase": "...", "decision": "approve" | "reject"}`, `<= 4,096` bytes; raw JSON scrubbed in `finally`).
5. `src/daemon/oia_harness.py` initializes `ApprovalContinuationService` with an ephemeral random placeholder secret (so raw `POST /approvals/{id}/decision` calls cannot forge proofs), invokes OIA to unwrap the owner secret only in memory for Step 4 HMAC (`_PROOF_DOMAIN`), and wipes the transient key immediately.
6. Continuation (`ApprovalContinuationService`, serialized under `RLock`) revalidates policy + target binding, **burns the challenge first**, marks the invocation `CONSUMED`, checks tool handler identity, and dispatches once (`close()` cancels pending continuations on daemon shutdown).

### 3. Target Resolver Coverage (`30` Reviewed Resolvers) & Fail-Closed Design
`build_approval_service()` in `source/src/daemon/oia_harness.py` registers **30 reviewed target resolvers** (covering `28` of the `29` approval-gated tools plus `file_read` and `file_list`), each marking `"display": {"reviewed": True, ...}` and scrubbing free-text/secret fields:
- **`file_read` (`filesystem.file`):** Full canonical binding (`reviewed = True`). Linux `file_read` dispatch (`src/harness/file_targets.py`) uses `O_PATH | O_DIRECTORY | O_NOFOLLOW` traversal, `/proc/self/fd/{N}`, and `fstat` before/after `os.pread` (`VerifiedFileHandle`) so TOCTOU symlink swaps fail closed.
- **`file_list` (`filesystem.directory`):** Binds exact directory stat + resolved file list scope (`pattern`).
- **File Mutations (`file_write`, `file_append`, `file_patch`, `rollback_file_backup`, `file_delete` — `filesystem.file_mutation`):** Snapshot canonical path plus existing `device`/`inode`/`mode`/`size`/`mtime_ns` (or parent `device`/`inode` for new files), automatically invalidating any pending approval if the file changes on disk before owner approval.
- **`bash` (`process.command`):** Binds shell executable stat + SHA-256 command digest + redacted preview (`reviewed = True`).
- **Network, Hardware, Schedule, System & Workflow Resolvers (`reviewed = True`):** Includes `tcp_connect`, `udp_send`, `tcp_listen`, `ssh_exec`, `wifi_connect` (redacts password via `auth_configured`), `http_request`, `gpio_write`, `gpio_read`, `i2c_transfer`, `spi_transfer`, `serial_write`, `serial_read`, `schedule_add`, `notify_user`, `set_volume`, `clipboard_get`, `clipboard_set`, `request_owner_approval`, `screen_capture`, `computer_observe`, `computer_act` (redacts typed text + tokens), and `compose_workflow` (`harness.workflow` binding workflow SHA-256 + step tools).
- **`power_action` (Intentionally Unreviewed Sentinel):** Keeps **no target resolver**, so `power_action` always fails closed (`target.binding_policy_unavailable`) as verified by `tests/test_daemon_target_presentation.py` and `tests/test_harness_completion.py`.
- **`OiaComputerUseApprovalGate`:** Mints single-use per-process HMAC tokens bound to `(invocation_id, action_kind, capture_id)` strictly inside `_respond_with_evidence()` during verified `computer_act` and `screen_capture` dispatches, and burns them immediately afterward (`authorize()` denies missing, forged, expired, wrong-target, or replayed tokens).
- **Spoken Owner Approval:** Matches `<phrase> <approve|reject> <6-digit code>` with `hmac.compare_digest` over a private zero-persistence `vTalks` session, and remains disabled (`provider.live_owner_asr_unverified`) until calibrated via `POST /owner/spoken/start` -> `/stop`. OS biometrics, FIDO2, PIN, and speaker verification remain unimplemented stubs (`UnsupportedProvider`).

### 4. Visual Perception & Computer Control (`VisualPerceptionBroker`)
- Requires `initiator == "owner_gesture"` (explicitly blocks `"sentinel"`, `"model_request"`, and `"background_task"`), consumes single-use HMAC-SHA256 tokens (`GestureTokenIssuer`, min `1s` / default `15s` TTL), keeps PNG bytes strictly in memory (`30s` default TTL, pauses/discards on demand), and revalidates SHA-256 `image_digest` before `VISION_OBSERVE`, `OCR_UIA_EXTRACT`, or `COMPUTER_INTERACTION`.

---

## Windows <-> WSL Mutual TLS Transport Security

Every API request to `https://127.0.0.1:8765` enforces **both**:
1. **Mutual TLS 1.2+ (`src/daemon/transport.py`):** OpenSSL server enforces `TLSv1_2`, `OP_NO_COMPRESSION`, `CERT_REQUIRED`, zero 0-RTT early data, checks client cert against `LILA_TLS_CLIENT_CA` + comma-separated leaf SHA-256 allowlist (`LILA_TLS_ALLOWED_CLIENT_SHA256`), and rejects permissive key modes (`mode & 0o077 != 0`). Windows client pins `LILA_TLS_SERVER_CERT_SHA256` with `CryptographicOperations.FixedTimeEquals` and loads its non-exportable client certificate from `CurrentUser\My`.
2. **Bearer API Token:** Stored in `~/.config/lila/service.env` (`0600`) and Windows Credential Manager (`"Lila.Desktop/127.0.0.1:8765"`), compared via `hmac.compare_digest`.

---

## Proof & Verification

- **OIA, Resolver Coverage, Computer-Use Gate & Continuation Suites (`test_harness_completion.py`, `test_daemon_target_presentation.py`, `test_oia_public_api.py`, `test_oia_approval_integration.py`, `test_approval_continuation.py`, `test_m2_end_to_end_security.py`):**
  - All `30` reviewed OIA resolvers pass `ApprovalApi.require_reviewable()`, `wifi_connect` / `computer_act` / `screen_capture` redact sensitive fields, `power_action` stays fail-closed, file mutation approvals catch TOCTOU modifications cleanly, and `OiaComputerUseApprovalGate` dispatches strictly via verified OIA decisions.
- **Perception Fail-Closed & Digest Enforcement (`test_daemon_m6_m8_http.py`, `test_harness_computer_use_and_context.py`):**
  - Verified stale/discarded `capture_id` returns `403` / `PermissionError` and `computer_act` rejects missing/invalid tokens.
- **Full Security Regression Files in `source/tests/`:** `test_oia_credentials.py`, `test_m2_end_to_end_security.py`, `test_approval_authentication.py`, `test_approval_continuation.py`, `test_approval_grants.py`, `test_pending_invocations.py`, `test_file_targets.py`, `test_mtls_provisioning.py`, `test_daemon_transport.py`, `test_harness_completion.py`.
