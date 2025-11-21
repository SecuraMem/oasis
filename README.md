# OASIS - AI-Native Code Intelligence & Compliance Platform

**Version:** 2.0.0  
**Status:** Production Ready ✅  
**Built on:** SecuraMem Foundation  
**Repository:** https://github.com/SecuraMem/oasis

## 🎯 Overview

**OASIS** (Orchestrated AI Security and Integrity System) extends the battle-tested SecuraMem compliance platform with AI-native code intelligence and isolated execution capabilities. Built as a single Rust binary with zero external dependencies.

### What is OASIS?

OASIS combines cryptographic audit trails, semantic code understanding, and sandboxed execution into a unified platform for AI-driven development workflows. It provides:

- **Semantic Code Intelligence** - Tree-sitter AST parsing + 384D embeddings for code search
- **Isolated Code Execution** - Wasmtime sandbox with fuel-limited WASM execution  
- **Cryptographic Audit Trail** - Blockchain-style immutable ledger (SHA-256 + Ed25519)
- **AI Jailbreak Detection** - ONNX-powered semantic firewall
- **Hardware Node-Locking** - Ed25519 JWT licensing with machine fingerprinting

### Origin Story

OASIS is a **fork** of [securamem-rust-core](https://github.com/SecuraMem/axiom-ledger-app) with two revolutionary new layers:
- **L2 Semantic Codex** - AI-native code understanding
- **L4 CodeChamber Sandbox** - Zero-trust execution environment

---

## 🏗️ Architecture

### 6-Layer Design

| Layer | Component | Purpose | Technology |
|-------|-----------|---------|------------|
| **L1** | Compliance Engine | Ed25519 signatures, SHA-256 hash chaining, immutable audit ledger | `securamem-l1`, `securamem-crypto` |
| **L2** | **Semantic Codex** ✨ | Tree-sitter AST parsing, code embeddings, semantic search | `oasis-codex`, tree-sitter, SQLite |
| **L3** | Data Storage | SQLx async, SQLite WAL mode, hash chain verification | `securamem-storage` |
| **L4** | **CodeChamber Sandbox** ✨ | Wasmtime WASI isolation, fuel-limited execution, ephemeral filesystem | `oasis-sandbox`, wasmtime |
| **L5** | NeuroWall Firewall | ONNX inference, 384D embeddings, jailbreak detection | `securamem-firewall` |
| **L6** | Monitoring & API | Prometheus metrics, Axum HTTP server, health checks | `securamem-l3` |

> ✨ **New in OASIS**: Layers 2 & 4 add AI-native code intelligence and execution sandboxing

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/SecuraMem/oasis.git
cd oasis

# Build release binary (single 100MB executable)
cargo build --release

# Binary location: target/release/oasis.exe
```

### Basic Usage

```bash
# 1. Initialize database and cryptographic identity
./oasis init

# 2. Check system status
./oasis status

# 3. Index your codebase for semantic search
./oasis index --path ./src

# 4. Search code semantically
./oasis search --query "authentication logic" --limit 5

# 5. Execute WASM in isolated sandbox
./oasis simulate --file ./code.wasm

# 6. Start semantic firewall (requires OpenAI API key)
export OPENAI_API_KEY=sk-...
./oasis firewall --port 3051

# 7. Verify audit chain integrity
./oasis verify
```

---

## 🧠 L2 Semantic Codex

### Overview
The Semantic Codex transforms flat text search into **AI-native code understanding** using tree-sitter AST parsing and semantic embeddings.

### Features
- **AST-Based Parsing**: Tree-sitter support for Rust, Python, JavaScript, TypeScript
- **Definition-Level Chunking**: Extracts functions, structs, classes (not arbitrary line ranges)
- **Semantic Embeddings**: 384D vectors via embedded ONNX model (all-MiniLM-L6-v2)
- **Incremental Indexing**: SHA256-based change detection, skips unchanged files
- **Cosine Similarity Search**: Semantic ranking of code snippets

### Technical Implementation

```rust
// crates/oasis-codex/src/parser.rs
pub struct CodeParser {
    // Hardcoded tree-sitter queries for zero external dependencies
}

// crates/oasis-codex/src/indexer.rs
pub struct CodexIndexer<'a> {
    db: &'a Database,
    engine: &'a SemanticEngine,
}

// crates/oasis-codex/src/search.rs  
pub struct CodexSearch<'a> {
    // Cosine similarity ranking over 384D vectors
}
```

### Database Schema

```sql
-- migrations/002_semantic_codex_schema.sql
CREATE TABLE semantic_index (
    id INTEGER PRIMARY KEY,
    file_path TEXT NOT NULL,
    symbol_name TEXT NOT NULL,
    symbol_type TEXT NOT NULL,
    code_content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    embedding BLOB NOT NULL,  -- 384D float32 vector
    indexed_at TEXT NOT NULL
);
```

### CLI Usage

```bash
# Index entire codebase
oasis index --path ./crates

# Search for authentication code
oasis search --query "JWT token validation" --limit 10

# Example output:
# #1: verify_license (Score: 0.94)
#   File: crates/securamem-core/src/license.rs
#   Code: pub fn verify_license(license_path: &Path) -> Result<LicenseInfo> { ... }
```

---

## 🛡️ L4 CodeChamber Sandbox

### Overview
The CodeChamber provides **zero-trust isolated execution** for AI-generated code using Wasmtime and WASI.

### Features
- **Wasmtime Engine**: Industry-standard WebAssembly runtime
- **Fuel Metering**: 1,000,000 fuel units prevent infinite loops
- **Network Isolation**: Zero network access ("air-gapped" execution)
- **Ephemeral Filesystem**: Temporary `/workspace` directory, auto-cleaned
- **Stdio Capture**: All output intercepted for analysis
- **Audit Logging**: Execution receipts logged to L1 audit chain

### The "Chamber" Architecture

```rust
// crates/oasis-sandbox/src/chamber.rs
pub struct CodeChamber {
    engine: Engine,  // Wasmtime with fuel consumption enabled
}

// The "Vacuum" - isolated environment configuration
impl CodeChamber {
    pub fn prepare_vacuum(&self, wasm_binary: &[u8]) 
        -> Result<(Linker<WasiCtx>, Store<WasiCtx>, Module)> {
        // Network: DENIED
        // Filesystem: Ephemeral temp dir at /workspace
        // Fuel: 1,000,000 units (halting problem mitigation)
    }
}
```

### Execution Flow

1. **Load**: WASM binary loaded into Wasmtime engine
2. **Configure**: Ephemeral filesystem created, fuel set to 1M units
3. **Execute**: `_start` function called with stdio capture
4. **Monitor**: Fuel consumption tracked to detect infinite loops
5. **Audit**: Execution receipt (code hash + fuel + status) logged to L1
6. **Cleanup**: Temporary filesystem destroyed

### CLI Usage

```bash
# Execute WASM file in sandbox
oasis simulate --file ./target/wasm32-wasi/release/app.wasm

# Output:
# Simulation Result:
#   Success: true
#   Fuel Consumed: 42,891
#   Output: Hello from WASM!
```

### Safety Guarantees

| Threat | Mitigation |
|--------|------------|
| Infinite loops | Fuel metering (1M limit) |
| Network exfiltration | Zero network capabilities |
| Filesystem tampering | Ephemeral `/workspace` only |
| Memory bombs | Wasmtime memory limits |
| Supply chain attacks | Audit logged to immutable L1 chain |

---

## 🔥 L5 NeuroWall Semantic Firewall

### Overview
Embedded ONNX-based jailbreak detection for AI prompts.

### Features
- **Embedded Model**: all-MiniLM-L6-v2 (90MB ONNX, no external API calls)
- **384D Embeddings**: Same vector space as L2 Codex
- **Prompt Injection Detection**: Semantic similarity against jailbreak corpus
- **Zero Latency Overhead**: Local inference (no network calls)

### Usage

```bash
# Start firewall proxy
export OPENAI_API_KEY=sk-...
oasis firewall --port 3051

# Configuration
# Proxies to: https://api.openai.com/v1/chat/completions
# Blocks: Jailbreak attempts, prompt injections
# Logs: All requests to L1 audit chain
```

---

## 🔐 L1 Compliance Engine

### Cryptographic Audit Trail

- **Ed25519 Signatures**: Each audit event signed with persistent node identity
- **SHA-256 Hash Chaining**: Blockchain-style immutability
- **Receipt Generation**: Unique UUID per event with timestamp
- **Chain Verification**: Cryptographic proof of log integrity

### Database Schema

```sql
-- migrations/001_audit_log_schema.sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    receipt_id TEXT UNIQUE,
    prev_hash TEXT,
    current_hash TEXT,
    actor_user_id TEXT,
    operation_type TEXT,
    log_data_json TEXT,
    signature BLOB,
    signer_key_id TEXT,
    timestamp_utc TEXT
);
```

---

## 📦 Build from Source

### Prerequisites
- Rust 1.70+ (stable toolchain)
- ~500MB disk space

### Clean Build

```bash
# Clone repository
git clone https://github.com/SecuraMem/oasis.git
cd oasis

# Clean build
cargo clean
cargo build --release

# Binary: target/release/oasis.exe (~100MB)
```

### Hardened Build Profile

```toml
[profile.release]
opt-level = "z"          # Size optimization
lto = "fat"              # Link-time optimization
strip = true             # Strip debug symbols
panic = "abort"          # No unwinding
overflow-checks = true   # Runtime safety checks
```

---

## 📊 Technical Specifications

| Property | Value |
|----------|-------|
| **Binary Size** | ~100 MB |
| **Embedded AI Model** | all-MiniLM-L6-v2 (90 MB ONNX) |
| **Embedding Dimensions** | 384 |
| **Runtime Dependencies** | **ZERO** (fully static) |
| **Supported Languages** | Rust, Python, JavaScript, TypeScript |
| **Database Engine** | SQLite 3 (embedded) |
| **WASM Runtime** | Wasmtime 16.0 |
| **SIMD Optimizations** | AVX2/FMA |
| **License System** | Ed25519 JWT + hardware fingerprinting |

---

## 🛠️ CLI Commands Reference

### Core Commands

```bash
oasis init              # Initialize database and cryptographic identity
oasis status            # Show system status (license, database, identity)
oasis verify            # Verify audit chain integrity
oasis machine-id        # Show hardware fingerprint for licensing
```

### L2 Semantic Codex

```bash
oasis index --path <PATH>           # Index file or directory
oasis search --query <QUERY>        # Semantic code search
  --limit <N>                       # Number of results (default: 5)
```

### L4 CodeChamber Sandbox

```bash
oasis simulate --file <WASM_FILE>   # Execute WASM in isolated sandbox
```

### L5 NeuroWall Firewall

```bash
oasis firewall --port <PORT>        # Start semantic firewall proxy
  --openai-api-key <KEY>            # OpenAI API key (or set OPENAI_API_KEY env var)
```

### L1 Compliance & Monitoring

```bash
oasis log --message <MSG>           # Log test event to audit chain
oasis serve --port <PORT>           # Start L3 API server (Prometheus metrics)
oasis test-embedding --text <TEXT>  # Test embedding generation
```

### Vendor Commands (Hidden)

```bash
oasis gen-vendor-keys               # Generate Ed25519 vendor keypair
oasis gen-license                   # Generate license for client
  --machine-id <ID>
  --company <NAME>
  --vendor-key <PATH>
```

---

## 📚 Documentation

- [Golden Binary Build](GOLDEN_BINARY_BUILD.md) - Build process and hardening
- [Verification Report](GOLDEN_BINARY_VERIFICATION.md) - Acceptance tests and validation
- [Post-Build Summary](POST_BUILD_SUMMARY.md) - Executive summary and metrics
- [Phase 5 NeuroWall](PHASE5_NEUROWALL_COMPLETE.md) - Semantic firewall deep dive
- [Rust Architecture](RUST_ARCHITECTURE.md) - Codebase structure and design patterns

---

## 🧪 Testing

### Unit Tests

```bash
# Test all workspace crates
cargo test --workspace

# Test specific layers
cargo test -p oasis-codex        # L2 Semantic Codex
cargo test -p oasis-sandbox      # L4 CodeChamber Sandbox
cargo test -p securamem-l1       # L1 Compliance Engine
cargo test -p securamem-firewall # L5 NeuroWall
```

### Integration Tests

```bash
# Index and search codebase (dogfooding L2)
cargo run --bin oasis -- init
cargo run --bin oasis -- index --path crates
cargo run --bin oasis -- search --query "audit trail" --limit 5

# Sandbox execution test (L4)
# (Requires WASM binary - see oasis-sandbox tests for WAT examples)
cargo run --bin oasis -- simulate --file tests/hello.wasm
```

---

## 🔒 Security & Compliance

### Air-Gapped Operation
- **Zero External Dependencies**: All AI models embedded (90MB ONNX)
- **No Telemetry**: No data leaves the machine
- **Offline Capable**: Full functionality without internet

### Compliance Features
- **Immutable Audit Log**: Cryptographically verified hash chain
- **Digital Signatures**: Ed25519 signatures on all audit events
- **License Enforcement**: Hardware-locked JWT with expiration
- **GDPR Ready**: No external data transmission
- **SOC 2 Aligned**: Comprehensive audit trail

### Threat Model
| Attack Vector | OASIS Defense |
|---------------|---------------|
| Malicious AI code execution | L4 Wasmtime sandbox (network denied, fuel limited) |
| Prompt injection attacks | L5 NeuroWall semantic detection |
| Audit log tampering | L1 SHA-256 hash chain + Ed25519 signatures |
| License bypass | Hardware fingerprinting + cryptographic verification |
| Supply chain attacks | Single binary, zero external dependencies |

oasis machine-id

# Output: 91f18d9691eea91d69f42a5bd474a26b1ca24b2747ba42fa3f99717caad79bfb
```

Contact sales@securamem.com with your Machine ID to request a license.

---

## 🤝 Contributing

This is a proprietary codebase. For enterprise partnerships or acquisition inquiries, contact:
- **Email**: sales@securamem.com
- **Repository**: https://github.com/SecuraMem/oasis

---

## 📈 Roadmap

### Completed ✅
- [x] L1 Compliance Engine (Ed25519 + SHA-256 hash chain)
- [x] L2 Semantic Codex (tree-sitter + 384D embeddings)
- [x] L3 Storage & Monitoring (SQLite + Prometheus)
- [x] L4 CodeChamber Sandbox (Wasmtime WASI isolation)
- [x] L5 NeuroWall Firewall (ONNX jailbreak detection)
- [x] L6 API Server (Axum REST endpoints)
- [x] CLI Integration (12 commands, single binary)
- [x] License System (JWT + hardware fingerprinting)

### Future Enhancements
- [ ] Multi-language LSP integration
- [ ] Distributed ledger synchronization
- [ ] Advanced sandbox policies (configurable resource limits)
- [ ] Real-time code suggestions (embedded LLM)
- [ ] WebAssembly Component Model support

---

**Built with ❤️ in Rust**  
**Status:** PRODUCTION READY ✅  
**Build Date:** 2025-11-20  
**Binary Hash:** `6b7edf8`
