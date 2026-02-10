# Database Schema Documentation

This document describes the SQLite database schema used by the Galatea agent for storing threat intelligence and configuration.

## Overview

**Database File:** `galatea_dataset.db`  
**Location:** Agent directory (same as `Agent.exe`)  
**Engine:** SQLite 3 (via `rusqlite` crate with bundled feature)  
**Connection Pooling:** r2d2 (max 16 connections)

## Schema

### Signatures Table

Stores known-bad file signatures (hashes) and their associated verdicts.

```sql
CREATE TABLE IF NOT EXISTS signatures (
    hash TEXT PRIMARY KEY,
    type INTEGER NOT NULL DEFAULT 0,
    verdict INTEGER NOT NULL DEFAULT 100,
    meta TEXT
);
```

**Columns:**

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `hash` | TEXT | PRIMARY KEY | Hash value (currently MD5, lowercase hex) |
| `type` | INTEGER | NOT NULL, DEFAULT 0 | Hash algorithm type (see enum below) |
| `verdict` | INTEGER | NOT NULL, DEFAULT 100 | Threat score (0-100, 100 = known malicious) |
| `meta` | TEXT | - | Optional metadata (malware family, source, etc.) |

**Hash Type Enum:**

```rust
pub enum IOCTYPE {
    Md5Hash = 0,    // Currently implemented
    // Future: SHA1 = 1, SHA256 = 2, etc.
    Unknown = 999,
}
```

**Verdict Scoring:**

| Score | Interpretation |
|-------|---------------|
| 100 | Known malicious (definitive block) |
| 75-99 | High confidence malicious |
| 50-74 | Suspicious |
| 25-49 | Low confidence threat |
| 0-24 | Informational only |

**Example Rows:**

```sql
INSERT INTO signatures (hash, type, verdict, meta) VALUES
  ('44d88612fea8a8f36de82e1278abb02f', 0, 100, 'EICAR test file'),
  ('5f4dcc3b5aa765d61d8327deb882cf99', 0, 95, 'Malware family: Emotet'),
  ('098f6bcd4621d373cade4e832627b4f6', 0, 100, 'Known ransomware');
```

