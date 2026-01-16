# re-audit

A tool to help prepare Rust crate releases for [cargo-vet](https://mozilla.github.io/cargo-vet/) auditing.

## The Problem

When projects like Chromium use third-party Rust crates, they require security audits via cargo-vet before adoption. Each new release needs a human reviewer to:

- Review all unsafe code changes
- Check for filesystem/network access
- Verify no crypto implementations
- Document findings in `audits.toml`

This creates friction for crate maintainers - every release means more work for auditors.

## The Solution

`re-audit` automates the tedious parts of audit preparation by:

- **Detecting unsafe code** - finds all `unsafe fn`, `unsafe impl`, `unsafe trait`, and `unsafe {}` blocks
- **Highlighting NEW changes** - marks unsafe code added in the diff with 🆕 so reviewers focus on what's new
- **Finding security patterns** - filesystem, network, crypto, FFI, raw pointers, transmute usage
- **Tracking dependencies** - shows added/removed/updated deps that need their own audits
- **Suggesting criteria** - recommends cargo-vet criteria based on analysis
- **Generating templates** - ready-to-paste TOML for `audits.toml`

## Installation

```bash
go install github.com/hjanuschka/re-audit@latest
```

Or build from source:

```bash
git clone https://github.com/hjanuschka/re-audit
cd re-audit
go build -o re-audit .
```

## Usage

### Compare two releases

```bash
re-audit -repo /path/to/crate -from v0.1.5 -to v0.2.0
```

### Compare last release to HEAD (for pre-release review)

```bash
re-audit -repo /path/to/crate -from v0.1.5 -to HEAD
```

### Output to file

```bash
re-audit -repo /path/to/crate -from v0.1.5 -to v0.2.0 -output audit-report.md
```

### JSON output (for automation)

```bash
re-audit -repo /path/to/crate -from v0.1.5 -to v0.2.0 -format json
```

## Example Output

```markdown
# 🔍 Audit Report: jxl v0.2.0

**Comparing:** `v0.1.5` → `v0.2.0`

**Diff stats:**  57 files changed, 4108 insertions(+), 601 deletions(-)

## Summary

| Metric | Count |
|--------|-------|
| Unsafe blocks (production) | 191 |
| **NEW unsafe blocks** | **60** |
| Unsafe blocks (tests) | 11 |
| Files with unsafe code | 18 |
| Security-relevant patterns | 145 |
| Dependency changes | 0 |
| Files changed | 58 |

## Risk Assessment

🔴 191 unsafe blocks in production code - thorough review needed
🆕 60 NEW unsafe blocks added in this diff
ℹ️  11 unsafe blocks in test code (less critical)
⚠️  Filesystem access detected - verify safe-to-deploy
🆕 Transmute usage detected - careful review needed

## Suggested cargo-vet Criteria

- `ub-risk-2` or `ub-risk-3`: Significant unsafe code present
- `safe-to-run`: Filesystem/network access present, review scope
- `does-not-implement-crypto`: No crypto implementations found

## 🆕 NEW Unsafe Code (Review Priority)

These unsafe blocks were **added in this diff** and require careful review:

### jxl/src/util/atomic_refcell/internal.rs:19 (unsafe_block)
```rust
    fn ptr(&self) -> NonNull<T> {
        // SAFETY: Pointer returned by `UnsafeCell::get` is non-null.
        unsafe { NonNull::new_unchecked(self.data.get()) }
    }
```

...

## Audit Template

```toml
[[audits.jxl]]
who = "Your Name <your.email@example.com>"
criteria = ["safe-to-deploy", "does-not-implement-crypto"]
delta = "v0.1.5 -> 0.2.0"
notes = "Reviewed via re-audit tool"
```
```

## CI Integration

Add `.github/workflows/audit-status.yml` to your repository to automatically:

- Generate audit reports on pull requests
- Create tracking issues when releases are tagged
- Comment on PRs with audit-relevant changes

See [.github/workflows/audit-status.yml](.github/workflows/audit-status.yml) for an example workflow.

## What It Detects

### Unsafe Code Patterns

| Pattern | Description |
|---------|-------------|
| `unsafe fn` | Unsafe function declarations |
| `unsafe impl` | Unsafe trait implementations |
| `unsafe trait` | Unsafe trait definitions |
| `unsafe { }` | Unsafe blocks |

### Security-Relevant Patterns

| Category | Examples |
|----------|----------|
| **fs** | `std::fs`, `File::`, `read_to_string`, `write_all` |
| **net** | `std::net`, `TcpStream`, `hyper::`, `reqwest::` |
| **crypto** | `encrypt`, `decrypt`, `aes`, `sha`, `hmac` |
| **ffi** | `extern "C"`, `CString`, `#[no_mangle]` |
| **env** | `std::env`, `process::Command` |
| **raw_ptr** | `*const`, `*mut`, `.as_ptr()` |
| **transmute** | `transmute`, `from_raw_parts` |

## cargo-vet Criteria Reference

| Criteria | Meaning |
|----------|---------|
| `ub-risk-0` | No unsafe code |
| `ub-risk-1` | Excellent soundness, well-documented unsafe |
| `ub-risk-2` | Average soundness, minor issues possible |
| `ub-risk-3` | Significant risk, use with caution |
| `safe-to-deploy` | No serious vulnerabilities for production use |
| `safe-to-run` | Safe for local/CI use, may have fs/net access |
| `does-not-implement-crypto` | No cryptographic implementations |

See [Google's auditing standards](https://github.com/google/rust-crate-audits/blob/main/auditing_standards.md) for full criteria definitions.

## License

MIT
