# ssl-generator RPM Repository

> PKI Certificate Generator — hosted as a YUM/DNF-compatible repo via GitHub Pages.

---

## Install on RHEL / Rocky / AlmaLinux / Fedora / CentOS

### Step 1 — Add the repository

```bash
sudo curl -o /etc/yum.repos.d/ssl-generator.repo \
  https://saadelkenawy.github.io/ssl-generator-repo/ssl-generator.repo
```

### Step 2 — Install

```bash
sudo dnf install ssl-generator      # RHEL 8+ / Rocky / AlmaLinux / Fedora
sudo yum install ssl-generator      # RHEL 7 / CentOS 7
```

---

## Direct RPM install (no repo needed)

```bash
sudo rpm -ivh https://YOUR_GITHUB_USERNAME.github.io/ssl-generator-repo/x86_64/ssl-generator-1.0.0-1.x86_64.rpm
```

---

## Usage

```bash
ssl-generator           # Interactive — choose Mode 1 or Mode 2
ssl-generator --help    # Show help
```

| Mode | Description |
|------|-------------|
| **Mode 1** | Full PKI: Root CA + Intermediate CA + Server Certificate |
| **Mode 2** | Issue additional server certs from an existing CA |

---

## Requirements

- OS: RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora (x86_64)
- `openssl >= 1.1.1` (installed automatically as a dependency)

---

## Uninstall

```bash
sudo dnf remove ssl-generator
```

---

## How to update this repo (maintainer notes)

1. Build the new `.rpm` using `rpmbuild`
2. Drop it into `x86_64/`
3. Regenerate metadata: `createrepo_c .`
4. Commit and push — GitHub Pages serves it automatically

---

*Maintained by Saad El-Kenawy*

