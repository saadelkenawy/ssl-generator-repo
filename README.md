# SSL Generator

> PKI Certificate Generator — available as a CLI tool, RPM package, Docker container, and a full-featured Flask Web UI.

---

## Table of Contents

- [Overview](#overview)
- [Web UI (ssl-ui)](#web-ui-ssl-ui)
- [CLI / RPM Install](#cli--rpm-install)
- [Docker](#docker)
- [CLI Usage](#cli-usage)
- [Security Notes](#security-notes)

---

## Overview

SSL Generator creates full PKI certificate chains with a single command. It supports:

| Mode | Description |
|------|-------------|
| **Mode 1** | Full PKI: Root CA → Intermediate CA → Server Certificate |
| **Mode 2** | Issue additional server certs from an existing CA |

---

## Web UI (ssl-ui)

A Flask-based web application with user authentication, certificate history, and one-click SSL generation.

### Features

- User registration & login (email/password)
- Google and Facebook OAuth login
- Email verification
- SSL certificate generation via the browser
- Certificate download (zip)
- Generation history per user
- PostgreSQL backend
- Dockerized with Docker Compose

### Quick Start

```bash
cd ssl-ui

# 1. Copy and fill in your credentials
cp .env.example .env
nano .env          # set POSTGRES_PASSWORD, SECRET_KEY, OAuth credentials, mail settings

# 2. Start the stack
docker compose up -d --build

# 3. Open in browser
open http://localhost:5000
```

### Environment Variables

All secrets are loaded from a `.env` file (never committed). Copy `.env.example` to get started:

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `SECRET_KEY` | Flask session secret (random string) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `FACEBOOK_CLIENT_ID` | Facebook App ID |
| `FACEBOOK_CLIENT_SECRET` | Facebook App secret |
| `MAIL_USERNAME` | SMTP email address |
| `MAIL_PASSWORD` | SMTP app password |

### Stack

| Service | Technology |
|---|---|
| Web app | Python 3 / Flask |
| Database | PostgreSQL 15 |
| Auth | Flask-Login + Authlib (OAuth) |
| Email | Flask-Mail |
| Container | Docker + Docker Compose |

---

## CLI / RPM Install

### Step 1 — Add the YUM/DNF repository

```bash
sudo curl -o /etc/yum.repos.d/ssl-generator.repo \
  https://saadelkenawy.github.io/ssl-generator-repo/ssl-generator.repo
```

### Step 2 — Install

```bash
sudo dnf install ssl-generator      # RHEL 8+ / Rocky / AlmaLinux / Fedora
sudo yum install ssl-generator      # RHEL 7 / CentOS 7
```

### Direct RPM install (no repo needed)

```bash
sudo rpm -ivh https://saadelkenawy.github.io/ssl-generator-repo/x86_64/ssl-generator-1.0.0-1.x86_64.rpm
```

### Requirements

- OS: RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora (x86_64)
- `openssl >= 1.1.1` (installed automatically as a dependency)

### Uninstall

```bash
sudo dnf remove ssl-generator
```

---

## Docker

Run the CLI tool in a container (UBI9 minimal base):

```bash
# Build
docker build -t ssl-generator .

# Run interactively
docker run -it --rm -v $(pwd)/certs:/output ssl-generator bash
ssl-generator
```

---

## CLI Usage

```bash
ssl-generator           # Interactive — choose Mode 1 or Mode 2
ssl-generator --help    # Show help
```

---

## Security Notes

- Never commit `.env` files — use `.env.example` as a template
- Rotate your `SECRET_KEY` before going to production
- Store OAuth credentials in environment variables only
- The `ssl-ui/certs/` directory is excluded from git (contains generated certificates)

---

## Maintainer Notes (RPM repo update)

1. Build the new `.rpm` using `rpmbuild`
2. Drop it into `x86_64/`
3. Regenerate metadata: `createrepo_c .`
4. Commit and push — GitHub Pages serves it automatically

---

*Maintained by [Saad El-Kenawy](https://github.com/saadelkenawy)*
