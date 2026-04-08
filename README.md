# AI SIEM

A local SIEM (Security Information and Event Management) tool with AI-powered log analysis. Built with Python/FastAPI, Elasticsearch, and Ollama.

## Features

- **Log Collection** — Syslog, file watching, Docker, and network collectors
- **Detection Engine** — YAML-based rules with anomaly detection
- **AI Analysis** — Event correlation, natural language queries, and alert explanations via Ollama
- **Web Dashboard** — Real-time alerts, event search, and rule management

## Requirements

- Python 3.12+
- Docker (for Elasticsearch)
- Ollama (for AI features)

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev]"

# Start Elasticsearch
make up

# Copy and configure environment
cp .env.example .env

# Run the app
make dev
```

The dashboard will be available at `http://localhost:8000`.

## Usage

```bash
make up        # Start Elasticsearch
make down      # Stop Elasticsearch
make dev       # Run app with hot reload
make test      # Run tests
make lint      # Run linter
make kibana    # Start Elasticsearch + Kibana
make install   # Install with dev dependencies
```

## Project Structure

```
siem/
  ai/          # Ollama integration (correlation, queries, summaries)
  api/         # FastAPI routes
  collectors/  # Log collectors (syslog, files, docker, network)
  detection/   # Rule engine and anomaly detection
  models/      # Pydantic models
  storage/     # Elasticsearch client and queries
  tasks/       # Background collector tasks
rules/         # YAML detection rules
frontend/      # HTML/CSS/JS dashboard
```
