# SOC Triage & Enrichment Pipeline (Production-Level Demo)

A production-style demo repository for Security Operations Center (SOC) alert parsing, triage, enrichment, MITRE mapping, severity scoring, reporting, GitHub security event ingestion, and CI/CD with GitHub Actions.

## Features
- Parses authentication and security event logs into a normalized schema
- Applies modular detection rules loaded from JSON
- Correlates related events into higher-priority analyst alerts
- Enriches source IP addresses from a local reputation feed
- Maps detections to MITRE ATT&CK techniques/tactics
- Produces JSON alerts and an HTML triage report
- Includes a local HTML dashboard generator
- Runs automated tests and pipeline execution in GitHub Actions
- Ingests simulated GitHub security events (secret scanning / dependency alerts)

## Quick Start
```bash
python -m src.main --input data/sample_logs.log --ioc data/ioc_reputation.json --rules rules/detection_rules.json --out output
```

## Run Tests
```bash
python -m unittest discover -s tests -v
```

## Run Dashboard
```bash
python -m src.dashboard --alerts output/alerts.json --out output/dashboard.html
```

## Security Note
This project is for training/demo use with synthetic data only.
