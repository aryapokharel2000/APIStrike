# APIStrike

APIStrike is a modular Python-based security scanner designed to identify common API security misconfigurations and vulnerabilities.

## Features

* CORS misconfiguration detection
* Security header analysis
* API vulnerability checks
* Modular scanning architecture
* JSON and HTML report generation
* CLI-based interface
* Docker-compatible vulnerable API test environment

## Requirements

* Python 3.10+
* Docker (optional, for running VulnAPI)

## Installation

```bash
git clone https://github.com/your-username/APIStrike.git
cd APIStrike

pip install -r requirements.txt
```

## Usage

Run APIStrike against a test API:

```bash
python -m apistrike --target http://127.0.0.1:5000
```

Use:

```bash
python -m apistrike --help
```

to view the available options.

## VulnAPI

The repository includes **VulnAPI**, a deliberately vulnerable Flask API designed for testing and demonstrating APIStrike's detection capabilities.

To start the test environment:

```bash
docker compose up --build
```

The API can then be accessed locally and scanned using APIStrike.

## Reports

APIStrike can generate scan results in:

* HTML
* JSON

These reports provide details about detected vulnerabilities and security findings.

## Disclaimer

APIStrike is intended for **authorized security testing, research, and educational purposes only**.

Only scan systems that you own or have explicit permission to test.

