# Catalyst Analysis

> [!WARNING]  
> **Experimental project:**
> The API may change before the first stable release.

### Overview

This project is a tool for enriching observables and events with additional information from
OpenCTI, MISP, and other sources.
It provides a plugin interface for easy integration with other services.

### Features

- RESTful API
- Enriches observables and events with additional information
- Supports multiple plugins
- Built-in plugins:
    - MITRE ATT&CK (`attack`)
        - Techniques
        - Tactics
    - MISP (`misp`)
        - Events
    - OpenCTI (`opencti`)
        - Observables
    - [CIRCLE Vulnerability Lookup](https://vulnerability.circl.lu/) (`vulnerability`)
        - CVE Details
    - GitHub (`github`)
        - Issues

### API

OpenAPI specification is available at [openapi.yaml](./openapi.yaml) 
([Open in Swagger Editor](https://editor.swagger.io/?url=https://raw.githubusercontent.com/SecurityBrewery/catalyst-analysis/main/openapi.yaml)).

### Installation and Usage

1. Clone the repository:
   ```sh
   git clone https://github.com/SecurityBrewery/catalyst-analysis.git
   cd catalyst-analysis
   ```

2. Build the server:
   ```sh
   go build -o catalyst-analysis ./cmd/server
   ```

3. Configure the server:
   ```sh
   echo '{
      "services": {
        "attack": {
          "plugin": "attack",
          "config": {}
        },
        "vulnerability": {
          "plugin": "vulnerability",
          "config": {}
        },
        "opencti": {
          "plugin": "opencti",
          "config": {
            "url": "https://your-opencti-instance",
            "key": "your-opencti-api-key"
          }
        },
        "internal-misp": {
          "plugin": "misp",
          "config": {
            "url": "https://your-misp-instance",
            "key": "your-misp-api-key"
          }
        },
        "sharing-misp": {
          "plugin": "misp",
          "config": {
            "url": "https://another-misp-instance",
            "key": "another-misp-api-key"
          }
        },
        "github": {
          "plugin": "github",
          "config": {
            "token": "your-github-token"
          }
        }
      }
    }' > config.json
   ```

4. Run the server:
   ```sh
   ./catalyst-analysis --config config.json --host 0.0.0.0 --port 8080
   ```

5. Use the API:
   ```sh
    curl http://localhost:8080/services
    ```
