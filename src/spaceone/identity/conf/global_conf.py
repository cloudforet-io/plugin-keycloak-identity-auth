CONNECTORS = {}

LOG = {
    "filters": {
        "masking": {
            "rules": {
                "ExternalAuth.init": ["secret_data"],
                "ExternalAuth.authorize": ["secret_data", "credentials"],
            }
        }
    }
}

HANDLERS = {}

ENDPOINTS = {}
