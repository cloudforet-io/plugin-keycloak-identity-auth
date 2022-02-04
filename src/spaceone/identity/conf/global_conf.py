CONNECTORS = {
}


LOG = {
    'filters': {
        'masking': {
            'rules': {
                'Auth.verify': ['secret_data'],
                'Auth.find': ['secret_data'],
                'Auth.login': ['secret_data']
            }
        }
    }
}

HANDLERS = {
}

ENDPOINTS = {
}
