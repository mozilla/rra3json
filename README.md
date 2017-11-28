This program integrates with service-map: https://github.com/mozilla/service-map
It posts a JSON version of the Gdocs RRA documents to service-map, to be precise.

See also: 
- https://wiki.mozilla.org/Security/Risk_management/Rapid_Risk_Assessment
- https://wiki.mozilla.org/Security/Data_Classification
- https://infosec.mozilla.com

# Get oauth2 credentials

See https://developers.google.com/api-client-library/python/start/get_started for a complete guide. This is the TLDR
version:
- As your user, login to https://console.developers.google.com/project/ and create a new project.
- Go to "Credentials".
- Click "Create credentials: Service account key"

You'll get a JSON key back (JWT), that's your credentials. It should contain `"type": "service_account"`, a
`client_email`, a `private_key` and a bunch of metadata.

NOTE: Make sure you authorize your service email (`client_email` field) to all the document you'll want rra3json to have
access to! By default it has no accesses.

# JSON Format

Refer to the `rra_schema.json` file.

# How to run

Make sure you have a configuration file such as `rra3json.yml` with all information filed in and run:
```
    #Make a venv if you like and activate it
    $ pip install -r requirements.txt
    $ ./rra3json.py -c rra3json.yml -s google_credentials.json
```
