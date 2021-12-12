# Python3 VirusTotal API v3 File Hash Lookup

### Getting started  

**Prerequisite:** A VirusTotal API key is required and must be set as an environment variable with a name of `VT_API_KEY`. Get a free public API key by completing the signup at https://www.virustotal.com/gui/join-us.

1. Download or clone the `vtlookup` repository 

2. Set the `VT_API_KEY` environment variable:

For Linux users -
```
VT_API_KEY="YOUR_VIRUSTOTAL_APIKEY"
export VT_API_KEY
```

For Windows users -
```
setx VT_API_KEY "YOUR_VIRUSTOTAL_APIKEY"
```

### Usage examples (running from terminal)

- Lookup using plain text hash *(hashValue can be md5, sha1, or sha256)*  -  
`python3 vtlookup.py -hash hashValue`  
*The below example will return detections:*  
`python3 vtlookup.py -hash a2f6b977b849ba588b88c81b68b4535c`  

- Lookup by getting the sha256 hash from a local file -  
`python3 vtlookup.py -file specifyfilename.ext`

- Offline debug using the included `test.json` file -  
`python3 vtlookup.py -debug test.json`

### Troubleshooting

API error code descriptions can be found at: https://developers.virustotal.com/reference/errors  
