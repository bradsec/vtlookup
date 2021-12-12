# VirusTotal Hash Lookup using API v3 and Python

### Download or clone the repository, see usage details below.

A VirusTotal public API key is required and must be set as an environment variable.
Please set the environment variable with a name of `VT_API_KEY`. If you don't have a key signup at https://www.virustotal.com/gui/join-us.

Use the following terminal commands to set the environment API key variable:

For Linux users -
```
> VT_API_KEY="YOUR_VIRUSTOTAL_APIKEY"
> export VT_API_KEY
```

For Windows users -
```
> setx VT_API_KEY "YOUR_VIRUSTOTAL_APIKEY"
```

USAGE EXAMPLES:

By plain text hash -
> `python3 vtlookup.py -hash 4534c2d2d89c40929adb71f9d52b650c`

By getting sha256 hash from a file on system
> `python3 vtlookup.py -file myfile.ext`

Offline debug using local json file
> `python3 vtlookup.py -debug text.json`
