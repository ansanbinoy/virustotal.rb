# Summary

A Ruby tool to fetch URLs associated with domains or subdomains from VirusTotal. Given a list of domains, it connects to the VirusTotal API, retrieves related URLs. The tool can handle rate limits by rotating through a list of API keys, ensuring continuous data retrieval without interruptions.

# Usage

-   **Linux**

```bash
cp virustotal.rb ~/.local/bin

```

-   Options

```txt
Usage: ./virustotal.rb [options]
    -f, --file FILE                  File that contain domains
    -s, --[no-]subs                  Take subdomains from given domains
    -p, --path PATH                  File path that contain apiKeys

```

-   Inlude domain siblings from virustotal

```bash
virustotal.rb -f domains --subs -p apiKeys.txt

```

OR

```
cat domains | virustotal.rb --subs  -p apiKeys.txt

```

-   Fetch urls only give subdomain or domains.

```bash
virustotal.rb -f domains -p apikeys.txt

```

OR

```
cat domains | virustotal.rb -p apiKeys.txt

```
