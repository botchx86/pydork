# pydork
```
    ____        ____             __  
   / __ \__  __/ __ \____  _____/ /__
  / /_/ / / / / / / / __ \/ ___/ //_/
 / ____/ /_/ / /_/ / /_/ / /  / ,<   
/_/    \__, /_____/\____/_/  /_/|_|  
      /____/                         
```
## PyDork: Python Google Dorking Command-Line Tool
```
usage: pydork [-h] [-f FILE] [-n NUM] [-o OUTPUT] [--json-output JSON_OUTPUT] [--delay DELAY] [-d DOMAIN_FILTER] [--proxy PROXY]
              [--fetch-titles]
              [dork]

positional arguments:
  dork                  The Google Dork query to execute

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Specify a file containing multiple dork queries
  -n NUM, --num NUM     Number of results to display (default: 10)
  -o OUTPUT, --output OUTPUT
                        Save the results to a specified file
  --json-output JSON_OUTPUT
                        Save the results to a JSON file
  --delay DELAY         Set a delay (in seconds) between requests (default: 2)
  -d DOMAIN_FILTER, --domain-filter DOMAIN_FILTER
                        Filter results to include only URLs containing a specific domain
  --proxy PROXY         Route queries through a proxy (e.g., http://127.0.0.1:8080)
  --fetch-titles        Fetch and display page titles with results
```
## Example usage:
```
  python pydork.py 'site:example.com inurl:login' -n 5
```
