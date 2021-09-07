# CBExpensive

```
  ___| __ )  ____|                           _)           
 |     __ \  __| \ \  / __ \   _ \ __ \   __| |\ \   / _ \
 |     |   | |    `  <  |   |  __/ |   |\__ \ | \ \ /  __/
\____| ___/ _____|_/\_\ .__/ \___|_|  _|____/_|  \_/ \___|
                       _|                                 
```

A tool that detects the "expensive" Carbon Black watchlists. 

This tool assist in detecting watchlists defined as "expensive", which may adversely affect the performance of the Carbon Black Response. 

Installation
-

1. Install Python 3 and PIP
2. Clone this repository
3. Go inside the repository and install the requirements: 
```console
pip install -r requirements.txt
```

How it works ?
-
This tool checks all the watchlists in the product for the cases specified in the following items.

* Number of wildcards used
* Is wildcard used with "modload" operand ?
* Is wildcard used with "filemod" operand ?
* Query Execution Time (last execution time)
* Number of "OR" operator use
* Is there usage of equals instead of colons with any operand ?

Usage
-
1. Url, port, and Carbon Black API Key fields must be entered in the config file.
2. Config file and script must be in the same directory. Then the script can be run as follows:
```console
python3 cbexpensive.py
```
3. After the script runs, it will generate the results as ".csv" in the directory where it is located.

Config File
-
<pre>
[APIKEY]
API_KEY = apikey
[URL]
CB_URL = https://1.1.1.1
CB_PORT = 80
</pre>

Example
-
Query|ExecutionTime|NumberofWildcard|WildcardwithFilemod|WildcardwithModload|EqualOperator|NumberofOROperator
--- | --- | --- | --- |--- |--- |---
((process_name:net.exe OR process_name:net1.exe) AND cmdline:use)|30|0|FALSE|FALSE|FALSE|1

References
-
1. https://developer.carbonblack.com/reference/enterprise-response/6.3/rest-api/#watchlist-operations
2. https://community.carbonblack.com/t5/Knowledge-Base/EDR-Are-there-Best-Practices-for-Performance-When-Writing-a/ta-p/88599
