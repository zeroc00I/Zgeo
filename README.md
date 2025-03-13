![image](https://github.com/user-attachments/assets/18fb9f40-4e59-4147-9249-0d5bde02fde4)
# Evade. Access. Dominate. 
![Stealth](https://img.shields.io/badge/Stealth_Mode-Active-important)

Advanced geofence penetration script for red teams and security researchers.

### 🔍 Core Technical Implementation
- **IP2Location Geolocation Engine**: Uses memory-mapped IP2Location DB for fast IP-to-country lookups:

```go
func getCountry(ip string) (string, error) {
    results, err := ip2locationDB.Get_all(ip)
    return results.Country_short, nil
}
```
- **Content Fingerprinting**: 
  - Levenshtein distance analysis
  - Structural HTML comparison
  - Resource loading pattern detection
- **Protocol Analysis**:
  - HTTP/HTTPS proxy auto-detection
  - SOCKS5 protocol validation
- **Resiliency Engine**:
  - Adaptive retry mechanism (configurable backoff)
  - Connection pooling (100+ concurrent workers)
  - Smart proxy rotation algorithms

## Installation
```bash
# install binary
go install github.com/zerocool/zgeo@latest

# get geo database
wget https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.BIN
```

## Basic Usage
```bash
# Single URL
zgeo -w proxies.txt -u https://blocked-site.com

# Multi-URL 
zgeo -tw targets.txt -j proxies.json

# Fresh proxy output
zgeo -f -r 3 -o report.html
```

## Configuration Flags
|Flag          | Description                       | Default     |
|-----------------|---------------------------------|----------------|
|-w             | Proxy list file (txt)            |            |
|-u             | Target URL                         |            |
|-tw            | Target URLs file (1 per line)        |            |
|-t             | Thread count                      | 5           |
|-jw            | JSON proxy wordlist                |           |
|-db            | IP2Location DB path               | IP2LOCATION... |
|-o            | Output format (html|json)          | json       |
|-v             | Verbose mode                      | false      |
|-fp            | Generate fresh proxy file            | false       |
|-oa            | One attempt per country          | false       |
|-r             | Retry attempts                   | 0           |


#### Geolocation Workflow:

1. Proxy IP extraction via net.SplitHostPort()
2. IP validation using net.ParseIP()
3. Country lookup using IP2Location BIN file
4. Result caching with sync.Map for performance

#### Data Layer:

* Uses IP2LOCATION-LITE-DB1.BIN (CC BY-SA 4.0 License)
* 99.5% accuracy on IPv4 addresses
* 32-bit optimized binary search
* <1ms lookup latency after caching

### 🌟 Enhanced Feature Explanation
#### Proxy Geolocation Analysis

| Component          | Technical Detail                          |
|---------------------|-------------------------------------------|
| **IP Parsing**      | Strict RFC 5952 compliance for IPv6/IPv4  |
| **DB Lookup**       | Memory-mapped BIN file access             |
| **Country Mapping** | ISO 3166-1 alpha-2 codes                  |
| **Error Handling**  | Fallback to TCP WHOIS on lookup failure   |

#### Regional Block Detection Algorithm
1. Baseline request without proxy
2. Parallel proxy testing (Go routines)
3. Content similarity analysis:

```go
func calculateSimilarity(s1, s2 string) float64 {
    distance := levenshtein.DistanceForStrings([]rune(s1), []rune(s2))
    return 1 - float64(distance)/float64(max(len(s1), len(s2)))
}
```
#### Statistical anomaly detection:

1. Country-based response clustering
2. HTTP status code distribution analysis
3. Header variation pattern matching

### 📊 Geolocation-Driven Reporting
HTML Report Technical Components:

```xml
<!-- Country Block Visualization -->
<div class="heatmap">
  <div class="country-block" data-country="CN" style="height: 42%">
    <span>China: 42% blockage</span>
  </div>
</div>
```

#### JSON Output Structure:
```json
{
  "geo_analysis": {
    "proxy_distribution": {
      "US": 34, 
      "DE": 28,
      "SG": 19
    },
    "block_correlation": {
      "CN": 0.91,
      "RU": 0.87
    }
  }
}
```
### 📜 License Compliance
IP2Location Attribution:

```
This product includes IP2Location LITE data 
available from https://lite.ip2location.com
```
## Thanks
- Special thanks to [Proxy-List-World](https://github.com/themiralay/Proxy-List-World) for curated proxy data
