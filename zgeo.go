package main

import (
    "crypto/tls"
    "net/url"
    "sync/atomic"
    "golang.org/x/net/html"
    "log"
    "os"
    "io"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
    "math"
	"net/http"
	"strings"
	"sync"
	"time"
	"bytes"
	"html/template"
	"context"
    "os/signal"
    "syscall"
    "sort"
    "math/rand"
    "strconv"
	"github.com/ip2location/ip2location-go"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"github.com/valyala/fasthttp"
    "path/filepath"
)

var (
    verboseLogger *log.Logger
)

var dnsCache = struct {
    sync.RWMutex
    m map[string]string
}{m: make(map[string]string)}

var (
    activeProxies   = ActiveProxies{}
    baselineContent string
    baselineTitle   string
    ip2locationDB   *ip2location.DB
    ipCache         sync.Map
    dashboard Dashboard
)
var (
    geoCache = struct {
        sync.RWMutex
        m map[string]string
    }{m: make(map[string]string)}
)
var baselineTagCounts map[string]int

type ProxyMap map[string][]string

type ActiveProxies struct {
    proxies []ProxyInfo
    mu      sync.Mutex
}

 func extractTagCounts(content string) map[string]int {
   counts := make(map[string]int)
   doc, err := html.Parse(strings.NewReader(content))
   if err != nil {
       return counts
   }

   var f func(*html.Node)
   f = func(n *html.Node) {
       if n.Type == html.ElementNode {
           tagName := strings.ToLower(n.Data)
           counts[tagName]++
       }
       for c := n.FirstChild; c != nil; c = c.NextSibling {
           f(c)
       }
   }
   f(doc)
   return counts
 }

 func calculateTagSimilarity(a, b map[string]int) float64 {
   sumA := 0
   sumB := 0
   common := 0

   for tag, countA := range a {
       sumA += countA
       if countB, exists := b[tag]; exists {
           common += int(math.Min(float64(countA), float64(countB)))
       }
   }

   for _, countB := range b {
       sumB += countB
   }

   total := sumA + sumB
   if total == 0 {
       return 0.0
   }
   
    similarity := 2.0 * float64(common) / float64(total)
    similarity = math.Max(similarity, 0.0)
    similarity = math.Round(similarity*100) / 100 // Round to two decimals
    return math.Max(similarity, 0.0)  }


func (ap *ActiveProxies) Add(proxy ProxyInfo) {
    ap.mu.Lock()
    defer ap.mu.Unlock()
    
        exists := false
    for _, p := range ap.proxies {
        if p.Address == proxy.Address {
            exists = true
            break
        }
    }
    
    if !exists {
        ap.proxies = append(ap.proxies, proxy)
    }
}

func (ap *ActiveProxies) GetAll() []ProxyInfo {
    ap.mu.Lock()
    defer ap.mu.Unlock()
    
        result := make([]ProxyInfo, len(ap.proxies))
    copy(result, ap.proxies)
    return result
}



type Dashboard struct {
    TotalProxies     int64
    TestedProxies    int64
    SuccessCount     int64
    FailureCount     int64
    AnomaliesCount   int64
    StartTime        time.Time
    DifferentCountries map[string]int
    Baseline         ProxyInfo
    mu               sync.Mutex
}



type AllResults struct {
    Results   []Result
    StartTime time.Time
    EndTime   time.Time
}

type Result struct {
    URL              string
    Baseline         ProxyInfo
    LocalCountry     string
    Proxies          []ProxyInfo
    BlockingLevel    int
    DifferentCountries map[string][]ProxyInfo
}

type UsedProxyTracker struct {
    sync.Mutex
    proxies map[string]struct{}
}

type Job struct {
    Proxy   string
    Retries int
}
func (u *UsedProxyTracker) MarkUsed(proxy string) bool {
    u.Lock()
    defer u.Unlock()
    if _, exists := u.proxies[proxy]; exists {
        return false
    }
    u.proxies[proxy] = struct{}{}
    return true
}

type Config struct {
    Timeout         time.Duration
    ProxiesFile          string
    ProxyList            ProxyMap
    JSONWordlist         string
    TargetWordlist       string
    Threads              int
    TargetURL            string
    Verbose              bool
    NoPrecheck           bool
    UpOnly               bool
    FreshProxyOut        bool
    OneAttemptPerCountry bool
    Retries              int
    OutputFormat         string
}

type ProxyInfo struct {
    Address    string
    Status     string
    Country    string
    StatusCode int
    ContentSim float64
    TitleSim   float64
    Title      string
    Location   string
    Protocol   string
}

var proxyMapMu sync.Mutex

var (
    badProxies   sync.Map
)


var htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geo-Blocking Analysis Report</title>
    <style>
        .comparison-table { margin-top: 20px; background: #f9f9f9; }
        .local-response { background-color: #e6ffe6; font-weight: bold; }
        .highlight { color: #ff4444; font-size: 0.9em; }
        .low-sim { background-color: #ffe6e6; }
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .result-container { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; cursor: pointer; }
        .different-behavior { background-color: #ffeeee; }
        .unique-behavior { background-color: #ffe0e0; }
        .summary { background-color: #e6f3ff; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .highlight { font-weight: bold; color: #ff0000; }
    </style>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/jquery.tablesorter.min.js"></script>
    <script>
        $(function() {
            $(".sortable").tablesorter();
        });
    </script>
</head>
<body>
    <h1>Geo-Blocking Analysis Report</h1>
    <div class="summary">
        <h2>Overall Summary</h2>
        <p>Analysis started: {{.StartTime.Format "2006-01-02 15:04:05"}}</p>
        <p>Analysis completed: {{.EndTime.Format "2006-01-02 15:04:05"}}</p>
        <p>Total URLs analyzed: {{len .Results}}</p>
        <p>URLs with blocking detected: {{.BlockedURLs}}</p>
        <p>Total proxies tested: {{.TotalProxies}}</p>
        <p>Total Different Behavior proxies: {{.BlockedProxies}}</p>
    </div>

    {{range $result := .Results}}
    <div class="result-container">
        <h2>Results for {{$result.URL}}</h2>
        <div class="local-info">
            <p><strong>Local Country:</strong> {{$result.LocalCountry}}</p>
            <p><strong>Baseline Status:</strong> {{$result.Baseline.StatusCode}} ({{$result.Baseline.Country}})</p>
            <p><strong>Blocking Level:</strong> {{$result.BlockingLevel}}</p>
            <p><strong>Total Proxies Tested:</strong> {{len $result.Proxies}}</p>
            <p><strong>Successful Accesses:</strong> {{countSuccess $result.Proxies}}</p>
        </div>

        <h3>Countries with Different Behavior ({{len $result.DifferentCountries}} detected)</h3>
        <table class="sortable">
            <thead>
                <tr>
                    <th>Country</th>
                    <th>Proxies with Different Behavior</th>
                </tr>
            </thead>
            <tbody>
                {{range $country, $proxies := $result.DifferentCountries}}
                <tr>
                    <td>{{$country}}</td>
                    <td>{{len $proxies}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <h3>Response Comparison: Local vs Proxies</h3>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Country</th>
                    <th>Status Code</th>
                    <th>Content Similarity</th>
                    <th>Title Similarity</th>
                    <th>Response Title</th>
                </tr>
            </thead>
            <tbody>
                <tr class="local-response">
                    <td>Local</td>
                    <td>{{$result.LocalCountry}}</td>
                    <td>{{$result.Baseline.StatusCode}} (Baseline)</td>
                    <td>1.00</td>
                    <td>1.00</td>
                    <td>{{truncateString $result.Baseline.Title 50}}</td>
                </tr>
                
                {{range $proxy := $result.Proxies}}
                {{if ne $proxy.StatusCode 0}}
                <tr class="{{if lt $proxy.ContentSim 0.9}}low-sim{{end}}">
                    <td>Proxy</td>
                    <td>{{$proxy.Country}}</td>
                    <td>
                        {{$proxy.StatusCode}}
                        {{if ne $proxy.StatusCode $result.Baseline.StatusCode}}
                        <span class="highlight">(Δ{{sub $proxy.StatusCode $result.Baseline.StatusCode}})</span>
                        {{end}}
                    </td>
                    <td>
                        {{printf "%.2f" $proxy.ContentSim}}
                        {{if lt $proxy.ContentSim 0.9}}<span class="highlight">*</span>{{end}}
                    </td>
                    <td>
                        {{printf "%.2f" $proxy.TitleSim}} 
                        {{if lt $proxy.TitleSim 0.9}}<span class="highlight">*</span>{{end}}
                    </td>
                    <td>{{truncateString $proxy.Title 50}}</td>
                </tr>
                {{end}}
                {{end}}
            </tbody>
        </table>

        <h3>Proxies with Different Behavior</h3>
        <table class="sortable">
            <thead>
                <tr>
                    <th>Proxy</th>
                    <th>Country</th>
                    <th>Status Code</th>
                    <th>Content Similarity</th>
                    <th>Title Similarity</th>
                    <th>Response</th>
                </tr>
            </thead>
            <tbody>
                {{$baseline := $result.Baseline}}
                {{$commonStatus := mostCommonStatus $result.Proxies}}
                {{range $proxy := $result.Proxies}}
                {{if ne $proxy.StatusCode 0}}
                {{if or (ne $proxy.StatusCode $baseline.StatusCode) (lt $proxy.ContentSim 0.9) (lt $proxy.TitleSim 0.9)}}
                <tr class="{{if and (ne $proxy.StatusCode $baseline.StatusCode) (ne $proxy.StatusCode $commonStatus)}}unique-behavior{{else}}different-behavior{{end}}">
                    <td>{{$proxy.Address}}</td>
                    <td>{{$proxy.Country}}</td>
                    <td>
                        {{$proxy.StatusCode}}
                        {{if ne $proxy.StatusCode $baseline.StatusCode}}
                        <span class="highlight">(Baseline: {{$baseline.StatusCode}})</span>
                        {{end}}
                        {{if and (ne $proxy.StatusCode $baseline.StatusCode) (ne $proxy.StatusCode $commonStatus)}}
                        <span class="highlight">(Common: {{$commonStatus}})</span>
                        {{end}}
                    </td>
                    <td>
                        {{printf "%.2f" $proxy.ContentSim}}
                        {{if lt $proxy.ContentSim 0.9}}<span class="highlight">*</span>{{end}}
                    </td>
                    <td>
                        {{printf "%.2f" $proxy.TitleSim}}
                        {{if lt $proxy.TitleSim 0.9}}<span class="highlight">*</span>{{end}}
                    </td>
                    <td>
                        {{if $proxy.Title}}
                            {{truncateString $proxy.Title 50}}
                        {{else}}
                            {{$proxy.Status}}
                        {{end}}
                    </td>
                </tr>
                {{end}}
                {{end}}
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
</body>
</html>
`



func determineProxyProtocol(ctx context.Context, proxyAddr string) string {
    dialer := &net.Dialer{
        Timeout: 1 * time.Second,
    }
    
    // Use context-aware dialing
    conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
    if err != nil {
        return "unknown"
    }
    defer conn.Close()

    // Set overall deadline from context
    deadline, ok := ctx.Deadline()
    if ok {
        conn.SetDeadline(deadline)
    } else {
        conn.SetDeadline(time.Now().Add(2 * time.Second))
    }

    // Test HTTPS support
    _, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
    if err != nil {
        return "http"
    }

    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
        return "http"
    }

    response := string(buffer[:n])
    if strings.Contains(response, "200 Connection established") {
        return "https"
    }
    return "http"
}
func getCountry(ip string) (string, error) {
    if ip2locationDB == nil {
        return "", fmt.Errorf("IP2Location database not initialized")
    }
    if net.ParseIP(ip) == nil {
        return "Invalid", nil
    }
    start := time.Now()
    defer logVerbose(start, "GeoIP Lookup")
    geoCache.RLock()
    if country, ok := geoCache.m[ip]; ok {
        geoCache.RUnlock()
        return country, nil
    }
    geoCache.RUnlock()

        results, err := ip2locationDB.Get_all(ip)
    if err != nil {
        return "", err
    }
    
    geoCache.Lock()
    geoCache.m[ip] = results.Country_short
    geoCache.Unlock()
    
    return results.Country_short, nil
}

func sendFileProxies(filename string, proxyChan chan<- string, oneAttemptPerCountry bool) {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("Error opening proxy file: %v\n", err)
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    countrySeen := make(map[string]bool)
    for scanner.Scan() {
        proxy := strings.TrimSpace(scanner.Text())
        if proxy == "" || !strings.Contains(proxy, ":") {
            continue         }
        if oneAttemptPerCountry {
            host, _, _ := net.SplitHostPort(proxy)
            country, err := getCountryWithCache(context.Background(), host)
            if err != nil {
                fmt.Printf("Error getting country for IP %s: %v\n", host, err)
                continue
            }
            if !countrySeen[country] {
                proxyChan <- proxy
                countrySeen[country] = true
            }
        } else {
            proxyChan <- proxy
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading proxy file: %v\n", err)
    }
}



func sendJSONProxies(filename string, proxyChan chan<- string, oneAttemptPerCountry bool) {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("Error opening JSON wordlist file: %v\n", err)
        return
    }
    defer file.Close()

    var freshProxies []struct {
        IP      string `json:"ip"`
        Port    string `json:"port"`
        Country string `json:"country"`
    }

    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&freshProxies); err != nil {
        fmt.Printf("Error decoding JSON wordlist: %v\n", err)
        return
    }

    countrySeen := make(map[string]bool)
    for _, proxy := range freshProxies {
        proxyAddr := fmt.Sprintf("%s:%s", proxy.IP, proxy.Port)
        if proxyAddr == ":" || proxyAddr == "" {
            continue         }
        if oneAttemptPerCountry {            
            if !countrySeen[proxy.Country] {
                proxyChan <- proxyAddr
                countrySeen[proxy.Country] = true
            }
        } else {
            proxyChan <- proxyAddr
        }
    }
}



func mostCommonStatus(proxies []ProxyInfo) int {
    statusCounts := make(map[int]int)
    for _, proxy := range proxies {
        statusCounts[proxy.StatusCode]++
    }
    
    maxCount := 0
    commonStatus := 0
    for status, count := range statusCounts {
        if count > maxCount {
            maxCount = count
            commonStatus = status
        }
    }
    return commonStatus
}

func saveHTMLReport(allResults AllResults) {
    filename := "geo_blocking_report.html"
    f, err := os.Create(filename)
    if err != nil {
        fmt.Printf("Error creating HTML report: %v\n", err)
        return
    }
    defer f.Close()

    funcMap := template.FuncMap{
        "truncateString": func(s string, max int) string {
            if len(s) <= max {
                return s
            }
            return s[:max-3] + "..."
        },
        "countSuccess": func(proxies []ProxyInfo) int {
            count := 0
            for _, p := range proxies {
                if p.Status == "UP" {
                    count++
                }
            }
            return count
        },
        "mostCommonStatus": mostCommonStatus,
        "sub": func(a, b int) int { return a - b },
        "lt": func(a, b float64) bool { return a < b },
        "percentage": func(f float64) string {
            return fmt.Sprintf("%.0f%%", f*100)
        },
    }

    tmpl := template.Must(
        template.New("report").Funcs(funcMap).Parse(htmlTemplate),
    )

    debugInfo := fmt.Sprintf("Number of results: %d\n", len(allResults.Results))
    for i, result := range allResults.Results {
        debugInfo += fmt.Sprintf("Result %d:\n", i)
        debugInfo += fmt.Sprintf("  URL: %s\n", result.URL)
        debugInfo += fmt.Sprintf("  Number of proxies: %d\n", len(result.Proxies))
        if len(result.Proxies) > 0 {
            debugInfo += fmt.Sprintf("  First proxy Address: %s\n", result.Proxies[0].Address)
            debugInfo += fmt.Sprintf("  First proxy Country: %s\n", result.Proxies[0].Country)
        }
    }

    data := struct {
        Results       []Result
        StartTime     time.Time
        EndTime       time.Time
        BlockedURLs   int
        TotalProxies  int
        BlockedProxies int
        DebugInfo     string
    }{
        Results:       allResults.Results,
        StartTime:     allResults.StartTime,
        EndTime:       allResults.EndTime,
        BlockedURLs:   0,
        TotalProxies:   0,
        BlockedProxies: 0,
        DebugInfo:     debugInfo,
    }

    for _, result := range data.Results {
        if result.BlockingLevel > 0 {
            data.BlockedURLs++
        }
        data.TotalProxies += len(result.Proxies)
        for _, proxies := range result.DifferentCountries {
            data.BlockedProxies += len(proxies)
        }
    }

    if err := tmpl.Execute(f, data); err != nil {
        fmt.Printf("Error executing HTML template: %v\n", err)
        return
    }

    fmt.Printf("HTML report saved to %s\n", filename)
}

func quickProxyCheck(proxyAddr string, timeout time.Duration) bool {
    conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}


func extractTitle(body []byte) string {
    doc, err := html.Parse(bytes.NewReader(body))
    if err != nil {
        return ""
    }

    var title string
    var f func(*html.Node)
    f = func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
            title = n.FirstChild.Data
            return
        }
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }
    f(doc)

    return title
}


func getBaseline(url string) (ProxyInfo, string, string) {
    localCountry := getLocalCountry()
    
    client := &http.Client{
        Timeout: 15 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
                MinVersion: tls.VersionTLS12,
            },
        },
    }

    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

    resp, err := client.Do(req)
    if err != nil {
        return ProxyInfo{
            Status:     "CONNECTION_FAILED",
            StatusCode: 0,
            Country:    localCountry,
            Protocol:   "DIRECT",
        }, "", ""
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    return ProxyInfo{
        Status:     "UP",
        StatusCode: resp.StatusCode,
        Country:    localCountry,
        Protocol:   "DIRECT",
        Location:   resp.Header.Get("Location"),
    }, string(body), extractTitle(body)
}

func statusDescription(code int) string {
    if code == 0 {
        return "Connection Failed"
    }
    return "UP"
}

func printProxyInfo(info ProxyInfo) {
    statusColor := "\033[32m" // Green
    if info.Status != "UP" {
        statusColor = "\033[31m" // Red
    }
    
    fmt.Printf(
        "%-25s "+statusColor+"%-7s\033[0m %-7s %-6d %-8s %-15.2f %-15.2f %s\n",
        info.Address,
        info.Status,
        info.Country,
        info.StatusCode,
        info.Protocol,
        info.ContentSim,
        info.TitleSim,
        truncateString(info.Title, 40),
    )
}

func printResults(result Result, upOnly bool) {
    fmt.Printf("\n\n📌 Local Connection")
    fmt.Printf("\n├─ Your Country:      %s", result.LocalCountry)
    fmt.Printf("\n├─ Connection Status: %s (%d)", result.Baseline.Status, result.Baseline.StatusCode)
    
    if result.Baseline.Location != "" {
        fmt.Printf("\n└─ Redirected To:     %s", result.Baseline.Location)
    } else {
        fmt.Printf("\n└─ Direct Access:     %s", result.URL)
    }
    
    fmt.Printf("\n\n📊 Geo-Blocking Analysis")
    fmt.Printf("\n├─ Confidence Level:  %d/3", result.BlockingLevel)
    fmt.Printf("\n├─ Proxies Tested:    %d", len(result.Proxies))
    fmt.Printf("\n├─ Anomalies Found:   %d", countAnomalies(result.Proxies))
    fmt.Printf("\n└─ Target URL:        %s", result.URL)
    
    // Rest of the existing print logic...
}

func countAnomalies(proxies []ProxyInfo) int {
    count := 0
    for _, p := range proxies {
        if p.StatusCode != 0 && (p.ContentSim < 0.8 || p.TitleSim < 0.8) {
            count++
        }
    }
    return count
}


func runCheck(ctx context.Context, config Config) Result {
    result := Result{URL: config.TargetURL}
    tracker := &UsedProxyTracker{
        proxies: make(map[string]struct{}),
    }

    totalProxies := 0
    for _, proxies := range config.ProxyList {
        totalProxies += len(proxies)
    }

    progressCtx, cancelProgress := context.WithCancel(ctx)
    defer cancelProgress()

    // Remove local progress variables and use package-level atomics directly
    if !config.Verbose && totalProxies > 0 {
        go func() {
            ticker := time.NewTicker(500 * time.Millisecond)
            defer ticker.Stop()
            
            for {
                select {
                case <-ticker.C:
                    // Use package-level atomic variables directly
                    p := atomic.LoadUint64(&processedProxies)
                    s := atomic.LoadUint64(&successCount)
                    f := atomic.LoadUint64(&failureCount)
                    e := atomic.LoadUint64(&errorCount)
                    
                    width := 20
                    progress := float64(p)/float64(totalProxies)
                    bars := int(progress * float64(width))
                    
                    fmt.Printf("\r[%s%s] %d/%d | ↑%d ↓%d !%d (%.1f%%)",
                        strings.Repeat("█", bars),
                        strings.Repeat("░", width-bars),
                        p, totalProxies, s, f, e,
                        float64(p)/float64(totalProxies)*100)
                        
                case <-progressCtx.Done():
                    fmt.Println()                     
                    return
                }
            }
        }()
    }

        jobs := make(chan Job, 10000)
    results := make(chan ProxyInfo, 10000)
    var wg sync.WaitGroup

        for w := 0; w < config.Threads; w++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for job := range jobs {
                workerCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
                defer cancel()
                
                start := time.Now()
                logVerbose(start, fmt.Sprintf("Worker %d", workerID))
                
                info := checkProxyWithRetry(workerCtx, job.Proxy, config.TargetURL, config.NoPrecheck, job.Retries, tracker, config)
                
                atomic.AddUint64(&processedProxies, 1)
                if info.Status == "UP" {
                    atomic.AddUint64(&successCount, 1)
                    activeProxies.Add(info)
                } else {
                    atomic.AddUint64(&failureCount, 1)
                }
                if info.Status == "INVALID" || info.Status == "MAX_RETRIES" {
                    atomic.AddUint64(&errorCount, 1)
                }
                
                if info.StatusCode != 0 {
                    select {
                    case results <- info:
                    case <-ctx.Done():
                        return
                    }
                }
            }
        }(w)

    }

        go func() {
        defer close(jobs)
        for country := range config.ProxyList {
            for _, proxy := range config.ProxyList[country] {
                cleanProxy := strings.TrimSpace(proxy)
                if !isValidProxy(cleanProxy) || !tracker.MarkUsed(cleanProxy) {
                    continue
                }
                
                select {
                case jobs <- Job{Proxy: cleanProxy, Retries: config.Retries}:
                case <-ctx.Done():
                    return
                }
            }
        }
    }()

        go func() {
        wg.Wait()
        close(results)
    }()

    var success, total int
    for info := range results {
        result.Proxies = append(result.Proxies, info)
        updateDashboardMetrics(info)
        total++
        
        if info.StatusCode >= 200 && info.StatusCode < 400 {
            success++
        }
        
        if config.Verbose {
            printProxyInfo(info)
        }
    }
    fmt.Printf("\nProxy success rate: %d/%d (%.1f%%)\n", 
        success, total, float64(success)/float64(total)*100)

        result.BlockingLevel = determineBlockingLevel(result.Baseline, result.Proxies)
    result.DifferentCountries = analyzeResults(result.Baseline, result.Proxies)
    
    return result
}

func isValidProxy(proxy string) bool {
    host, portStr, err := net.SplitHostPort(proxy)
    if err != nil {
        return false
    }
    // Validate host is not empty (could be DNS name or IP)
    if host == "" {
        return false
    }
    port, err := strconv.Atoi(portStr)
    return err == nil && port > 0 && port <= 65535
}

func bulkCheckProxies(proxies []string, timeout time.Duration) []string {
    valid := make(chan string)
    var wg sync.WaitGroup
    
    for _, proxy := range proxies {
        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            if quickProxyCheck(p, timeout) {
                valid <- p
            }
        }(proxy)
    }
    
    go func() {
        wg.Wait()
        close(valid)
    }()
    
    var alive []string
    for v := range valid {
        alive = append(alive, v)
    }
    return alive
}

func isValidProxyFormat(proxy string) bool {
    parts := strings.Split(proxy, ":")
    if len(parts) != 2 {
        return false
    }
    port := parts[1]
    _, err := strconv.Atoi(port)
    return err == nil && net.ParseIP(parts[0]) != nil
}

func checkProxyWithRetry(ctx context.Context, proxyAddr string, targetURL string,
    noPrecheck bool, retries int, tracker *UsedProxyTracker, config Config) ProxyInfo {
    
    baseDelay := 500 * time.Millisecond
    maxDelay := config.Timeout
    if maxDelay > 5*time.Second {
        maxDelay = 5*time.Second
    }

    for attempt := 0; attempt <= retries; attempt++ {
        // Create per-attempt context with timeout
        attemptCtx, cancel := context.WithTimeout(ctx, config.Timeout)
        defer cancel()

        if _, exists := badProxies.Load(proxyAddr); exists {
            return ProxyInfo{Status: "CACHED_FAIL"}
        }
        
        result := checkProxy(attemptCtx, proxyAddr, targetURL, config)
        
        // Don't retry successful or invalid proxies
        if result.Status == "UP" || result.Status == "INVALID" {
            return result
        }

        if attempt < retries {
            // Exponential backoff with jitter
            delay := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
            if delay > maxDelay {
                delay = maxDelay
            }
            delay += time.Duration(rand.Int63n(500)) * time.Millisecond
            
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return ProxyInfo{Status: "CANCELLED"}
            }
        }
    }
    
    return ProxyInfo{Status: "MAX_RETRIES"}
}


func cachedLookup(ctx context.Context, host string) (string, error) {
    start := time.Now()
    defer logVerbose(start, "DNS Lookup")
        if ip := net.ParseIP(host); ip != nil {
        return host, nil
    }

    dnsCache.RLock()
    if ip, ok := dnsCache.m[host]; ok {
        dnsCache.RUnlock()
        return ip, nil
    }
    dnsCache.RUnlock()

        ips, err := net.LookupIP(host)
    if err != nil {
        return "", err
    }

        var result string
    for _, ip := range ips {
        if ip.To4() != nil {
            result = ip.String()
            break
        }
    }
    if result == "" && len(ips) > 0 {
        result = ips[0].String()
    }

    dnsCache.Lock()
    dnsCache.m[host] = result
    dnsCache.Unlock()

    return result, nil
}

func getCountryWithCache(ctx context.Context, ip string) (string, error) {
    geoCache.RLock()
    if country, ok := geoCache.m[ip]; ok {
        geoCache.RUnlock()
        return country, nil
    }
    geoCache.RUnlock()

    results, err := ip2locationDB.Get_all(ip)
    if err != nil {
        return "", err
    }
    
    geoCache.Lock()
    geoCache.m[ip] = results.Country_short
    geoCache.Unlock()
    
    return results.Country_short, nil
}

func checkProxy(ctx context.Context, proxyAddr string, targetURL string, config Config) ProxyInfo {
    if _, exists := badProxies.Load(proxyAddr); exists {
        return ProxyInfo{Status: "CACHED_FAIL"}
    }

    info := ProxyInfo{Address: proxyAddr}
    start := time.Now()
    defer func() {
        if !strings.Contains(info.Status, "UP") {
            badProxies.Store(proxyAddr, true)
        }
        logProxyAttempt(proxyAddr, start, strings.Contains(info.Status, "UP"))
    }()

    target, err := url.Parse(targetURL)
    if err != nil {
        info.Status = "INVALID_URL"
        return info
    }

    deadline, ok := ctx.Deadline()
    if !ok {
        deadline = time.Now().Add(config.Timeout)
    }
    remaining := time.Until(deadline)

    client := &fasthttp.Client{
        ReadTimeout:  remaining,
        WriteTimeout: remaining,
        Dial: func(addr string) (net.Conn, error) {
            // Phase 1: TCP Connection with aggressive timeout
            conn, err := fasthttp.DialTimeout(proxyAddr, 2*time.Second)
            if err != nil {
                return nil, fmt.Errorf("TCP dial failed: %w", err)
            }

            if target.Scheme == "https" {
                // Get proper host:port for CONNECT
                host := target.Hostname()
                port := target.Port()
                if port == "" {
                    port = "443"
                }
                connectTarget := net.JoinHostPort(host, port)

                // Phase 2: CONNECT Request
                connectDeadline := time.Now().Add(3 * time.Second)
                conn.SetWriteDeadline(connectDeadline)
                
                connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", 
                    connectTarget, connectTarget)
                
                if _, err := conn.Write([]byte(connectReq)); err != nil {
                    conn.Close()
                    return nil, fmt.Errorf("CONNECT write failed: %w", err)
                }

                // Phase 3: CONNECT Response
                conn.SetReadDeadline(connectDeadline.Add(1 * time.Second))
                br := bufio.NewReader(conn)
                resp, err := http.ReadResponse(br, nil)
                if err != nil {
                    conn.Close()
                    return nil, fmt.Errorf("CONNECT read failed: %w", err)
                }
                if resp.StatusCode != 200 {
                    conn.Close()
                    return nil, fmt.Errorf("bad CONNECT status: %d", resp.StatusCode)
                }

                // Phase 4: TLS Handshake
                tlsConfig := &tls.Config{
                    ServerName: host, // Use original target hostname
                    MinVersion: tls.VersionTLS12,
                }
                tlsConn := tls.Client(conn, tlsConfig)
                handshakeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
                defer cancel()
                
                if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
                    tlsConn.Close()
                    return nil, fmt.Errorf("TLS handshake failed: %w", err)
                }

                // Phase 5: Set final deadline for HTTPS connection
                tlsConn.SetDeadline(time.Now().Add(remaining - 5*time.Second))
                return tlsConn, nil
            }
            
            // For HTTP, set final deadline
            conn.SetDeadline(time.Now().Add(remaining))
            return conn, nil
        },
    }

    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer func() {
        fasthttp.ReleaseRequest(req)
        fasthttp.ReleaseResponse(resp)
    }()

    req.SetRequestURI(targetURL)
    req.Header.SetMethod(fasthttp.MethodGet)
    req.Header.Set("Host", target.Host)
    req.Header.SetUserAgent("Mozilla/5.0 (compatible; zgeo-proxy-checker/1.0)")

    // Get proxy metadata
    if host, _, err := net.SplitHostPort(proxyAddr); err == nil {
        if geo, err := getCountryWithCache(ctx, host); err == nil {
            info.Country = geo
        }
    }

    err = client.DoTimeout(req, resp, remaining)
    if err != nil {
        info.Status = "DOWN"
        info.StatusCode = 0
        return info
    }

    info.StatusCode = resp.StatusCode()
    info.Protocol = target.Scheme
    if location := resp.Header.Peek("Location"); len(location) > 0 {
        info.Location = string(location)
    }

    if info.StatusCode >= 200 && info.StatusCode < 400 {
        info.Status = "UP"
        
        if baselineContent != "" {
            body := resp.Body()
            if strings.Contains(string(resp.Header.ContentType()), "text/html") {
                info.Title = extractTitle(body)
                
                proxyContent := string(body)
                proxyTagCounts := extractTagCounts(proxyContent)
                info.ContentSim = calculateTagSimilarity(baselineTagCounts, proxyTagCounts)
                info.TitleSim = calculateSimilarity(info.Title, baselineTitle)
            }
        }
    } else {
        info.Status = fmt.Sprintf("DOWN (%d)", info.StatusCode)
    }

    return info
}


func normalizeContent(s string) string {
        return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func calculateSimilarity(s1, s2 string) float64 {
    start := time.Now()
    defer logVerbose(start, "Content Compare")
    
    if s1 == "" && s2 == "" {
        return 1.0
    }
    if s1 == "" || s2 == "" {
        return 0.0
    }
    
        if len(s1) < 1000 && len(s2) < 1000 {
        distance := levenshtein.DistanceForStrings([]rune(s1), []rune(s2), levenshtein.DefaultOptions)
        maxLength := math.Max(float64(len(s1)), float64(len(s2)))
        similarity := 1.0 - float64(distance)/maxLength
        return math.Max(similarity, 0.0)     }
    
        words1 := strings.Fields(s1)
    words2 := strings.Fields(s2)
    
    freq1 := make(map[string]int)
    freq2 := make(map[string]int)
    
    for _, word := range words1 { freq1[word]++ }
    for _, word := range words2 { freq2[word]++ }
    
    commonWords := 0
    for word, count1 := range freq1 {
        count2 := freq2[word]
        commonWords += min(count1, count2)
    }
    
    totalWords := len(words1) + len(words2)
    if totalWords == 0 {
        return 0.0
    }
    
    return 2.0 * float64(commonWords) / float64(totalWords)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func blockingLevelDescription(level int) string {
    return map[int]string{
        0: "Consistent Global Access",
        1: "Regional Behavior Variations",
        2: "Partial Service Restrictions",
        3: "Widespread Access Issues",
    }[level]
}

func determineBlockingLevel(baseline ProxyInfo, proxies []ProxyInfo) int {
    if len(proxies) == 0 {
        return 0 // No proxies to compare
    }

    baselineAccessible := baseline.StatusCode >= 200 && baseline.StatusCode < 400
    totalCountries := make(map[string]bool)
    blockedCountries := make(map[string]bool)

    for _, proxy := range proxies {
        totalCountries[proxy.Country] = true
        if proxy.StatusCode != baseline.StatusCode ||
            proxy.ContentSim < 0.8 ||  // Lower threshold for better detection
            proxy.TitleSim < 0.8 {
            blockedCountries[proxy.Country] = true
        }
    }

    if baselineAccessible {
        if len(blockedCountries) > 0 {
            return 1 // Different behavior detected
        }
        return 0 // No blocking detected
    }

    // When baseline is blocked, analyze proxy accessibility
    successfulProxies := 0
    for _, proxy := range proxies {
        if proxy.StatusCode >= 200 && proxy.StatusCode < 400 {
            successfulProxies++
        }
    }

    successRatio := float64(successfulProxies) / float64(len(proxies))
    switch {
    case successRatio == 0:
        return 3 // All access blocked
    case successRatio < 0.3:
        return 3 // Strict blocking
    case successRatio < 0.7:
        return 2 // Partial blocking
    default:
        return 1 // Minimal blocking
    }
}

func analyzeResults(baseline ProxyInfo, proxies []ProxyInfo) map[string][]ProxyInfo {
    countryStats := make(map[string][]ProxyInfo)
    totalCountries := make(map[string]bool)
    
    for _, proxy := range proxies {
        totalCountries[proxy.Country] = true
        sameBehavior := true
        
        if baseline.StatusCode >= 200 && baseline.StatusCode < 400 {
            sameBehavior = proxy.StatusCode == baseline.StatusCode &&
                proxy.ContentSim >= 0.8 &&
                proxy.TitleSim >= 0.8
        } else {
            sameBehavior = !(proxy.Status == "UP" && (proxy.ContentSim < 0.8 || proxy.TitleSim < 0.8))
        }

        if !sameBehavior {
            countryStats[proxy.Country] = append(countryStats[proxy.Country], 
                proxy)
        }
    }

    // Add reporting for total countries tested
    if len(countryStats) > 0 {
        fmt.Printf("\nDifferent behavior detected in %d/%d countries:\n", 
            len(countryStats), len(totalCountries))
        for country := range countryStats {
            fmt.Printf(" - %s\n", country)
        }
    }
    
    return countryStats
}

func countSuccess(proxies []ProxyInfo) int {
    count := 0
    for _, p := range proxies {
        if p.Status == "UP" {
            count++
        }
    }
    return count
}

func truncateString(s string, maxLength int) string {
    if len(s) <= maxLength {
        return s
    }
    return s[:maxLength-3] + "..."
}

func updateDashboardMetrics(info ProxyInfo) {
    dashboard.mu.Lock()
    defer dashboard.mu.Unlock()

    dashboard.TestedProxies++
    if info.Status == "UP" {
        dashboard.SuccessCount++
    } else {
        dashboard.FailureCount++
    }

    if info.StatusCode != 0 && (info.StatusCode != 200 || info.ContentSim < 0.9 || info.TitleSim < 0.9) {
        dashboard.AnomaliesCount++
        dashboard.DifferentCountries[info.Country]++
    }
}

func cleanup() {
    if ip2locationDB != nil {
        ip2locationDB.Close()
    }
}

func loadProxies(proxyFile, jsonFile string) []string {
    start := time.Now()
    defer logVerbose(start, "Load Proxies")
    var proxies []string
    
    addProxy := func(proxy string) {
        proxy = strings.TrimSpace(proxy)
                if proxy == "" || 
           !strings.Contains(proxy, ":") || 
           strings.Count(proxy, ":") != 1 {
            return
        }
        proxies = append(proxies, proxy)
    }

    if proxyFile != "" {
        file, err := os.Open(proxyFile)
        if err == nil {
            defer file.Close()
            scanner := bufio.NewScanner(file)
            for scanner.Scan() {
                addProxy(strings.TrimSpace(scanner.Text()))
            }
        }
    } else if jsonFile != "" {
        file, err := os.Open(jsonFile)
        if err == nil {
            defer file.Close()
            var jsonProxies []struct {
                IP   string `json:"ip"`
                Port string `json:"port"`
            }
            if err := json.NewDecoder(file).Decode(&jsonProxies); err == nil {
                for _, p := range jsonProxies {
                    addProxy(fmt.Sprintf("%s:%s", p.IP, p.Port))
                }
            }
        }
    }
    return proxies
}


func loadProxiesGroupedByCountry(proxyFile, jsonFile string, timeout time.Duration) ProxyMap {
    proxyMap := make(ProxyMap)
    
        proxies := loadProxies(proxyFile, jsonFile)
    if len(proxies) == 0 {
        return proxyMap
    }
    if ip2locationDB == nil {
        fmt.Println("GeoIP database not initialized")
        return proxyMap
    }
        var dnsWg sync.WaitGroup
    dnsSem := make(chan struct{}, 200)
    
    for _, proxy := range proxies {
        dnsWg.Add(1)
        go func(p string) {
            defer dnsWg.Done()
            dnsSem <- struct{}{}
            defer func() { <-dnsSem }()
            
            host, _, _ := net.SplitHostPort(p)
            cachedLookup(context.Background(), host)
        }(proxy)
    }
    dnsWg.Wait()

        verifiedProxies := bulkPreCheck(proxies, timeout)
    fmt.Printf("Pre-check complete: %d/%d proxies alive\n", len(verifiedProxies), len(proxies))

        var geoWg sync.WaitGroup
    geoQueue := make(chan string, len(verifiedProxies))
    results := make(chan struct {
        country string
        proxy   string
    }, len(verifiedProxies))

        for i := 0; i < 200; i++ {
        geoWg.Add(1)
        go func() {
            defer geoWg.Done()
            for proxy := range geoQueue {
                host, _, _ := net.SplitHostPort(proxy)
                ip, _ := cachedLookup(context.Background(), host) // Add context
                
                country, err := getCountryWithCache(context.Background(), ip) // Use context-aware version
                if err != nil {
                    country = "Unknown"
                }
                
                results <- struct {
                    country string
                    proxy   string
                }{country: country, proxy: proxy}
            }
        }()
    }

        go func() {
        for _, p := range verifiedProxies {
            geoQueue <- p
        }
        close(geoQueue)
    }()

        go func() {
        geoWg.Wait()
        close(results)
    }()

        proxyMapMu.Lock()
    defer proxyMapMu.Unlock()
    for res := range results {
        proxyMap[res.country] = append(proxyMap[res.country], res.proxy)
    }

        countries := make([]string, 0, len(proxyMap))
    for country := range proxyMap {
        countries = append(countries, country)
    }
    
    sort.Slice(countries, func(i, j int) bool {
        return len(proxyMap[countries[i]]) > len(proxyMap[countries[j]])
    })

    sortedProxyMap := make(ProxyMap)
    for _, country := range countries {
        sortedProxyMap[country] = proxyMap[country]
    }

    return sortedProxyMap
}

func findAlternativeProxy(country string, usedProxies *UsedProxyTracker, config Config) string {
    for _, proxy := range config.ProxyList[country] {
        if !usedProxies.MarkUsed(proxy) {
            return proxy
        }
    }
    return ""
}



func saveFreshProxies(proxies []ProxyInfo) {
    now := time.Now()
    filename := fmt.Sprintf("fresh_proxies_%s.json", now.Format("20060102_1504"))
    
    type FreshProxy struct {
        IP        string  `json:"ip"`
        Port      string  `json:"port"`
        Country   string  `json:"country"`
        Protocol  string  `json:"protocol"`
        Success   bool    `json:"success"`
        Score     float64 `json:"score"`
    }

    var freshProxies []FreshProxy
    totalUp := 0
    baselineValid := dashboard.Baseline.StatusCode >= 200 && dashboard.Baseline.StatusCode < 400 &&
                    len(baselineContent) > 0 && baselineTitle != ""

    if *vFlag {
        fmt.Printf("\nSaving fresh proxies... (Baseline valid: %v)\n", baselineValid)
    }

    for _, proxy := range proxies {
        if proxy.Status != "UP" {
            continue
        }
        totalUp++

        host, port, err := net.SplitHostPort(proxy.Address)
        if err != nil {
            continue
        }

        var score float64
        var success bool
        
        if baselineValid {
            score = (proxy.ContentSim + proxy.TitleSim) / 2
            success = score >= 0.8
        } else {
            score = 1.0
            success = true
        }

        freshProxies = append(freshProxies, FreshProxy{
            IP:        host,
            Port:      port,
            Country:   proxy.Country,
            Protocol:  proxy.Protocol,
            Success:   success,
            Score:     math.Round(score*100)/100,
        })
    }

    // Actually write to file
    file, err := os.Create(filename)
    if err != nil {
        if *vFlag {
            fmt.Printf("Error creating fresh proxies file: %v\n", err)
        }
        return
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(freshProxies); err != nil {
        if *vFlag {
            fmt.Printf("Error encoding fresh proxies: %v\n", err)
        }
        return
    }

    if *vFlag {
        fmt.Printf("Saved %d/%d UP proxies to %s (Baseline valid: %v)\n",
            len(freshProxies), totalUp, filename, baselineValid)
    }
}

func runMassiveCheck(ctx context.Context, config Config) []Result {
    file, err := os.Open(config.TargetWordlist)
    if err != nil {
        fmt.Printf("Error opening target wordlist: %v\n", err)
        return nil
    }
    defer file.Close()

    var results []Result
    totalURLs := 0
    processedURLs := 0

        scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if strings.TrimSpace(scanner.Text()) != "" {
            totalURLs++
        }
    }
    file.Seek(0, 0)
    scanner = bufio.NewScanner(file)

        jobs := make(chan string, 100)
    resultsChan := make(chan Result, 10)
    var wg sync.WaitGroup

        for w := 0; w < config.Threads; w++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for url := range jobs {
                select {
                case <-ctx.Done():
                    return
                default:
                    configCopy := config
                    configCopy.TargetURL = url
                    result := runCheck(ctx, configCopy)
                    resultsChan <- result
                }
            }
        }(w)
    }

        go func() {
        defer close(jobs)
        for scanner.Scan() {
            url := strings.TrimSpace(scanner.Text())
            if url == "" {
                continue
            }
            
            select {
            case jobs <- url:
            case <-ctx.Done():
                return
            }
        }
    }()

        go func() {
        wg.Wait()
        close(resultsChan)
    }()

        startTime := time.Now()
    for result := range resultsChan {
        processedURLs++
        
                if time.Since(startTime) > 5*time.Second || processedURLs == totalURLs {
            fmt.Printf("\rProgress: [%-50s] %d/%d URLs checked (%.1f%%)",
                strings.Repeat("=", int(float64(processedURLs)/float64(totalURLs)*50)),
                processedURLs,
                totalURLs,
                float64(processedURLs)/float64(totalURLs)*100,
            )
            startTime = time.Now()
        }

        results = append(results, result)
        
                select {
        case <-ctx.Done():
            return results
        default:
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("\nError reading wordlist: %v\n", err)
    }

    fmt.Println("\nMassive check completed")
    return results
}

var (
    timeout        = flag.Duration("timeout", 5*time.Second, "Timeout for proxy connections")
    dbFile              = flag.String("db", "IP2LOCATION-LITE-DB1.BIN", "Path to IP2Location DB")
    proxiesFile         = flag.String("w", "", "Proxy list file")
    jsonWordlist        = flag.String("jw", "", "JSON proxy list")
    targetWordlist      = flag.String("tw", "", "Target URL list")
    threads             = flag.Int("t", 50, "Number of threads")
    targetURL           = flag.String("u", "", "Target URL")
    vFlag               = flag.Bool("v", false, "Verbose mode")
    noPrecheck          = flag.Bool("np", false, "Disable proxy precheck")
    upOnly              = flag.Bool("up", false, "Show only working proxies")
    freshProxyOut       = flag.Bool("fpo", false, "Output fresh proxies")
    oneAttemptPerCountry= flag.Bool("oa", false, "One attempt per country")
    retries             = flag.Int("r", 3, "Number of retries")
    outputFormat        = flag.String("o", "json", "Output format")
)

var (
    httpClient      *http.Client
    clientPool      *sync.Pool
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    setupSignalHandler(cancel)
    
    // Parse command line flags
    flag.Parse()
    
    // Initialize configuration
    config := Config{
        Timeout:            *timeout,
        ProxiesFile:        *proxiesFile,
        JSONWordlist:       *jsonWordlist,
        TargetURL:          *targetURL,
        Threads:            *threads,
        Verbose:            *vFlag,
        NoPrecheck:         *noPrecheck,
        OutputFormat:       *outputFormat,
        Retries:            *retries,
        OneAttemptPerCountry: *oneAttemptPerCountry,
    }

    // Initialize GeoIP database
    var err error
    ip2locationDB, err = ip2location.OpenDB(*dbFile)
    if err != nil {
        log.Fatalf("Failed to initialize GeoIP database: %v", err)
    }
    defer ip2locationDB.Close()

    // Load and verify proxies
    proxyMap := loadProxiesGroupedByCountry(config.ProxiesFile, config.JSONWordlist, config.Timeout)
    if len(proxyMap) == 0 {
        log.Fatal("No valid proxies found")
    }
    config.ProxyList = proxyMap

    // Establish baseline connection
    baselineInfo, baseContent, baseTitle := getBaseline(config.TargetURL)
    dashboard.Baseline = baselineInfo
    dashboard.StartTime = time.Now()
    dashboard.DifferentCountries = make(map[string]int)

    if baselineInfo.StatusCode == 0 {
        log.Println("⚠️  Baseline connection failed - comparison metrics disabled")
    } else {
        baselineContent = baseContent
        baselineTitle = baseTitle
        baselineTagCounts = extractTagCounts(baselineContent)
    }

    // Run checks
    var allResults AllResults
    allResults.StartTime = dashboard.StartTime

    result := runCheck(ctx, config)
    result.LocalCountry = baselineInfo.Country // Set LocalCountry from baseline
    allResults.Results = []Result{result}
    
    // Generate output
    allResults.EndTime = time.Now()
    switch config.OutputFormat {
    case "html":
        saveHTMLReport(allResults)
    case "json":
        saveImprovedJSON(improveJSONOutput(allResults.Results))
    default:
        printResults(result, config.UpOnly)
    }

    // Final output
    fmt.Println(generateSummaryReport(allResults.Results))
    
    if config.FreshProxyOut {
        saveFreshProxies(activeProxies.GetAll())
    }
}


// Signal handler setup
func setupSignalHandler(cancel context.CancelFunc) {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\n🛑 Received termination signal - shutting down...")
        cancel()
    }()
}

func shouldRetry(status string) bool {
    return status == "DOWN" || status == "TIMEOUT"
}

func logVerbose(start time.Time, operation string) {
    if verboseLogger != nil {
        elapsed := time.Since(start)
        verboseLogger.Printf("%-15s %v", operation, elapsed)
    }
}

func logProxyAttempt(proxy string, start time.Time, success bool) {
    if verboseLogger != nil {
        status := "OK"
        if !success {
            status = "FAIL"
        }
        verboseLogger.Printf("%-15s %-20s %v", 
            "PROXY", 
            status,
            time.Since(start),
        )
    }
}

func checkFreshProxyAge() {
    files, _ := filepath.Glob("fresh_proxies_*.json")
    now := time.Now()
    
    for _, f := range files {
        tsStr := strings.TrimSuffix(strings.TrimPrefix(f, "fresh_proxies_"), ".json")
        fileTime, err := time.Parse("20060102_1504", tsStr)
        if err == nil && now.Sub(fileTime) < time.Hour {
            return
        }
    }
    
    fmt.Println("\nTip: No fresh proxies found from last hour. Run with -fpo next time to cache working proxies.")
}

func improveJSONOutput(results []Result) map[string]interface{} {
    output := make(map[string]interface{})
    output["total_urls"] = len(results)
    output["blocked_urls"] = 0
    output["total_proxies"] = 0
    output["blocked_proxies"] = 0
    countriesBlocked := make(map[string]int)
    
    var detailedResults []map[string]interface{}
    
    for _, result := range results {
        detailedResult := make(map[string]interface{})
        detailedResult["url"] = result.URL
        detailedResult["blocking_level"] = result.BlockingLevel
        detailedResult["different_countries"] = result.DifferentCountries
        
        if result.BlockingLevel > 0 {
            output["blocked_urls"] = output["blocked_urls"].(int) + 1
        }
        
        output["total_proxies"] = output["total_proxies"].(int) + len(result.Proxies)
        
        for country, proxies := range result.DifferentCountries {
            countriesBlocked[country] += len(proxies)
            output["blocked_proxies"] = output["blocked_proxies"].(int) + len(proxies)
        }
        
        detailedResults = append(detailedResults, detailedResult)
    }
    
    output["countries_blocked"] = countriesBlocked
    output["detailed_results"] = detailedResults
    
    return output
}

func saveImprovedJSON(data map[string]interface{}) {
    filename := fmt.Sprintf("improved_geo_blocking_results_%d.json", time.Now().Unix())
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("Error creating improved JSON file: %v\n", err)
        return
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(data); err != nil {
        fmt.Printf("Error encoding improved JSON: %v\n", err)
    } else {
        fmt.Printf("Improved results saved to %s\n", filename)
    }
}

func generateSummaryReport(results []Result) string {
    var summary strings.Builder
    summary.WriteString("=== Network Behavior Analysis Summary ===\n\n")

    totalURLs := len(results)
    differentBehavior := 0
    totalProxies := 0
    totalDifferent := 0

    for _, result := range results {
        if result.BlockingLevel > 0 {
            differentBehavior++
        }
        totalProxies += len(result.Proxies)
        for _, proxies := range result.DifferentCountries {
            totalDifferent += len(proxies)
        }
    }

    summary.WriteString(fmt.Sprintf("Total analyzed URLs: %d\n", totalURLs))
    summary.WriteString(fmt.Sprintf("URLs with different proxy behavior: %d (%.1f%%)\n",
        differentBehavior, float64(differentBehavior)/float64(totalURLs)*100))
    summary.WriteString(fmt.Sprintf("Total proxies analyzed: %d\n", totalProxies))
    summary.WriteString(fmt.Sprintf("Proxies with different behavior: %d (%.1f%%)\n",
        totalDifferent, float64(totalDifferent)/float64(totalProxies)*100))

    return summary.String()
}

func bulkPreCheck(proxies []string, timeout time.Duration) []string {
    sem := make(chan struct{}, 50)
    validProxies := make(chan string, len(proxies))
    var wg sync.WaitGroup

    for _, proxy := range proxies {
        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            if quickProxyCheck(p, timeout) {
                validProxies <- p
            }
        }(proxy)
    }

    go func() {
        wg.Wait()
        close(validProxies)
    }()

    var alive []string
    for p := range validProxies {
        alive = append(alive, p)
    }
    return alive
}

var (
    processedProxies uint64
    successCount     uint64
    failureCount     uint64
    errorCount       uint64
)

func startProgressUpdater(total int, ctx context.Context) {
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                p := atomic.LoadUint64(&processedProxies)
                s := atomic.LoadUint64(&successCount)
                f := atomic.LoadUint64(&failureCount)
                e := atomic.LoadUint64(&errorCount)
                
                width := 20
                percent := float64(p)/float64(total)
                bars := int(percent * float64(width))
                
                fmt.Printf("\r[%s] %d/%d | ↑%d ↓%d !%d", 
                    strings.Repeat("=", bars) + strings.Repeat(" ", width-bars),
                    p, total, s, f, e)
                
            case <-ctx.Done():
                return
            }
        }
    }()
}

func getLocalCountry() string {
    services := []string{
        "https://api.ipify.org?format=text",
        "https://ident.me",
        "https://ifconfig.me/ip",
    }

    var ip string
    var lastErr error
    
    for _, service := range services {
        resp, err := http.Get(service)
        if err == nil {
            defer resp.Body.Close()
            body, _ := io.ReadAll(resp.Body)
            ip = strings.TrimSpace(string(body))
            if net.ParseIP(ip) != nil {
                break
            }
        }
        lastErr = err
    }

    if ip == "" {
        fmt.Printf("\n⚠️ IP detection failed (Last error: %v)\n", lastErr)
        return "Unknown Location"
    }

    country, err := getCountry(ip)
    if err != nil {
        fmt.Printf("\n⚠️ GeoIP lookup failed for %s: %v\n", ip, err)
        return "Location Unknown"
    }
    
    if record, err := ip2locationDB.Get_all(ip); err == nil {
        return fmt.Sprintf("%s (%s)", record.Country_long, record.Country_short)
    }
    
    return country
}

func downloadProxies() bool {
    fmt.Print("\nNo proxy list found. Download default proxies? (y/n): ")
    var response string
    fmt.Scanln(&response)
    
    if strings.ToLower(response) == "y" {
        resp, err := http.Get("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt")
        if err != nil {
            fmt.Println("Download failed:", err)
            return false
        }
        defer resp.Body.Close()
        
        file, err := os.Create("http.txt")
        if err != nil {
            fmt.Println("Error creating file:", err)
            return false
        }
        defer file.Close()
        
        _, err = io.Copy(file, resp.Body)
        if err != nil {
            fmt.Println("Download failed:", err)
            return false
        }
        fmt.Println("Downloaded proxies to http.txt")
        return true
    }
    return false
}


func sortMapByValue(m map[string]int) []string {
    type kv struct {
        Key   string
        Value int
    }
    var ss []kv
    for k, v := range m {
        ss = append(ss, kv{k, v})
    }
    sort.Slice(ss, func(i, j int) bool {
        return ss[i].Value > ss[j].Value
    })
    sorted := make([]string, len(ss))
    for i, kv := range ss {
        sorted[i] = kv.Key
    }
    return sorted
}
