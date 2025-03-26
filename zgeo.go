package main

import (
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
	"github.com/valyala/fasthttp/fasthttpproxy"
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
    httpClient      = &http.Client{
        Transport: &http.Transport{
            MaxIdleConnsPerHost: 100,
            MaxConnsPerHost:     500,
            IdleConnTimeout:     90 * time.Second,
        },
        Timeout: 10 * time.Second,
    }
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
    CountriesBlocked map[string]int
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
    Proxies          []ProxyInfo
    BlockingLevel    int
    BlockedCountries map[string][]string
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


var clientPool = sync.Pool{
    New: func() interface{} {
        return &fasthttp.Client{
            ReadTimeout:  3 * time.Second,
            WriteTimeout: 3 * time.Second,
            Dial: func(addr string) (net.Conn, error) {
                return fasthttp.DialTimeout(addr, 2*time.Second)
            },
        }
    },
}

var htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geo-Blocking Analysis Report</title>
    <style>
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
        <p>Total blocked proxies: {{.BlockedProxies}}</p>
    </div>
    {{range .Results}}
    <div class="result-container">
        <h2>Results for {{.URL}}</h2>
        <p><strong>Blocking Level:</strong> {{.BlockingLevel}}</p>
        <p><strong>Total Proxies Tested:</strong> {{len .Proxies}}</p>
        <p><strong>Successful Accesses:</strong> {{countSuccess .Proxies}}</p>
        
        <h3>Countries with Different Behavior</h3>
        <table class="sortable">
            <thead>
                <tr>
                    <th>Country</th>
                    <th>Proxies with Different Behavior</th>
                </tr>
            </thead>
            <tbody>
                {{range $country, $proxies := .BlockedCountries}}
                    <tr>
                        <td>{{$country}}</td>
                        <td>{{len $proxies}}</td>
                    </tr>
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
            <th>Title</th>
        </tr>
    </thead>
    <tbody>
        {{$baseline := .Baseline}}
        {{$commonStatus := mostCommonStatus .Proxies}}
        {{range .Proxies}}
            {{if ne .StatusCode 0}}
                {{if or (ne .StatusCode $baseline.StatusCode) (lt .ContentSim 0.9) (lt .TitleSim 0.9)}}
                    <tr class="{{if and (ne .StatusCode $baseline.StatusCode) (ne .StatusCode $commonStatus)}}unique-behavior{{else}}different-behavior{{end}}">
                        <td>{{.Address}}</td>
                        <td>{{.Country}}</td>
                        <td>
                            {{.StatusCode}}
                            {{if ne .StatusCode $baseline.StatusCode}}
                                <span class="highlight">(Baseline: {{$baseline.StatusCode}})</span>
                            {{end}}
                            {{if and (ne .StatusCode $baseline.StatusCode) (ne .StatusCode $commonStatus)}}
                                <span class="highlight">(Common: {{$commonStatus}})</span>
                            {{end}}
                        </td>
                        <td>{{printf "%.2f" .ContentSim}}{{if lt .ContentSim 0.9}}<span class="highlight">*</span>{{end}}</td>
                        <td>{{printf "%.2f" .TitleSim}}{{if lt .TitleSim 0.9}}<span class="highlight">*</span>{{end}}</td>
                        <td>{{truncateString .Title 50}}</td>
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

func determineProxyProtocol(proxyAddr string) string {
    conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
    if err != nil {
        return "unknown"
    }
    defer conn.Close()

    _, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
    if err != nil {
        return "unknown"
    }

    buffer := make([]byte, 1024)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
            country, err := getCountry(host)
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
        "truncateString": truncateString,
        "countSuccess": countSuccess,
        "mostCommonStatus": mostCommonStatus,
    }

    tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
    if err != nil {
        fmt.Printf("Error parsing HTML template: %v\n", err)
        return
    }

    debugInfo := fmt.Sprintf("Number of results: %d\n", len(allResults.Results))
    for i, result := range allResults.Results {
        debugInfo += fmt.Sprintf("Result %d:\n", i)
        debugInfo += fmt.Sprintf("  URL: %s\n", result.URL)
        debugInfo += fmt.Sprintf("  Number of proxies: %d\n", len(result.Proxies))
        if len(result.Proxies) > 0 {
            debugInfo += fmt.Sprintf("  First proxy Address: %s\n", result.Proxies[0].Address)
            debugInfo += fmt.Sprintf("  First proxy Country: %s\n", result.Proxies[0].Country)
        } else {
            debugInfo += "  No proxies in this result\n"
        }
        debugInfo += fmt.Sprintf("  All proxies:\n")
        for j, proxy := range result.Proxies {
            debugInfo += fmt.Sprintf("    Proxy %d: Address: %s, Country: %s\n", j, proxy.Address, proxy.Country)
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
        Results:   allResults.Results,
        StartTime: allResults.StartTime,
        EndTime:   allResults.EndTime,
        DebugInfo: debugInfo,
    }


    for _, result := range data.Results {
        if result.BlockingLevel > 0 {
            data.BlockedURLs++
        }
        data.TotalProxies += len(result.Proxies)
        for _, proxies := range result.BlockedCountries {
            data.BlockedProxies += len(proxies)
        }
    }

    err = tmpl.Execute(f, data)
    if err != nil {
        fmt.Printf("Error executing HTML template: %v\n", err)
        return
    }

    fmt.Printf("HTML report saved to %s\n", filename)
}

func quickProxyCheck(proxyAddr string) bool {
    conn, err := net.DialTimeout("tcp", proxyAddr, 500*time.Millisecond)
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
        resp, err := httpClient.Get(url)
    if err != nil {
        return ProxyInfo{}, "", ""
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return ProxyInfo{}, "", ""
    }

    info := ProxyInfo{
        Status:     "UP",
        StatusCode: resp.StatusCode,
    }
    title := extractTitle(body)
    baselineTagCounts = extractTagCounts(string(body))     
    return info, string(body), title
}

func printProxyInfo(info ProxyInfo) {
    fmt.Printf("%-21s %-6s %-7s %-10d %-15.2f %-15.2f %-30s\n",
        fmt.Sprintf("%s (%s)", info.Address, info.Protocol),
        info.Status,
        info.Country,
        info.StatusCode,
        info.ContentSim,
        info.TitleSim,
        truncateString(info.Title, 30))
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
    
        var processed uint64
    var success, failure, errors uint64
    progressCtx, cancelProgress := context.WithCancel(ctx)
    defer cancelProgress()
    
        if !config.Verbose && totalProxies > 0 {
        go func() {
            ticker := time.NewTicker(500 * time.Millisecond)
            defer ticker.Stop()
            
            for {
                select {
                case <-ticker.C:
                    p := atomic.LoadUint64(&processed)
                    s := atomic.LoadUint64(&success)
                    f := atomic.LoadUint64(&failure)
                    e := atomic.LoadUint64(&errors)
                    
                                        width := 20
                    progress := float64(p)/float64(totalProxies)
                    bars := int(progress * float64(width))
                    
                    fmt.Printf("\r[%s] %d/%d ↑%d ↓%d !%d",
                        strings.Repeat("=", bars) + strings.Repeat(" ", width-bars),
                        p, totalProxies, s, f, e)
                        
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
            start := time.Now()
            logVerbose(start, fmt.Sprintf("Worker %d", workerID))
                    select {
                case <-ctx.Done():
                    return
                default:
                    info := checkProxyWithRetry(ctx, job.Proxy, config.TargetURL, config.NoPrecheck, job.Retries, tracker, config)
                        
                                        atomic.AddUint64(&processedProxies, 1)
                    if info.Status == "UP" {
                        atomic.AddUint64(&successCount, 1)
                    } else {
                        atomic.AddUint64(&failureCount, 1)
                    }
                    if info.Status == "INVALID" || info.Status == "MAX_RETRIES" {
                        atomic.AddUint64(&errorCount, 1)
                    }
                    
                    if info.StatusCode != 0 {
                        results <- info
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

        for info := range results {
        result.Proxies = append(result.Proxies, info)
        updateDashboardMetrics(info)
        
        if config.Verbose {
            printProxyInfo(info)
        }
    }

        result.BlockingLevel = determineBlockingLevel(result.Baseline, result.Proxies)
    result.BlockedCountries = analyzeResults(result.Baseline, result.Proxies)
    
    return result
}

func isValidProxy(proxy string) bool {
    parts := strings.Split(proxy, ":")
    if len(parts) != 2 {
        return false
    }
    port, err := strconv.Atoi(parts[1])
    return err == nil && port > 0 && port <= 65535
}

func bulkCheckProxies(proxies []string, timeout time.Duration) []string {
    valid := make(chan string)
    var wg sync.WaitGroup
    
    for _, proxy := range proxies {
        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            if quickProxyCheck(p) {
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
    
    maxRetries := config.Retries
    baseDelay := 500 * time.Millisecond
    maxDelay := 5 * time.Second
    
    for attempt := 0; attempt <= maxRetries; attempt++ {
                if _, exists := badProxies.Load(proxyAddr); exists {
            return ProxyInfo{Status: "CACHED_FAIL"}
        }
        
        result := checkProxy(proxyAddr, targetURL, config)
        
                if result.Status == "UP" || result.Status == "INVALID" {
            return result
        }

        if attempt < maxRetries {
                        delay := baseDelay * time.Duration(1<<attempt)
            if delay > maxDelay {
                delay = maxDelay
            }
            delay += time.Duration(rand.Intn(500)) * time.Millisecond
            
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return ProxyInfo{Status: "CANCELLED"}
            }
        }
    }
    
    return ProxyInfo{Status: "MAX_RETRIES"}
}


func cachedLookup(host string) (string, error) {
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

func getCountryWithCache(ip string) (string, error) {
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


func checkProxy(proxyAddr string, targetURL string, config Config) ProxyInfo {
        if _, exists := badProxies.Load(proxyAddr); exists {
        return ProxyInfo{Status: "CACHED_FAIL"}
    }

    info := ProxyInfo{Address: proxyAddr}
    start := time.Now()
    
    defer func() {
        if info.Status != "UP" {
            badProxies.Store(proxyAddr, true)
        }
        logProxyAttempt(proxyAddr, start, info.Status == "UP")
    }()

        cleanAddr := strings.TrimPrefix(strings.TrimPrefix(proxyAddr, "http://"), "https://")
    host, port, err := net.SplitHostPort(cleanAddr)
    if err != nil {
        info.Status = "INVALID"
        return info
    }

        ip, err := cachedLookup(host)
    if err != nil {
        info.Status = "DNS_FAIL"
        return info
    }

        country, err := getCountryWithCache(ip)
    if err != nil {
        info.Country = "Unknown"
    } else {
        info.Country = country
    }

        info.Protocol = determineProxyProtocol(net.JoinHostPort(ip, port))
    if info.Protocol == "unknown" {
        info.Status = "PROTO_FAIL"
        return info
    }

        client := clientPool.Get().(*fasthttp.Client)
    defer clientPool.Put(client)
    
        client.Dial = fasthttpproxy.FasthttpHTTPDialerTimeout(
        cleanAddr, 
        3*time.Second,
    )

    req := fasthttp.AcquireRequest()
    defer fasthttp.ReleaseRequest(req)
    req.SetRequestURI(targetURL)

    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseResponse(resp)

        err = client.Do(req, resp)
    if err != nil || resp.StatusCode() >= 400 {
        info.Status = "DOWN"
        info.StatusCode = 0
        return info
    }

        info.Status = "UP"
    info.StatusCode = resp.StatusCode()
    
        if resp.StatusCode() == 200 {
        body := resp.Body()
        proxyContent := string(body)
        proxyTagCounts := extractTagCounts(proxyContent)
        info.ContentSim = calculateTagSimilarity(baselineTagCounts, proxyTagCounts)
        info.Title = extractTitle(body)
        info.TitleSim = calculateSimilarity(info.Title, baselineTitle)
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

func determineBlockingLevel(baseline ProxyInfo, proxies []ProxyInfo) int {
    if len(proxies) == 0 {
        return 0     }

    baselineAccessible := baseline.StatusCode == 200
    matchingBehavior := 0
    differentBehavior := 0

    for _, proxy := range proxies {
        if proxy.StatusCode == baseline.StatusCode &&
            proxy.ContentSim >= 0.9 &&
            proxy.TitleSim >= 0.9 {
            matchingBehavior++
        } else {
            differentBehavior++
        }
    }

    if baselineAccessible {
        if differentBehavior > 0 {
                        return 1
        }
                return 0
    }

        accessibleProxies := 0
    for _, proxy := range proxies {
        if proxy.StatusCode == 200 {
            accessibleProxies++
        }
    }

    if accessibleProxies == 0 {
        return 3     }

    blockingPercentage := float64(accessibleProxies) / float64(len(proxies))
    if blockingPercentage <= 0.5 {
        return 3     }
    return 2 }

func analyzeResults(baseline ProxyInfo, proxies []ProxyInfo) map[string][]string {
    differentBehavior := make(map[string][]string)
    statusCounts := make(map[int]int)
    
    for _, proxy := range proxies {
        statusCounts[proxy.StatusCode]++
    }

    for _, proxy := range proxies {
        sameBehavior := proxy.StatusCode == baseline.StatusCode &&
            proxy.ContentSim >= 0.9 &&
            proxy.TitleSim >= 0.9

        if !sameBehavior {
            differentBehavior[proxy.Country] = append(differentBehavior[proxy.Country], 
                fmt.Sprintf("%s (%s)", proxy.Address, proxy.Protocol))
        }
    }

    return differentBehavior
}

func printResults(result Result, upOnly bool) {
    fmt.Printf("\n=== Final Results for %s ===\n", result.URL)
    fmt.Printf("Blocking Level: %d\n", result.BlockingLevel)
    
    if len(result.BlockedCountries) > 0 {
        fmt.Printf("Blocked Countries (%d):\n", len(result.BlockedCountries))
        for country, proxies := range result.BlockedCountries {
            fmt.Printf("  - %s: %d proxies\n", country, len(proxies))
        }
    } else {
        fmt.Println("No country-based blocking detected")
    }
    
    fmt.Printf("\nTotal Proxies Tested: %d\n", len(result.Proxies))
    fmt.Printf("Successful Accesses: %d\n", countSuccess(result.Proxies))

    fmt.Println("\nProxies with Different Behavior:")
    for _, proxy := range result.Proxies {
        if proxy.StatusCode != 0 && (proxy.StatusCode != result.Baseline.StatusCode || proxy.ContentSim < 0.9 || proxy.TitleSim < 0.9) {
            fmt.Printf("  Proxy: %s (%s) [%s]\n", proxy.Address, proxy.Country, proxy.Protocol)
            fmt.Printf("    Status Code: %d (Baseline: %d)\n", proxy.StatusCode, result.Baseline.StatusCode)
            fmt.Printf("    Content Similarity: %.2f\n", proxy.ContentSim)
            fmt.Printf("    Title Similarity: %.2f\n", proxy.TitleSim)
            fmt.Printf("    Title: %s\n", truncateString(proxy.Title, 50))
            fmt.Printf("    Baseline Title: %s\n", truncateString(result.Baseline.Title, 50))
            if proxy.StatusCode == 301 {
                fmt.Printf("    Location: %s\n", proxy.Location)
            }
        }
    }
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
        dashboard.CountriesBlocked[info.Country]++
    }
}

func setupSignalHandler(cancel context.CancelFunc) {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\nReceived interrupt signal. Shutting down gracefully...")
        cancel()
    }()
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


func loadProxiesGroupedByCountry(proxyFile, jsonFile string) ProxyMap {
    proxyMap := make(ProxyMap)
    
        proxies := loadProxies(proxyFile, jsonFile)
    if len(proxies) == 0 {
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
            cachedLookup(host)
        }(proxy)
    }
    dnsWg.Wait()

        verifiedProxies := bulkPreCheck(proxies, 300)
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
                ip, _ := cachedLookup(host)
                
                country, err := getCountry(ip)
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

    fmt.Printf("\nSaving fresh proxies... (Baseline valid: %v)\n", baselineValid)

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

        fmt.Printf("\nSaved %d/%d UP proxies to %s (Baseline valid: %v)\n",
        len(freshProxies), totalUp, filename, baselineValid)
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

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    setupSignalHandler(cancel)
    defer cleanup()

    flag.Parse()

        var err error
    ip2locationDB, err = ip2location.OpenDB(*dbFile)
    if err != nil {
        fmt.Printf("Error opening GeoIP database: %v\n", err)
        return
    }
    defer ip2locationDB.Close()

        proxyMap := loadProxiesGroupedByCountry(*proxiesFile, *jsonWordlist)
    if len(proxyMap) == 0 {
        fmt.Println("No valid proxies found")
        return
    }

        if (*targetURL == "" && *targetWordlist == "") {
        fmt.Println("Error: Target URL or wordlist required")
        flag.PrintDefaults()
        return
    }

    config := Config{
        ProxyList:            proxyMap,
        ProxiesFile:          *proxiesFile,
        JSONWordlist:         *jsonWordlist,
        TargetWordlist:       *targetWordlist,
        Threads:              *threads,
        TargetURL:            *targetURL,
        Verbose:              *vFlag,
        NoPrecheck:           *noPrecheck,
        UpOnly:               *upOnly,
        FreshProxyOut:        *freshProxyOut,
        OneAttemptPerCountry: *oneAttemptPerCountry,
        Retries:              *retries,
        OutputFormat:         *outputFormat,
    }
    if *vFlag {
        logFile, err := os.OpenFile("zgeo_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
            verboseLogger = log.New(logFile, "", log.LstdFlags|log.Lmicroseconds)
        }
    }
    baselineInfo, baseContent, baseTitle := getBaseline(config.TargetURL)
    if baseContent == "" {
        fmt.Println("Warning: Could not establish baseline - using empty comparison")
    }
    baselineContent = baseContent
    baselineTitle = baseTitle
    dashboard.Baseline = baselineInfo

        dashboard.StartTime = time.Now()
    dashboard.CountriesBlocked = make(map[string]int)

    var allResults AllResults
    allResults.StartTime = dashboard.StartTime

        if config.TargetWordlist != "" {
        allResults.Results = runMassiveCheck(ctx, config)
    } else {
        result := runCheck(ctx, config)
        allResults.Results = []Result{result}
        printResults(result, config.UpOnly)
    }
    
        allResults.EndTime = time.Now()
    if config.OutputFormat == "html" {
        saveHTMLReport(allResults)
    } else {
        saveImprovedJSON(improveJSONOutput(allResults.Results))
    }
    
        if config.FreshProxyOut {
        saveFreshProxies(activeProxies.GetAll())
    }
    fmt.Println(generateSummaryReport(allResults.Results))
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
        detailedResult["blocked_countries"] = result.BlockedCountries
        
        if result.BlockingLevel > 0 {
            output["blocked_urls"] = output["blocked_urls"].(int) + 1
        }
        
        output["total_proxies"] = output["total_proxies"].(int) + len(result.Proxies)
        
        for country, proxies := range result.BlockedCountries {
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
        for _, proxies := range result.BlockedCountries {
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

func bulkPreCheck(proxies []string, concurrency int) []string {
    sem := make(chan struct{}, 50)
    validProxies := make(chan string, len(proxies))
    var wg sync.WaitGroup

    for _, proxy := range proxies {
        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            if quickProxyCheck(p) {
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
