package main

import (
    "golang.org/x/time/rate"
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

type Progress struct {
    Total      int64
    Processed  int64
    Success    int64
    Failures   int64
    Errors     int64
}

var globalProgress Progress

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
    Proxy       string
    Retries int
}

type WorkerPool struct {
    config     Config
    jobs       chan Job
    results    chan ProxyInfo
    metrics    *Metrics
    throttler  *DynamicThrottler
    batchMgr   *BatchManager
    wg         sync.WaitGroup
    ctx        context.Context
    closeOnce  sync.Once
    jobsClosed bool
}


type BatchManager struct {
    mu           sync.Mutex
    currentBatch int
    maxBatch     int
}

func (bm *BatchManager) AdjustBatchSize(delta int) {
    bm.mu.Lock()
    defer bm.mu.Unlock()
    bm.currentBatch = clamp(bm.currentBatch+delta, 50, bm.maxBatch)
}

type Metrics struct {
    mu         sync.Mutex
    Successes  int
    Failures   int
    Retries    int
    CurrentRPS int
}

func (m *Metrics) Record(result ProxyInfo) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    if result.Status == "UP" {
        m.Successes++
    } else {
        m.Failures++
    }
}

func (m *Metrics) Report() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        m.mu.Lock()
        fmt.Printf(
            "Metrics: Success=%d Failures=%d Retries=%d RPS=%d\n",
            m.Successes, m.Failures, m.Retries, m.CurrentRPS,
        )
        m.mu.Unlock()
    }
}


func createWorkerPool(ctx context.Context, config Config) *WorkerPool {
    pool := &WorkerPool{
        config:    config,
        jobs:      make(chan Job, 100000),
        results:   make(chan ProxyInfo, 100000),
        metrics:   &Metrics{},
        throttler: NewThrottler(1000),
        batchMgr:  &BatchManager{currentBatch: 100, maxBatch: 1000},
        ctx:       ctx,
    }

    pool.wg.Add(config.Threads)
    for i := 0; i < config.Threads; i++ {
        go pool.worker()
    }

    // Start metrics reporter
    go pool.metrics.Report()
    
    return pool
}

func (wp *WorkerPool) worker() {
    defer wp.wg.Done()
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Worker panic recovered: %v", r)
        }
    }()

    for job := range wp.jobs {
        select {
        case <-wp.ctx.Done():
            return
        default:
            // Rate limiting
            if err := wp.throttler.Wait(wp.ctx); err != nil {
                continue
            }

            // Process job with retries
            result := wp.processJobWithRetries(job)
            
            // Update global progress counters
            atomic.AddInt64(&globalProgress.Processed, 1)
            if result.Status == "UP" {
                atomic.AddInt64(&globalProgress.Success, 1)
            } else if result.Status == "INVALID" {
                atomic.AddInt64(&globalProgress.Errors, 1)
            } else {
                atomic.AddInt64(&globalProgress.Failures, 1)
            }

            // Send result
            select {
            case wp.results <- result:
                wp.metrics.Record(result)
            case <-wp.ctx.Done():
                return
            }
        }
    }
}
func (wp *WorkerPool) CloseJobs() {
    wp.closeOnce.Do(func() {
        close(wp.jobs)
        wp.jobsClosed = true
    })
}

// Helper method for batch processing
func (wp *WorkerPool) SubmitBatch(batch []Job) {
    for _, job := range batch {
        select {
        case wp.jobs <- job:
        case <-wp.ctx.Done():
            return
        }
    }
}
func (wp *WorkerPool) processJobWithRetries(job Job) ProxyInfo {
    var result ProxyInfo
    var err error

    for attempt := 0; attempt <= job.Retries; attempt++ {
        result, err = checkProxy(wp.ctx, job.Proxy, wp.config.TargetURL, wp.config)
        
        if err == nil && result.Status == "UP" {
            return result
        }

        if !isRetryableError(err) || attempt >= job.Retries {
            break
        }

        backoff := calculateBackoff(
            500*time.Millisecond,
            10*time.Second,
            attempt,
        )

        select {
        case <-time.After(backoff):
        case <-wp.ctx.Done():
            return ProxyInfo{Status: "CANCELLED"}
        }
    }

    if err != nil {
        result.Error = err.Error()
    }
    return result
}

func (wp *WorkerPool) checkWithRetries(job Job) ProxyInfo {
    var result ProxyInfo
    var err error
    attempt := 0

    for attempt <= job.Retries {
        // Check main context first
        select {
        case <-wp.ctx.Done():
            return ProxyInfo{Status: "CANCELLED"}
        default:
        }

        // Execute check
        result, err = checkProxy(wp.ctx, job.Proxy, wp.config.TargetURL, wp.config)
        
        // Update retry metrics
        if attempt > 0 {
            wp.metrics.mu.Lock()
            wp.metrics.Retries++
            wp.metrics.mu.Unlock()
        }

        if err == nil && result.Status == "UP" {
            return result
        }

        // Check if we should retry
        if !isRetryableError(err) || attempt >= job.Retries {
            break
        }

        // Calculate backoff with jitter
        backoff := calculateBackoff(
            500*time.Millisecond, 
            10*time.Second, 
            attempt,
        )

        select {
        case <-time.After(backoff):
        case <-wp.ctx.Done():
            return ProxyInfo{Status: "CANCELLED"}
        }

        attempt++
    }

    if err != nil {
        result.Error = err.Error()
    }
    return result
}

func (wp *WorkerPool) feedBatches() {
    defer close(wp.jobs)
    
    // Load proxies with country filtering
    proxies := loadProxies(
        wp.config.ProxiesFile,
        wp.config.JSONWordlist,
        wp.config.OneAttemptPerCountry,
    )
    
    if len(proxies) == 0 {
        log.Println("No proxies available after filtering")
        return
    }

    // Prefetch DNS records to improve performance
    prefetchProxyDNS(proxies)

    // Dynamic batch processing
    for len(proxies) > 0 {
        batchSize := wp.batchMgr.GetBatchSize()
        end := min(batchSize, len(proxies))
        batch := proxies[:end]
        proxies = proxies[end:]

        // Submit batch to workers
        for _, proxy := range batch {
            select {
            case wp.jobs <- Job{Proxy: proxy, Retries: wp.config.Retries}:
            case <-wp.ctx.Done():
                log.Println("Batch feeding cancelled")
                return
            }
        }

        wp.batchMgr.RecordBatch(len(batch))
        
        // Adaptive batch sizing
        select {
        case <-time.After(1 * time.Second):
            // Monitor system load between batches
            if systemLoadOverThreshold() {
                wp.batchMgr.AdjustBatchSize(-25) // Reduce batch size
            } else {
                wp.batchMgr.AdjustBatchSize(+25) // Increase batch size
            }
        case <-wp.ctx.Done():
            return
        }
    }
}

// Helper functions
func systemLoadOverThreshold() bool {
    load := getSystemLoadAverage()
    return load > 70.0 // 70% CPU load threshold
}

func (wp *WorkerPool) processJob(job Job) {
    result := wp.checkWithRetries(job)
    
    atomic.AddInt64(&globalProgress.Processed, 1)
    
    if result.Status == "UP" {
        atomic.AddInt64(&globalProgress.Success, 1)
    } else if result.Status == "INVALID" {
        atomic.AddInt64(&globalProgress.Errors, 1)
    } else {
        atomic.AddInt64(&globalProgress.Failures, 1)
    }

    select {
    case wp.results <- result:
    case <-wp.ctx.Done():
    }
}



func (wp *WorkerPool) Results() <-chan ProxyInfo {
    return wp.results
}

func (wp *WorkerPool) Stop() {
    wp.wg.Wait()
}

// Helper functions
func isRetryableError(err error) bool {
    if err == nil {
        return false
    }
    return strings.Contains(err.Error(), "timeout") ||
        strings.Contains(err.Error(), "connection reset")
}

func calculateBackoff(base, max time.Duration, attempt int) time.Duration {
    exp := math.Pow(2, float64(attempt))
    delay := time.Duration(float64(base) * exp)
    jitter := time.Duration(rand.Float64() * 0.3 * float64(delay))
    
    if delay > max {
        return max
    }
    return delay + jitter
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
    Retries    int  
    Address    string
    Status     string
    Country    string
    StatusCode int
    ContentSim float64
    TitleSim   float64
    Title      string
    Location   string
    Protocol   string
    Error      string
    Duration   time.Duration
}

var proxyMapMu sync.Mutex

var (
    badProxies   sync.Map
    clientPool = sync.Pool{
        New: func() interface{} {
            return &fasthttp.Client{
                NoDefaultUserAgentHeader: true,
                MaxConnsPerHost:          100,
                ReadBufferSize:           4096,
                WriteBufferSize:          4096,
                MaxIdleConnDuration:      30 * time.Second,
            }
        },
    }
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

    // Calculate summary statistics
    totalProxies := 0
    blockedProxies := 0
    blockedURLs := 0
    
    for _, result := range allResults.Results {
        totalProxies += len(result.Proxies)
        if result.BlockingLevel > 0 {
            blockedURLs++
        }
        for _, proxies := range result.DifferentCountries {
            blockedProxies += len(proxies)
        }
    }

    data := struct {
        Results       []Result
        StartTime     time.Time
        EndTime       time.Time
        BlockedURLs   int
        TotalProxies  int
        BlockedProxies int
    }{
        Results:       allResults.Results,
        StartTime:     allResults.StartTime,
        EndTime:       allResults.EndTime,
        BlockedURLs:   blockedURLs,
        TotalProxies:  totalProxies,
        BlockedProxies: blockedProxies,
    }

    if err := tmpl.Execute(f, data); err != nil {
        fmt.Printf("Error executing HTML template: %v\n", err)
        return
    }

    fmt.Printf("HTML report saved to %s\n", filename)
}


func quickProxyCheck(proxyAddr string, timeout time.Duration) bool {
    host, port, err := net.SplitHostPort(proxyAddr)
    if err != nil {
        return false
    }
    
    // Use cached DNS lookup
    ip, err := cachedLookup(context.Background(), host)
    if err != nil {
        return false
    }
    
    target := net.JoinHostPort(ip, port)
    conn, err := net.DialTimeout("tcp", target, timeout)
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

func prefetchProxyDNS(proxies []string) {
    var wg sync.WaitGroup
    for _, proxy := range proxies {
        parts := strings.Split(proxy, ":")
        if len(parts) != 2 {
            continue
        }
        wg.Add(1)
        go func(host string) {
            defer wg.Done()
            cachedLookup(context.Background(), host)
        }(parts[0])
    }
    wg.Wait()
}

func runCheck(ctx context.Context, config Config) Result {
    throttler := NewThrottler(1000) // Start with 1000 RPS
    go throttler.MonitorSystem()
    
    proxies := loadProxies(config.ProxiesFile, config.JSONWordlist,config.OneAttemptPerCountry)
    
    // Preprocess proxies
    prefetchProxyDNS(proxies)
    proxies = prioritizeProxies(proxies)
    
    // Process in adaptive batches
    processBatches(proxies, config)

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
    if totalProxies > 0 {
        go func() {
            defer cancelProgress() // Ensure cleanup
            ticker := time.NewTicker(500 * time.Millisecond)
            defer ticker.Stop()
            
            for {
                select {
                case <-ticker.C:
                    // Use package-level atomic variables directly
                    p := atomic.LoadInt64(&globalProgress.Processed)
                    s := atomic.LoadInt64(&globalProgress.Success)
                    f := atomic.LoadInt64(&globalProgress.Failures)
                    e := atomic.LoadInt64(&globalProgress.Errors)
                    
                    width := 20
                    progress := float64(p)/float64(totalProxies)
                    bars := int(progress * float64(width))
                    
                    fmt.Printf("\r[%s%s] %d/%d | ↑%d ↓%d !%d (%.1f%%)",
                        strings.Repeat("█", bars),
                        strings.Repeat("░", width-bars),
                        p, totalProxies, s, f, e,
                        float64(p)/float64(totalProxies)*100)
                case <-ctx.Done():
                    return // Exit on cancellation                        
                case <-progressCtx.Done():                   
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
                
                info, _ := checkProxyWithRetry(workerCtx, job.Proxy, config.TargetURL, config.NoPrecheck, job.Retries, tracker, config)
                
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
    }
    fmt.Printf("\nProxy success rate: %d/%d (%.1f%%)\n", 
    success, total, float64(success)/float64(total)*100)

        result.BlockingLevel = determineBlockingLevel(result.Baseline, result.Proxies)
    result.DifferentCountries = analyzeResults(result.Baseline, result.Proxies)
    
    return result
}

func generateReports(results []ProxyInfo, config Config, startTime time.Time) {
    // Create baseline information
    baseline, content, title := getBaseline(config.TargetURL)
    baselineContent = content
    baselineTitle = title
    baselineTagCounts = extractTagCounts(content)

    // Create AllResults structure
    allResults := AllResults{
        Results: []Result{{
            URL:              config.TargetURL,
            Baseline:         baseline,
            LocalCountry:     getLocalCountry(),
            Proxies:          results,
            BlockingLevel:    determineBlockingLevel(baseline, results),
            DifferentCountries: analyzeResults(baseline, results),
        }},
        StartTime: startTime,
        EndTime:   time.Now(),
    }

    if config.OutputFormat == "json" {
        saveImprovedJSON(results)
    } else {
        saveHTMLReport(allResults)
    }
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
    noPrecheck bool, retries int, tracker *UsedProxyTracker, config Config) (ProxyInfo, error) {
    
    maxDelay := config.Timeout
    if maxDelay > 5*time.Second {
        maxDelay = 5*time.Second
    }

    var result ProxyInfo
    var lastErr error
    
    for attempt := 0; attempt <= retries; attempt++ {
        attemptCtx, cancel := context.WithTimeout(ctx, config.Timeout)
        result, lastErr = checkProxy(attemptCtx, proxyAddr, targetURL, config)
        
        if lastErr == nil && result.Status == "UP" {
            cancel()
            return result, nil
        }
        
        if attempt < retries {
            backoff := calculateBackoff(500*time.Millisecond, maxDelay, attempt)
            select {
            case <-time.After(backoff):
            case <-ctx.Done():
                cancel()
                return ProxyInfo{Status: "CANCELLED"}, ctx.Err()
            }
        }
        cancel()
    }
    
    return result, fmt.Errorf("after %d attempts: %w", retries, lastErr)
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
func prioritizeProxies(proxies []string) []string {
    // Simple prioritization: random shuffle
    rand.Seed(time.Now().UnixNano())
    rand.Shuffle(len(proxies), func(i, j int) {
        proxies[i], proxies[j] = proxies[j], proxies[i]
    })
    return proxies
}

func checkProxy(ctx context.Context, proxyAddr string, targetURL string, config Config) (ProxyInfo, error) {
    info := ProxyInfo{Address: proxyAddr}
    startTime := time.Now()
    defer func() {
        info.Duration = time.Since(startTime)
        logVerbose(startTime, fmt.Sprintf("Proxy check %s", info.Status))
    }()

    // Validate target URL
    target, err := url.Parse(targetURL)
    if err != nil {
        info.Status = "INVALID_TARGET"
        return info, fmt.Errorf("invalid target URL: %w", err)
    }

    // Get client from pool
    client := clientPool.Get().(*fasthttp.Client)
    defer clientPool.Put(client)

    // Configure client for this proxy
    client.Dial = createProxyDialer(proxyAddr, target, config.Timeout)
    
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer func() {
        fasthttp.ReleaseRequest(req)
        fasthttp.ReleaseResponse(resp)
    }()

    // Configure request
    req.SetRequestURI(targetURL)
    req.Header.SetMethod(fasthttp.MethodGet)
    req.Header.Set("Host", target.Host)
    req.Header.SetUserAgent("Mozilla/5.0 (compatible; zgeo-proxy-checker/2.0)")
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

    // Execute request with context-based timeout
    err = client.DoTimeout(req, resp, config.Timeout)
    if err != nil {
        info.Status = classifyError(err)
        info.Error = err.Error()
        
        if isRetryableError(err) {
            badProxies.Store(proxyAddr, struct{}{})
        }
        return info, err
    }

    // Process successful response
    info.StatusCode = resp.StatusCode()
    info.Protocol = target.Scheme
    info.Location = string(resp.Header.Peek("Location"))
    
    // Mark as UP if we got any valid HTTP response
    info.Status = "UP"
    
    // Get country information
    if host, _, err := net.SplitHostPort(proxyAddr); err == nil {
        info.Country, _ = getCountryWithCache(ctx, host)
    }

    // Calculate metrics if we have baseline
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

    return info, nil
}

func createProxyDialer(proxyAddr string, target *url.URL, timeout time.Duration) func(string) (net.Conn, error) {
    return func(addr string) (net.Conn, error) {
        // Establish proxy connection
        conn, err := fasthttp.DialTimeout(proxyAddr, 3*time.Second)
        if err != nil {
            return nil, fmt.Errorf("proxy connection failed: %w", err)
        }

        // HTTPS-specific handling
        if target.Scheme == "https" {
            host, port, _ := net.SplitHostPort(target.Host)
            if port == "" {
                port = "443"
            }

            // Send CONNECT request
            connectReq := fmt.Sprintf(
                "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                host, port, host, port,
            )
            
            conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
            if _, err := conn.Write([]byte(connectReq)); err != nil {
                conn.Close()
                return nil, fmt.Errorf("CONNECT write failed: %w", err)
            }

            // Verify CONNECT response
            br := bufio.NewReader(conn)
            resp, err := http.ReadResponse(br, nil)
            if err != nil || resp.StatusCode != 200 {
                conn.Close()
                status := 0
                if resp != nil {
                    status = resp.StatusCode
                }
                return nil, fmt.Errorf("CONNECT failed (status %d): %w", status, err)
            }

            // Perform TLS handshake
            tlsConfig := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: true,
                MinVersion:         tls.VersionTLS12,
            }
            
            tlsConn := tls.Client(conn, tlsConfig)
            tlsConn.SetDeadline(time.Now().Add(timeout - 2*time.Second))
            if err := tlsConn.Handshake(); err != nil {
                tlsConn.Close()
                return nil, fmt.Errorf("TLS handshake failed: %w", err)
            }

            return tlsConn, nil
        }

        return conn, nil
    }
}

// Add detailed error classification
func classifyError(err error) string {
    if err == nil {
        return "success"
    }
    
    switch {
    case strings.Contains(err.Error(), "timeout"):
        return "timeout"
    case strings.Contains(err.Error(), "connection refused"):
        return "refused"
    case strings.Contains(err.Error(), "tls handshake"):
        return "tls_error"
    case strings.Contains(err.Error(), "reset by peer"):
        return "connection_reset"
    default:
        return "unknown_error"
    }
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

func loadProxies(proxyFile, jsonFile string, oneAttemptPerCountry bool) []string {
    var proxies []string
    
    // 1. Try to load from JSON wordlist first
    if jsonFile != "" {
        if *vFlag {
            fmt.Printf("[DEBUG] Trying to load from JSON: %s\n", jsonFile)
        }
        proxies = loadJSONProxies(jsonFile)
    }

    // 2. If still empty, try to load from proxies file
    if len(proxies) == 0 && proxyFile != "" {
        if *vFlag {
            fmt.Printf("[DEBUG] Trying to load from proxy file: %s\n", proxyFile)
        }
        proxies = loadTextProxies(proxyFile)
    }

    // 3. If still empty, check for default downloaded file
    if len(proxies) == 0 {
        if *vFlag {
            fmt.Println("[DEBUG] No proxies found in provided files")
        }
        if fileExists("http_proxies_zgeo.txt") {
            if *vFlag {
                fmt.Println("[DEBUG] Using default proxies file")
            }
            proxies = loadTextProxies("http_proxies_zgeo.txt")
        }
    }

    // 4. If still empty, prompt to download
    if len(proxies) == 0 {
        fmt.Print("\nNo proxy list found. Download default proxies? (y/n): ")
        var response string
        _, err := fmt.Scanln(&response)
        if err != nil || strings.ToLower(response) != "y" {
            log.Fatal("Proxy list required")
        }
        
        if downloadProxies() {
            proxies = loadTextProxies("http_proxies_zgeo.txt")
        } else {
            log.Fatal("Failed to download proxies")
        }
    }

    if *vFlag {
        fmt.Printf("[DEBUG] Total proxies loaded: %d\n", len(proxies))
    }
    
    // Apply country filtering
    if oneAttemptPerCountry {
        return filterOnePerCountry(proxies)
    }
    return proxies
}

func filterOnePerCountry(proxies []string) []string {
    countryMap := make(map[string]bool)
    var filtered []string
    
    for _, proxy := range proxies {
        host, _, err := net.SplitHostPort(proxy)
        if err != nil {
            continue
        }
        country, err := getCountryWithCache(context.Background(), host)
        if err != nil || country == "" {
            continue
        }
        if !countryMap[country] {
            filtered = append(filtered, proxy)
            countryMap[country] = true
        }
    }
    
    return filtered
}


func loadProxiesGroupedByCountry(config Config) ProxyMap {
    proxyMap := make(ProxyMap)

    // Handle prechecked proxy files first
    if strings.HasPrefix(config.ProxiesFile, "prechecked_") {
        file, err := os.Open(config.ProxiesFile)
        if err == nil {
            defer file.Close()
            
            var prechecked []struct {
                IP      string `json:"ip"`
                Port    string `json:"port"`
                Country string `json:"country"`
            }
            
            if err := json.NewDecoder(file).Decode(&prechecked); err == nil {
                for _, p := range prechecked {
                    addr := net.JoinHostPort(p.IP, p.Port)
                    if p.Country == "" {
                        p.Country = "UNKNOWN"
                    }
                    proxyMap[p.Country] = append(proxyMap[p.Country], addr)
                }
                fmt.Printf("Loaded %d prechecked proxies from %s\n", len(prechecked), config.ProxiesFile)
                return sortProxyMap(proxyMap)
            }
        }
    }

    // Normal processing for raw text or JSON proxies
    var proxies []string
    if config.JSONWordlist != "" {
        // Handle JSON input format for fresh proxies
        proxies = loadJSONProxies(config.JSONWordlist)
    } else {
        // Handle raw text format
        proxies = loadTextProxies(config.ProxiesFile)
    }
    
    if len(proxies) == 0 {
        return proxyMap
    }

    // Proxy verification phase
    verifiedProxies := proxies
    if !config.NoPrecheck {
        verifiedProxies = bulkPreCheck(proxies, config.Timeout)
        fmt.Printf("Pre-check complete: %d/%d alive\n", len(verifiedProxies), len(proxies))
    }

    // GeoIP processing with caching
    var wg sync.WaitGroup
    geoQueue := make(chan string, len(verifiedProxies))
    results := make(chan struct {
        proxy   string
        country string
    }, len(verifiedProxies))

    // Start worker pool
    for i := 0; i < 200; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for proxy := range geoQueue {
                host, _, err := net.SplitHostPort(proxy)
                if err != nil {
                    results <- struct{proxy, country string}{proxy, "INVALID"}
                    continue
                }

                country := getCachedCountry(host)
                results <- struct{proxy, country string}{proxy, country}
            }
        }()
    }

    // Feed proxies to workers
    go func() {
        for _, p := range verifiedProxies {
            geoQueue <- p
        }
        close(geoQueue)
        wg.Wait()
        close(results)
    }()

    // Aggregate results
    for res := range results {
        country := res.country
        if country == "" {
            country = "UNKNOWN"
        }
        proxyMap[country] = append(proxyMap[country], res.proxy)
    }

    return sortProxyMap(proxyMap)
}

// Helper functions
func getCachedCountry(host string) string {
    // Check DNS cache
    dnsCache.RLock()
    ip, found := dnsCache.m[host]
    dnsCache.RUnlock()

    if !found {
        ips, err := net.LookupIP(host)
        if err != nil || len(ips) == 0 {
            return "DNS_FAIL"
        }
        ip = ips[0].String()
        dnsCache.Lock()
        dnsCache.m[host] = ip
        dnsCache.Unlock()
    }

    // Check geo cache
    geoCache.RLock()
    country, found := geoCache.m[ip]
    geoCache.RUnlock()
    
    if !found {
        record, err := ip2locationDB.Get_all(ip)
        if err != nil {
            country = "GEO_FAIL"
        } else {
            country = record.Country_short
        }
        geoCache.Lock()
        geoCache.m[ip] = country
        geoCache.Unlock()
    }

    return country
}

func loadJSONProxies(filename string) []string {
    file, _ := os.Open(filename)
    defer file.Close()

    var proxies []struct {
        IP      string `json:"ip"`
        Port    string `json:"port"`
        Country string `json:"country"` // Campo adicionado
    }

    if err := json.NewDecoder(file).Decode(&proxies); err != nil {
        log.Fatalf("Erro ao decodificar JSON: %v", err)
    }

    var result []string
    for _, p := range proxies {
        result = append(result, net.JoinHostPort(p.IP, p.Port))
    }
    return result
}

func loadTextProxies(filename string) []string {
    file, _ := os.Open(filename)
    defer file.Close()
    
    var proxies []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        proxies = append(proxies, strings.TrimSpace(scanner.Text()))
    }
    return proxies
}

func sortProxyMap(original ProxyMap) ProxyMap {
    countries := make([]string, 0, len(original))
    for country := range original {
        countries = append(countries, country)
    }

    sort.Slice(countries, func(i, j int) bool {
        return len(original[countries[i]]) > len(original[countries[j]])
    })

    sorted := make(ProxyMap)
    for _, country := range countries {
        sorted[country] = original[country]
    }
    return sorted
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
    dbFile              = flag.String("db", "db-1.bin", "Path to IP2Location DB")
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
)

func main() {
    flag.Parse()

    // 1. Inicializa contexto com cancelamento
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // 2. Configura tratamento de sinais
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Println("\nRecebido sinal de desligamento...")
        cancel()
    }()

    // 3. Carrega database GeoIP
    absDBPath, _ := filepath.Abs(*dbFile)
    
    if err := checkAndDownloadGeoDB(); err != nil {
        log.Fatalf("GeoIP database error: %v", err)
    }

    var err error // Nova declaração de erro
    ip2locationDB, err = ip2location.OpenDB(absDBPath)
    if err != nil {
        log.Fatalf("Failed to open GeoIP database: %v\n located in: %s", err,absDBPath)
    }

    defer ip2locationDB.Close()

    // 4. Carrega configuração
    config := Config{
        Timeout:            *timeout,
        ProxiesFile:        *proxiesFile,
        JSONWordlist:       *jsonWordlist,
        TargetURL:          *targetURL,
        Threads:            *threads,
        Verbose:            *vFlag,
        NoPrecheck:         *noPrecheck,
        UpOnly:             *upOnly,
        FreshProxyOut:      *freshProxyOut,
        Retries:            *retries,
        OutputFormat:       *outputFormat,
        OneAttemptPerCountry: *oneAttemptPerCountry,
    }
    proxies := loadProxies(config.ProxiesFile, config.JSONWordlist, config.OneAttemptPerCountry)
    
    if len(proxies) == 0 {
        log.Fatal("No valid proxies found after all attempts")
    }
    
    // Inicializa progresso global
    globalProgress.Total = int64(len(proxies))
    atomic.StoreInt64(&globalProgress.Total, int64(len(proxies)))
    atomic.StoreInt64(&globalProgress.Processed, 0)
    atomic.StoreInt64(&globalProgress.Success, 0)
    atomic.StoreInt64(&globalProgress.Failures, 0)
    atomic.StoreInt64(&globalProgress.Errors, 0)

    // 6. Inicia exibição de progresso
    progressCtx, stopProgress := context.WithCancel(ctx)
    defer stopProgress()
    startProgressUpdater(progressCtx)

    // 7. Cria pool de workers
    pool := createWorkerPool(ctx, config)
    defer pool.Stop()

    // 8. Canal de resultados
    results := make([]ProxyInfo, 0)
    resultDone := make(chan struct{})
    var resultWG sync.WaitGroup // Adicionar declaração


    // 9. Coletor de resultados
    go func() {
        defer close(resultDone)
        for result := range pool.Results() {
            results = append(results, result)
            if config.Verbose {
                printProxyInfo(result)
            }
        }
    }()

    // 10. Alimenta os workers com proxies
    var feedWG sync.WaitGroup
    feedWG.Add(1)
    go func() {
        defer feedWG.Done()
        // Remove defer close(pool.jobs) here
        for _, proxy := range proxies {
            select {
            case pool.jobs <- Job{Proxy: proxy, Retries: config.Retries}:
            case <-ctx.Done():
                return
            }
        }
        close(pool.jobs) // Close jobs after feeding all proxies
    }()
    feedWG.Wait()
    pool.Stop() // Garante que todos os workers pararam
    resultWG.Wait() // Espera o coletor terminar

    select {
    case <-ctx.Done():
        fmt.Println("\nOperação cancelada pelo usuário")
    default:
        fmt.Println("\nVerificação completa")
    }

    // 12. Gera relatórios finais
    if len(results) > 0 {
        generateReports(results, config, time.Now())
    }
    processed := atomic.LoadInt64(&globalProgress.Processed)
    success := atomic.LoadInt64(&globalProgress.Success)
    failures := atomic.LoadInt64(&globalProgress.Failures)
    errors := atomic.LoadInt64(&globalProgress.Errors)

    successRate := 0.0
    if processed > 0 {
        successRate = float64(success)/float64(processed)*100
    }

    fmt.Printf(`
    === Final Summary ===
    Proxies tested:  %d
    Success:         %d
    Failures:        %d
    Errors:          %d
    Success rate:    %.2f%%
    `, 
        processed,
        success,
        failures,
        errors,
        successRate,
    )
}
// Helper functions for proxy management
func findLatestPrecheckedFile() string {
    files, _ := filepath.Glob("prechecked_proxies_*.json")
    if len(files) == 0 {
        return ""
    }

    // Sort descending by timestamp using Before/After methods
    sort.Slice(files, func(i, j int) bool {
        t1 := extractTimestamp(files[i])
        t2 := extractTimestamp(files[j])
        return t1.After(t2)  // Use After() instead of > operator
    })

    // Get today's date
    now := time.Now()
    today := now.Format("20060102")

    // Find first file from today
    for _, f := range files {
        fileTime := extractTimestamp(f)
        if fileTime.Format("20060102") == today {
            return f
        }
    }
    return ""
}
func getTimestampFromFilename(path string) string {
    base := filepath.Base(path)
    return strings.TrimSuffix(strings.TrimPrefix(base, "fresh_proxies_"), ".json")
}

func getFileTime(path string) time.Time {
    tsStr := getTimestampFromFilename(path)
    t, err := time.Parse("20060102_1504", tsStr)  // Now parses full timestamp
    if err != nil {
        return time.Time{}
    }
    return t
}

func extractTimestamp(path string) time.Time {
    base := filepath.Base(path)
    tsStr := strings.TrimSuffix(strings.TrimPrefix(base, "prechecked_proxies_"), ".json")
    t, err := time.Parse("20060102_1504", tsStr)
    if err != nil {
        return time.Time{}
    }
    return t
}

func checkAndDownloadGeoDB() error {
    // Obter caminho absoluto do arquivo
    absPath, _ := filepath.Abs(*dbFile)
    
    // Verificar no diretório atual primeiro
    if _, err := os.Stat(absPath); err == nil {
        fmt.Printf("✅ Database encontrada em: %s\n", absPath)
        return nil
    }

    fmt.Printf("\n❗ GeoIP database (%s) not found! Attempting automatic download...\n", *dbFile)
    
    // Use a valid GeoIP database URL (update this to a real source)
    dbURL := "https://github.com/zeroc00I/Zgeo/raw/refs/heads/main/db-1.bin" 
    
    resp, err := http.Get(dbURL)
    if err != nil {
        fmt.Printf("❌ Download failed: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        fmt.Printf("❌ Bad response from server: %d\n", resp.StatusCode)
        os.Exit(1)
    }

    outFile, err := os.Create(*dbFile)
    if err != nil {
        fmt.Printf("❌ Couldn't create file: %v\n", err)
        os.Exit(1)
    }
    defer outFile.Close()

    if _, err := io.Copy(outFile, resp.Body); err != nil {
        fmt.Printf("❌ Write failed: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Println("✅ GeoIP database downloaded successfully")
    return nil
}
func savePrecheckedProxies(proxies []string) string {
    filename := fmt.Sprintf("prechecked_proxies_%s.json", time.Now().Format("20060102_1504"))
    file, _ := os.Create(filename)
    defer file.Close()

    type PrecheckedProxy struct {
        IP      string `json:"ip"`
        Port    string `json:"port"`
        Country string `json:"country"`
        Checked string `json:"last_checked"` 
    }

    var output []PrecheckedProxy
    now := time.Now().Format(time.RFC3339)
    
    for _, proxy := range proxies {
        host, port, err := net.SplitHostPort(proxy)
        if err != nil {
            continue
        }
        
        country, _ := getCountryWithCache(context.Background(), host)
        
        output = append(output, PrecheckedProxy{
            IP:      host,
            Port:    port,
            Country: country,
            Checked: now,
        })
    }

    json.NewEncoder(file).Encode(output)
    return filename
}

// Signal handler setup
func setupSignalHandler(cancel context.CancelFunc) {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\n🛑 Received termination signal - shutting down...")
        time.Sleep(1 * time.Second)
        cancel()
    }()
}

func shouldRetry(status string) bool {
    return status == "DOWN" || status == "TIMEOUT"
}

func logVerbose(start time.Time, operation string) {
    if verboseLogger != nil {
        elapsed := time.Since(start)
        fmt.Printf("\r\033[K") // Mantém o cursor na mesma linha
        verboseLogger.Printf("%-15s %v", operation, elapsed)
    }
}

func fileExists(filename string) bool {
    _, err := os.Stat(filename)
    return !os.IsNotExist(err)
}

func logProxyAttempt(proxy string, start time.Time, success bool, config Config) {
    if config.Verbose {
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

func saveImprovedJSON(results []ProxyInfo) {
    filename := fmt.Sprintf("geo_results_%d.json", time.Now().Unix())
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("Error creating JSON file: %v\n", err)
        return
    }
    defer file.Close()

    // Create enhanced JSON structure
    type EnhancedResult struct {
        ProxyInfo
        Anomaly bool `json:"anomaly"`
    }

    // Calculate statistics
    var (
        total          = len(results)
        successCount   int
        anomalyCount   int
        countryStats   = make(map[string]int)
        enhancedResults []EnhancedResult
    )

    for _, res := range results {
        enhanced := EnhancedResult{
            ProxyInfo: res,
            Anomaly:   res.ContentSim < 0.8 || res.TitleSim < 0.8,
        }
        
        if res.Status == "UP" {
            successCount++
        }
        if enhanced.Anomaly {
            anomalyCount++
        }
        countryStats[res.Country]++
        
        enhancedResults = append(enhancedResults, enhanced)
    }

    // Create final output structure
    output := struct {
        Timestamp     time.Time         `json:"timestamp"`
        TotalProxies  int               `json:"total_proxies"`
        SuccessRate   float64           `json:"success_rate"`
        AnomalyRate   float64           `json:"anomaly_rate"`
        Countries     map[string]int    `json:"country_stats"`
        Proxies       []EnhancedResult  `json:"proxies"`
    }{
        Timestamp:    time.Now(),
        TotalProxies: total,
        SuccessRate:  float64(successCount)/float64(total)*100,
        AnomalyRate:  float64(anomalyCount)/float64(total)*100,
        Countries:    countryStats,
        Proxies:      enhancedResults,
    }

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(output); err != nil {
        fmt.Printf("Error encoding JSON: %v\n", err)
    } else {
        fmt.Printf("JSON report saved to %s\n", filename)
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

func init() {
    // Increase file descriptor limits
    var rLimit syscall.Rlimit
    syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    rLimit.Cur = 100000
    syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
}

type proxyTarget struct {
    host string
    port string
}

// Then modify your bulkPreCheck function like this:
func bulkPreCheck(proxies []string, timeout time.Duration) []string {
    // Pre-process all targets first
    targets := make([]proxyTarget, 0, len(proxies))
    for _, p := range proxies {
        host, port, err := net.SplitHostPort(p)
        if err == nil {
            targets = append(targets, proxyTarget{host, port})
        }
    }
    
    total := len(targets)
    if total == 0 {
        return []string{}
    }
    var wgPrefetch sync.WaitGroup
    for _, p := range proxies {
        wgPrefetch.Add(1)
        go func(proxy string) {
            defer wgPrefetch.Done()
            host, _, err := net.SplitHostPort(proxy)
            if err == nil {
                cachedLookup(context.Background(), host)
            }
        }(p)
    }
    var processed int64
    var aliveCount int64
    valid := make(chan string, total)
    var wg sync.WaitGroup

    // Progress updater
    done := make(chan bool)
    go func() {
        defer close(done)
        ticker := time.NewTicker(500 * time.Millisecond)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                current := atomic.LoadInt64(&processed)
                alive := atomic.LoadInt64(&aliveCount)
                
                width := 40
                percent := float64(current)/float64(total)
                bars := int(percent * float64(width))
                
                fmt.Printf("\rPrechecking [%s%s] %d/%d | Alive: %d (%.1f%%)", 
                    strings.Repeat("█", bars),
                    strings.Repeat("░", width-bars),
                    current, total,
                    alive,
                    percent*100)
                
            case <-done:
                return
            }
        }
    }()

    // Check workers
    sem := make(chan struct{}, 200)
    for _, proxy := range proxies {
        wg.Add(1)
        go func(p string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            if quickProxyCheck(p, timeout) {
                atomic.AddInt64(&aliveCount, 1)
                valid <- p
            }
            atomic.AddInt64(&processed, 1)
        }(proxy)
    }
    
    go func() {
        wg.Wait()
        close(valid)
        done <- true
        fmt.Println() // Newline after progress bar
    }()

    var alive []string
    for v := range valid {
        alive = append(alive, v)
    }
    return alive
}

func startProgressUpdater(ctx context.Context) {
    go func() {
        ticker := time.NewTicker(200 * time.Millisecond)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                total := atomic.LoadInt64(&globalProgress.Total)
                processed := atomic.LoadInt64(&globalProgress.Processed)
                success := atomic.LoadInt64(&globalProgress.Success)
                failures := atomic.LoadInt64(&globalProgress.Failures)
                errors := atomic.LoadInt64(&globalProgress.Errors)
                
                // Add safety check
                if total == 0 {
                    fmt.Printf("\r[%s] Initializing...", strings.Repeat("░", 40))
                    continue
                }
                
                percent := float64(processed)/float64(total)
                bars := int(percent * 40)
                
                fmt.Printf("\r[%s%s] %d/%d | ↑%d ↓%d !%d (%.1f%%)",
                    strings.Repeat("█", bars),
                    strings.Repeat("░", 40-bars),
                    processed, total,
                    success, failures, errors,
                    percent*100)
                
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

const downloadedProxyFile = "http_proxies_zgeo.txt"

func downloadProxies() bool {
    const proxyURL = "https://raw.githubusercontent.com/zgeo-proxy-checker/public-proxy-list/main/http.txt"
    
    // Check existing file first
    if info, err := os.Stat(downloadedProxyFile); err == nil {
        if time.Since(info.ModTime()) < 2*time.Hour {
            fmt.Printf("Using recent proxies (%s old)\n", time.Since(info.ModTime()).Round(time.Minute))
            return true
        }
    }
    fmt.Print("\nNo proxy list found. Download default proxies? (y/n): ")
    
    var response string
    _, err := fmt.Scanln(&response)
    if err != nil || strings.ToLower(response) != "y" {
        return false
    }

    client := &http.Client{
        Timeout: 15 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    req, _ := http.NewRequest("GET", 
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt", nil)
    req.Header.Set("User-Agent", "zgeo-proxy-checker")

    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Download failed: %v\n", err)
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        fmt.Printf("Bad response status: %d\n", resp.StatusCode)
        return false
    }

    file, err := os.Create(downloadedProxyFile)
    if err != nil {
        fmt.Printf("File creation error: %v\n", err)
        return false
    }
    defer file.Close()

    if _, err := io.Copy(file, resp.Body); err != nil {
        fmt.Printf("Download write failed: %v\n", err)
        return false
    }

    fmt.Printf("\nSuccessfully downloaded proxies to %s\n", downloadedProxyFile)
    return true
}

func getSystemLoadAverage() float64 {
    // Linux-specific implementation
    data, err := os.ReadFile("/proc/loadavg")
    if err != nil {
        return 0.0
    }
    
    load, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
    return load
}


func (bm *BatchManager) AdjustInBackground() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        // Use default adjustment when called from background
        bm.AdjustBatchSize(50) // Default incremental adjustment
    }
}



func processBatch(batch []string, config Config) {
    ctx := context.Background()
    pool := createWorkerPool(ctx, config)
    defer pool.Stop()
    
    var batchResults []ProxyInfo
    var wg sync.WaitGroup // Declaração local
    
    wg.Add(1)
    go func() {
        defer wg.Done()
        for result := range pool.Results() {
            batchResults = append(batchResults, result)
            if config.Verbose {
                printProxyInfo(result)
            }
        }
    }()

    for _, proxy := range batch {
        pool.jobs <- Job{Proxy: proxy, Retries: config.Retries}
    }

    close(pool.jobs)
    wg.Wait()
}


func (bm *BatchManager) RecordBatch(size int) {}

func (bm *BatchManager) GetBatchSize() int {
    bm.mu.Lock()
    defer bm.mu.Unlock()
    return bm.currentBatch
}

func processBatches(proxies []string, config Config) {
    bm := &BatchManager{
        currentBatch: 100,
        maxBatch:     1000,
    }
    
    // Metrics tracking
    var (
        totalProxies  uint64
        successCount  uint64
        failureCount  uint64
        retryCount    uint64
        currentBatch  uint64
    )

    // Setup metrics collection ticker
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    go func() {
        for range ticker.C {
            // Get snapshot of metrics
            tp := atomic.LoadUint64(&totalProxies)
            sc := atomic.LoadUint64(&successCount)
            rc := atomic.LoadUint64(&retryCount)
            cb := atomic.LoadUint64(&currentBatch)

            // Calculate success rate
            successRate := 0.0
            if tp > 0 {
                successRate = float64(sc) / float64(tp)
            }

            // Calculate retry density
            retryDensity := 0.0
            if cb > 0 {
                retryDensity = float64(rc) / float64(cb)
            }

            // Update batch manager
            bm.updateBatchMetrics(successRate, int(retryDensity))

            // Log debug info
            if config.Verbose {
                fmt.Printf(
                    "[Batch Metrics] Size: %d Success: %.1f%% Retries/batch: %.1f\n",
                    bm.currentBatch,
                    successRate*100,
                    retryDensity,
                )
            }

            // Rotate metrics
            atomic.StoreUint64(&currentBatch, 0)
            atomic.StoreUint64(&retryCount, 0)
        }
    }()

    // Main processing loop
    for len(proxies) > 0 {
        batchSize := bm.GetBatchSize()
        end := min(batchSize, len(proxies))
        batch := proxies[:end]
        proxies = proxies[end:]

        // Create batch-specific metrics
        var (
            batchSuccess uint64
            batchFailure uint64
            batchRetries uint64
        )

        // Create worker pool with batch context
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()
        
        pool := createWorkerPool(ctx, config)
        go func() {
            for _, proxy := range proxies {
                select {
                case pool.jobs <- Job{Proxy: proxy, Retries: config.Retries}:
                case <-ctx.Done():
                    return
                }
            }
            defer close(pool.jobs)
        }()

        // Process results
        for result := range pool.results {
            atomic.AddUint64(&totalProxies, 1)
            
            if result.Status == "UP" {
                atomic.AddUint64(&batchSuccess, 1)
            } else {
                atomic.AddUint64(&batchFailure, 1)
            }

            // Update retry count from result metadata
            if result.Retries > 0 {
                atomic.AddUint64(&batchRetries, uint64(result.Retries))
            }
        }

        // Commit batch metrics
        atomic.AddUint64(&successCount, batchSuccess)
        atomic.AddUint64(&failureCount, batchFailure)
        atomic.AddUint64(&retryCount, batchRetries)
        atomic.AddUint64(&currentBatch, uint64(len(batch)))

        // Cleanup
        pool.Stop()
        cancel()
    }
}

func (bm *BatchManager) updateBatchMetrics(successRate float64, retryCount int) {
    bm.mu.Lock()
    defer bm.mu.Unlock()

    // Adaptive scaling based on success rate and retries
    const (
        upperThreshold = 0.85 // 85% success rate
        lowerThreshold = 0.65 // 65% success rate
        maxStep        = 150
        minStep        = 50
    )

    // Calculate performance ratio
    perfRatio := successRate - (float64(retryCount) * 0.01)

    switch {
    case perfRatio > upperThreshold:
        // Scale up aggressively
        step := int(float64(maxStep) * (perfRatio - upperThreshold))
        bm.currentBatch = min(bm.currentBatch+step, bm.maxBatch)
        
    case perfRatio < lowerThreshold:
        // Scale down conservatively
        step := int(float64(maxStep) * (lowerThreshold - perfRatio))
        bm.currentBatch = max(bm.currentBatch-step, minStep)
        
    default:
        // Linear scaling between thresholds
        scaleFactor := (perfRatio - lowerThreshold) / (upperThreshold - lowerThreshold)
        step := int(float64(maxStep-minStep) * scaleFactor)
        bm.currentBatch = clamp(bm.currentBatch+step, minStep, bm.maxBatch)
    }

    // Jitter injection for herd immunity
    jitter := rand.Intn(21) - 10 // ±10% variation
    bm.currentBatch = bm.currentBatch * (100 + jitter) / 100

    // Hard limits enforcement
    bm.currentBatch = max(min(bm.currentBatch, bm.maxBatch), 50)

    // Continuous feedback integration
    if successRate > 0.9 && bm.currentBatch < bm.maxBatch {
        bm.currentBatch = min(bm.currentBatch+25, bm.maxBatch)
    }
    
    if retryCount > 50 && bm.currentBatch > 100 {
        bm.currentBatch = max(bm.currentBatch-25, 100)
    }
}

// Helper clamp function
func clamp(value, min, max int) int {
    if value < min {
        return min
    }
    if value > max {
        return max
    }
    return value
}


type DynamicThrottler struct {
    mu             sync.Mutex
    currentLimiter *rate.Limiter
    maxRPS         int
    loadAverage    float64
}

func NewThrottler(initialRPS int) *DynamicThrottler {
    return &DynamicThrottler{
        currentLimiter: rate.NewLimiter(rate.Limit(initialRPS), initialRPS*3),
        maxRPS:         initialRPS,
    }
}

func (dt *DynamicThrottler) MonitorSystem() {
    ticker := time.NewTicker(5 * time.Second)
    
    for range ticker.C {
        load := getSystemLoad()
        dt.mu.Lock()
        dt.loadAverage = load
        
        newLimit := dt.calculateNewLimit()
        dt.currentLimiter.SetLimit(rate.Limit(newLimit))
        dt.currentLimiter.SetBurst(newLimit)
        
        dt.mu.Unlock()
    }
}

func getSystemLoad() float64 {
    load, err := os.ReadFile("/proc/loadavg")
    if err != nil {
        return 0.0
    }
    fields := strings.Fields(string(load))
    if len(fields) > 0 {
        load1, _ := strconv.ParseFloat(fields[0], 64)
        return load1
    }
    return 0.0
}


func (dt *DynamicThrottler) calculateNewLimit() int {
    switch {
    case dt.loadAverage > 80:
        return max(dt.maxRPS/2, 10)
    case dt.loadAverage > 60:
        return int(float64(dt.maxRPS) * 0.8)
    default:
        return dt.maxRPS
    }
}

func (dt *DynamicThrottler) Wait(ctx context.Context) error {
    dt.mu.Lock()
    limiter := dt.currentLimiter
    dt.mu.Unlock()
    
    return limiter.Wait(ctx)
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
