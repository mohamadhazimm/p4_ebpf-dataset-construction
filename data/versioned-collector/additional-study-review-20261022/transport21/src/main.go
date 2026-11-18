// labtransport: one benign client and server that move the same HTTP requests over plain TCP,
// TLS 1.1, TLS 1.2, TLS 1.3 (HTTP/1.1 in each) and QUIC (HTTP/3), for the thesis's encrypted-traffic
// test. Only the transport changes between modes; the request pattern is fixed per workload.
//
//	labtransport server [-addr 10.0.0.1] [-base 9080]          ports: base plain, base+361..363 TLS 1.1..1.3, base+364/udp QUIC
//	labtransport client MODE WORKLOAD SERVER [-duration 16s]   MODE: http tls11 tls12 tls13 quic; WORKLOAD: poll session bulk
//
// Workloads: poll = a new connection every 1 s with one GET of 4 KiB (a beacon's pattern); session =
// one kept-alive connection, a GET of 1 KiB every 100 ms; bulk = a new connection per GET of 1 MiB,
// 0.5 s apart. The client stops at -duration and prints one JSON summary. The lab uses a self-signed
// certificate, so the client does not validate it (certificate checking is not what is measured).
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var tlsVersions = map[string]uint16{"tls11": tls.VersionTLS11, "tls12": tls.VersionTLS12, "tls13": tls.VersionTLS13}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// ---------------------------------------------------------------- server

func selfSigned(host string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

type logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (l *logger) log(v map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v["t"] = time.Now().UnixNano()
	_ = l.enc.Encode(v)
}

func handler(port int, lg *logger) http.Handler {
	block := make([]byte, 64*1024)
	for i := range block {
		block[i] = byte(i*131 + 7)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("n"))
		if err != nil || n < 0 || n > 8<<20 {
			n = 1024
		}
		ver := "plain"
		if r.TLS != nil {
			ver = versionName(r.TLS.Version)
		}
		lg.log(map[string]any{"port": port, "proto": r.Proto, "tls": ver, "remote": r.RemoteAddr, "path": r.URL.Path, "n": n})
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Header().Set("Content-Type", "application/octet-stream")
		for n > 0 {
			k := n
			if k > len(block) {
				k = len(block)
			}
			if _, err := w.Write(block[:k]); err != nil {
				return
			}
			n -= k
		}
	})
}

func server(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "10.0.0.1", "address to listen on")
	base := fs.Int("base", 9080, "plain HTTP port; TLS 1.1/1.2/1.3 on base+361..363, QUIC on base+364/udp")
	_ = fs.Parse(args)
	cert, err := selfSigned(*addr)
	if err != nil {
		return err
	}
	lg := &logger{enc: json.NewEncoder(os.Stdout)}
	errc := make(chan error, 5)
	plain := *base
	go func() {
		errc <- (&http.Server{Addr: net.JoinHostPort(*addr, strconv.Itoa(plain)), Handler: handler(plain, lg)}).ListenAndServe()
	}()
	for i, mode := range []string{"tls11", "tls12", "tls13"} {
		port := *base + 361 + i
		v := tlsVersions[mode]
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: v, MaxVersion: v, NextProtos: []string{"http/1.1"}}
		srv := &http.Server{Addr: net.JoinHostPort(*addr, strconv.Itoa(port)), Handler: handler(port, lg), TLSConfig: cfg,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
		go func() { errc <- srv.ListenAndServeTLS("", "") }()
	}
	qport := *base + 364
	go func() {
		srv := &http3.Server{Addr: net.JoinHostPort(*addr, strconv.Itoa(qport)), Handler: handler(qport, lg),
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})}
		errc <- srv.ListenAndServe()
	}()
	lg.log(map[string]any{"event": "ready", "addr": *addr, "plain": plain, "tls11": *base + 361, "tls12": *base + 362,
		"tls13": *base + 363, "quic": qport})
	return <-errc
}

// ---------------------------------------------------------------- client

type result struct {
	Mode, Workload, Server   string
	OK, Failed, Connections  int
	Bytes                    int64
	Versions                 map[string]int
	Errors                   map[string]int
	DurationS                float64
}

func newClient(mode string, keepAlive bool) (*http.Client, func(), error) {
	if mode == "quic" {
		tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
			QUICConfig: &quic.Config{}}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}, func() { _ = tr.Close() }, nil
	}
	tr := &http.Transport{DisableKeepAlives: !keepAlive, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	if v, ok := tlsVersions[mode]; ok {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: v, MaxVersion: v}
	} else if mode != "http" {
		return nil, nil, fmt.Errorf("unknown mode %q", mode)
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, func() { tr.CloseIdleConnections() }, nil
}

func url(mode, host string, n int) string {
	switch mode {
	case "http":
		return fmt.Sprintf("http://%s:9080/bytes?n=%d", host, n)
	case "tls11":
		return fmt.Sprintf("https://%s:9441/bytes?n=%d", host, n)
	case "tls12":
		return fmt.Sprintf("https://%s:9442/bytes?n=%d", host, n)
	case "tls13":
		return fmt.Sprintf("https://%s:9443/bytes?n=%d", host, n)
	}
	return fmt.Sprintf("https://%s:9444/bytes?n=%d", host, n)
}

func client(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: client MODE WORKLOAD SERVER [-duration 16s]")
	}
	mode, workload, host := args[0], args[1], args[2]
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	duration := fs.Duration("duration", 16*time.Second, "stop after this long")
	_ = fs.Parse(args[3:])
	var size int
	var gap time.Duration
	keep := false
	switch workload {
	case "poll":
		size, gap = 4096, time.Second
	case "session":
		size, gap, keep = 1024, 100*time.Millisecond, true
	case "bulk":
		size, gap = 1<<20, 500*time.Millisecond
	default:
		return fmt.Errorf("unknown workload %q", workload)
	}
	res := result{Mode: mode, Workload: workload, Server: host, Versions: map[string]int{}, Errors: map[string]int{}}
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(*duration))
	defer cancel()
	var c *http.Client
	var closeFn func()
	var err error
	if keep {
		if c, closeFn, err = newClient(mode, true); err != nil {
			return err
		}
		res.Connections = 1
	}
	for next := start; ctx.Err() == nil; next = next.Add(gap) {
		if d := time.Until(next); d > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
			if ctx.Err() != nil {
				break
			}
		}
		if !keep {
			if c, closeFn, err = newClient(mode, false); err != nil {
				return err
			}
			res.Connections++
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", url(mode, host, size), nil)
		resp, err := c.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				res.Failed++
				res.Errors[fmt.Sprintf("%T", err)]++
			}
		} else {
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			res.Bytes += n
			if resp.TLS != nil {
				res.Versions[versionName(resp.TLS.Version)+"/"+resp.Proto]++
			} else {
				res.Versions["plain/"+resp.Proto]++
			}
			if resp.StatusCode == 200 && n == int64(size) {
				res.OK++
			} else {
				res.Failed++
				res.Errors[fmt.Sprintf("status %d, %d bytes", resp.StatusCode, n)]++
			}
		}
		if !keep {
			closeFn()
		}
	}
	if keep {
		closeFn()
	}
	res.DurationS = time.Since(start).Seconds()
	return json.NewEncoder(os.Stdout).Encode(res)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labtransport server|client ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = server(os.Args[2:])
	case "client":
		err = client(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "labtransport:", err)
		os.Exit(1)
	}
}
