package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spaolacci/murmur3"
	"golang.org/x/net/html"
)

type MassDNSOutput struct {
	Name string `json:"name"`
	Data struct {
		Answers []struct {
			Type string `json:"type"`
			Data string `json:"data"`
		} `json:"answers"`
	} `json:"data"`
}

type DNSResponse struct {
	domain string
	ips    []net.IP
}

type Fingerprint struct {
	Domain        string   `json:"domain"`
	Status        int      `json:"status_code"`
	Url           string   `json:"url"`
	Title         string   `json:"title"`
	ContentLength int64    `json:"content_length"`
	Murmur        int32    `json:"favicon_hash"`
	Ips           []string `json:"A"`
}

var resolvers []string

const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

// Function from https://github.com/projectdiscovery/httpx/blob/b14f64a9e1374c5cf36304eec41999c201156932/common/stringz/stringz.go#L132
func InsertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}

func doFingerprinting(dnsResponses <-chan DNSResponse, results chan<- Fingerprint) {
	var (
		dnsResolverIP        = resolvers[rand.Intn(len(resolvers))] + ":53"
		dnsResolverProto     = "udp"
		dnsResolverTimeoutMs = 5000
	)
	resolvedHostname := "example.com"
	resolvedIP := "0.0.0.0"

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host != resolvedHostname {
			return dialer.DialContext(ctx, network, addr)
		}

		return dialer.DialContext(ctx, network, resolvedIP+":"+port)
	}

	tr := &http.Transport{
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext:           dialContext,
	}
	client := &http.Client{Timeout: 25 * time.Second, Transport: tr}

	for response := range dnsResponses {
		var domain = strings.TrimSpace(response.domain)
		if strings.Contains(domain, "*.") {
			domain = strings.ReplaceAll(domain, "*.", "")
		}
		fingerprint := Fingerprint{Domain: domain}
		resolvedIP = response.ips[0].String()
		resolvedHostname = fingerprint.Domain

		// Try https and http and get index page
		protocol := "https"
		req, err := http.NewRequest("GET", "https://"+fingerprint.Domain, nil)
		if err != nil {
			continue
		}
		req.Header.Add("User-Agent", USER_AGENT)
		resp, err := client.Do(req)

		if err != nil {
			req, err := http.NewRequest("GET", "http://"+fingerprint.Domain, nil)
			if err != nil {
				continue
			}
			req.Header.Add("User-Agent", USER_AGENT)
			resp, err = client.Do(req)
			if err != nil {
				continue
			}
			protocol = "http"
		}

		fingerprint.Status = resp.StatusCode
		fingerprint.Url = resp.Request.URL.String()
		fingerprint.ContentLength = resp.ContentLength

		// Read only 256K of response
		bodyReader := io.LimitReader(resp.Body, 256*1024)

		// Parse title and favicon URL if present
		var isTitle bool
		title := ""
		faviconUrl := ""

		tokenizer := html.NewTokenizer(bodyReader)
		for {
			tokenType := tokenizer.Next()

			if tokenType == html.ErrorToken || (title != "" && faviconUrl != "") {
				break
			} else if tokenType == html.StartTagToken {
				token := tokenizer.Token()
				tagName := token.Data
				isTitle = tagName == "title"
				if tagName == "link" && faviconUrl == "" {
					// Converting tag attributes to a map
					attributes := make(map[string]string)
					for _, attr := range token.Attr {
						attributes[attr.Key] = attr.Val
					}

					if attributes["rel"] == "icon" {
						faviconUrl = attributes["href"]
					}
				}
			} else if tokenType == html.TextToken {
				if isTitle {
					title = strings.TrimSpace(tokenizer.Token().Data)
					isTitle = false
				}
			}
		}

		fingerprint.Title = title

		// Getting absolute favicon URL
		responseURL, err := url.Parse(fingerprint.Url)
		if err != nil {
			responseURL, _ = url.Parse(protocol + "://" + fingerprint.Domain + "/")
		}

		if faviconUrl != "" {
			parsedFaviconUrl, err := url.Parse(faviconUrl)
			if err != nil {
				responseURL.Path = "/favicon.ico"
				faviconUrl = responseURL.String()
			} else {
				faviconUrl = responseURL.ResolveReference(parsedFaviconUrl).String()
			}
		} else {
			responseURL.Path = "/favicon.ico"
			faviconUrl = responseURL.String()
		}

		// Get favicon
		req, err = http.NewRequest("GET", faviconUrl, nil)
		if err != nil {
			fingerprint.Murmur = 0
		} else {
			req.Header.Add("User-Agent", USER_AGENT)
			faviconResp, err := client.Do(req)

			if err != nil {
				fingerprint.Murmur = 0
			} else {
				faviconBody, err := io.ReadAll(io.LimitReader(faviconResp.Body, 1*1024*1024))
				if err != nil {
					fingerprint.Murmur = 0
				} else {
					faviconBase64 := base64.StdEncoding.EncodeToString(faviconBody)
					faviconBase64 = InsertInto(faviconBase64, 76, '\n')
					fingerprint.Murmur = int32(murmur3.Sum32([]byte(faviconBase64)))
				}
				faviconResp.Body.Close()
			}
		}

		for _, ip := range response.ips {
			fingerprint.Ips = append(fingerprint.Ips, ip.String())
		}

		results <- fingerprint

		// Get new resolver
		dnsResolverIP = resolvers[rand.Intn(len(resolvers))] + ":53"
	}
}

func main() {
	rand.Seed(time.Now().Unix())
	// log.SetOutput(io.Discard) // To get rid of "Unsolicited response received on" messages

	args := os.Args[1:]
	if len(args) != 3 {
		fmt.Printf("usage: %s <resolvers path> <massdns ndjson output> <thread count>\n", os.Args[0])
		os.Exit(2)
	}

	resolversPath := args[0]
	domainsPath := args[1]
	threadCount, err := strconv.Atoi(args[2])
	if err != nil {
		log.Panicf("Error parsing thread count: %s", args[2])
	}

	log.Println("Loading resolver list")
	file, err := os.Open(resolversPath)
	if err != nil {
		log.Panicf("Error loading resolver list from %s", resolversPath)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		resolvers = append(resolvers, scanner.Text())
	}

	domains := make(chan DNSResponse)
	results := make(chan Fingerprint)

	// Go over a file line by line and queue up domains
	log.Println("Starting sending domains to channel")
	go func() {
		file, err := os.Open(domainsPath)
		if err != nil {
			log.Panicf("Error loading domain list from %s", domainsPath)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			massdnsJson := scanner.Text()
			massdnsOutput := MassDNSOutput{}
			err := json.Unmarshal([]byte(massdnsJson), &massdnsOutput)
			if err != nil {
				log.Printf("Error reading massdns ndjson: %s", massdnsJson)
				continue
			}
			var ips []net.IP
			for _, answer := range massdnsOutput.Data.Answers {
				if answer.Type == "A" {
					ips = append(ips, net.ParseIP(answer.Data))
				}
			}

			if len(ips) > 0 {
				domains <- DNSResponse{domain: massdnsOutput.Name[:len(massdnsOutput.Name)-1], ips: ips}
			}
		}
		close(domains)
	}()

	// Start workers
	var wg sync.WaitGroup

	log.Println("Starting workers")
	for i := 0; i < threadCount; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			doFingerprinting(domains, results)
		}()
	}

	// Wait for workers to finish and close channel
	go func() {
		wg.Wait()
		close(results)
	}()

	log.Println("Receiving results")
	count := int64(0)
	startTime := time.Now().UnixMilli()
	lastTime := time.Now().UnixMilli()
	for result := range results {
		jsonOutput, _ := json.Marshal(result)
		fmt.Printf("%s\n", jsonOutput)
		count++
		if count%1500 == 0 {
			curTime := time.Now().UnixMilli()
			avgSpeed := float64(count) / (float64(curTime-startTime) / 1000)
			lastSpeed := 1500.0 / (float64(curTime-lastTime) / 1000)
			lastTime = curTime

			log.Printf("%d domains processed. Avg speed: %.2f it/s, Last batch speed: %.2f it/s\n", count, avgSpeed, lastSpeed)
		}
	}
	log.Println("All results received, processing done")
}
