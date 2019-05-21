package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func main() {

	proxyURL, err := url.Parse("https://localhost:8888")
	if err != nil {
		panic(err)
	}

	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     5 * time.Second,
		DisableCompression:  true,

		//Disable HTTP/2
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	client := &http.Client{Transport: tr}

	start := time.Now()
	ch := make(chan string)
	for i := 0; i <= 100; i++ {
		go MakeRequest(client, ch)
	}

	for i := 0; i <= 100; i++ {
		fmt.Println(<-ch)
	}

	fmt.Printf("%.2fs elapsed\n", time.Since(start).Seconds())
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func MakeRequest(client *http.Client, ch chan<- string) {
	start := time.Now()
	req, _ := http.NewRequest("GET", "https://www.yu.io", nil)
	req.Header.Add("Authorization", "Basic "+basicAuth("username1", "password123"))
	resp, _ := client.Do(req)
	secs := time.Since(start).Seconds()
	ch <- fmt.Sprintf("%.2f elapsed with response length: %d %s", secs, resp)
}
