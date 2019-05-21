package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const ConnLimit = 50

var proxyConfig ProxyConfig

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// HandleHTTPS handles https traffic by opening tunnel to destination
func (r HttpReq) HandleHTTPS() {

	// Authorization using http headers
	value := r.Request.Header.Get("Authorization")

	if value != "null" || value != " " {
		if strings.ContainsAny(value, apikey) {
			r.Request.Header.Set("Authorization", proxyConfig.Apikey)
		} else if strings.ContainsAny(value, accesstoken) {
			r.Request.Header.Set("Authorization", proxyConfig.AccessToken)
		} else if strings.ContainsAny(value, basic) {
			r.Request.Header.Set("Authorization", "Basic "+basicAuth(proxyConfig.Username, proxyConfig.Password))
		} else {
			r.Request.Header.Set("Authorization", "null")
		}

		log.Println("Authorization using ", value, "with value ", r.Request.Header.Get("Authorization"))
	}

	destConn, err := net.DialTimeout("tcp", r.Request.Host, 60*time.Second)
	if err != nil {
		http.Error(r.Response, err.Error(), http.StatusServiceUnavailable)
		return
	}

	r.Response.WriteHeader(http.StatusOK)

	hijacker, ok := r.Response.(http.Hijacker)
	if !ok {
		http.Error(r.Response, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(r.Response, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)

}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func main() {
	pwd, _ := os.Getwd()
	jsonFile, err := os.Open(pwd + "/config.json")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Read config.json file successfully")
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(byteValue, &proxyConfig)

	var PEM string
	flag.StringVar(&PEM, "pem", proxyConfig.ServerPem, proxyConfig.CertLocation)

	var KEY string
	flag.StringVar(&KEY, "key", proxyConfig.ServerKey, proxyConfig.CertLocation)

	var proto string
	flag.StringVar(&proto, "proto", "https", "Proxy protocol https")
	flag.Parse()

	if proto != "https" {
		log.Fatal("Protocol should be https")
	}

	// Start the dispatcher.
	log.Println("Starting the dispatcher")
	StartDispatcher(ConnLimit)

	server := &http.Server{
		Addr:    proxyConfig.HTTPSPort,
		Handler: http.HandlerFunc(TaskRunner),

		// Read & write timeout of a http request
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,

		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServeTLS(PEM, KEY))
	//log.Fatal(server.ListenAndServe())

}
