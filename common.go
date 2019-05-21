package main

import "net/http"

// ProxyConfig struct
type ProxyConfig struct {
	HTTPSPort    string `json:"https_port"`
	ServerKey    string `json:"server_key"`
	ServerPem    string `json:"server_pem"`
	CertLocation string `json:"cert_location"`
	Apikey       string `json:"api_key"`
	AccessToken  string `json:"access_token"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

// Key parameters of authentication
const (
	apikey      = "api_key"
	accesstoken = "access_token"
	basic       = "basic"
)

func getIP(req *http.Request) (IPAddress string) {

	IPAddress = req.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = req.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = req.RemoteAddr
	}

	return
}
