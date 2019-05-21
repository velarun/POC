# POC

Pre-requistie:

Golang should be installed. 

Version > 1.10.1

$ make

Certificate Generation:

use cert.sh file to generate pem and key.
Point out the location in config.json file

Add authorization key in config.json

Run:

$ ./proxyserver

use client/httpclient.go for testing

Sample:

Proxy:
$ go run proxyserver.go limiter.go common.go 
2019/05/12 19:40:58 Read config.json file successfully
2019/05/12 19:40:58 Blocked IP List: []


Client:

$ go run httpclient.go 
0.42 elapsed with response length: 0 %!s(MISSING)
0.42 elapsed with response length: 0 %!s(MISSING)
