package main

import (
	"log"
	"net/http"
)

type WorkRequest interface {
	HandleHTTPS()
}

type HttpReq struct {
	Request  *http.Request
	Response http.ResponseWriter
}

var WorkQueue = make(chan WorkRequest, 100)

func TaskRunner(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		var work WorkRequest = HttpReq{Response: w, Request: r}

		WorkQueue <- work
		log.Println("Work request queued")
		log.Println("Established & Served https connection for Client -> ", getIP(r))
	} else {
		http.Error(w, "Blocked non-Https Traffic", http.StatusInternalServerError)
		log.Println("Blocked Establishing & Serving http request for Client -> ", getIP(r))
	}
}
