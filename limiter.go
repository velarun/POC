package main

import (
	"log"
	"time"
)

// Stores last requests IPs
var lastRequestsIPs []string

// Block IP for 1 Minute
var blockedIPs []string

func existsBlockedIP(ipAddr string) bool {
	for _, ip := range blockedIPs {
		if ip == ipAddr {
			return true
		}
	}
	return false
}

func existsLastRequest(ipAddr string) bool {
	for _, ip := range lastRequestsIPs {
		if ip == ipAddr {
			return true
		}
	}
	return false
}

// Clears lastRequestsIPs array every 1 mins
func clearLastRequestsIPs() {
	for {
		lastRequestsIPs = []string{}
		time.Sleep(time.Minute * 1)
	}
}

// Clears blockedIPs array every 1 hours
func clearBlockedIPs() {
	for {
		log.Println("Blocked IP List:", blockedIPs)
		blockedIPs = []string{}
		time.Sleep(time.Minute * 1)
	}
}
