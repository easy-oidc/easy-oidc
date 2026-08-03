// Easy OIDC <https://easy-oidc.dev>
// Copyright The Easy OIDC Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
)

// main serves the E2E issuer and alternates requests between the configured Easy
// OIDC replicas. Routing each request independently verifies that OIDC flows
// work across replicas sharing PostgreSQL state.
func main() {
	listenAddress := flag.String("listen", "", "proxy listen address")
	flag.Parse()
	if *listenAddress == "" || flag.NArg() < 2 {
		log.Fatal("usage: test-rr-proxy -listen address target1 target2 [target...]")
	}

	targets := make([]*url.URL, 0, flag.NArg())
	for _, value := range flag.Args() {
		target, err := url.Parse(value)
		if err != nil || target.Scheme == "" || target.Host == "" {
			log.Fatalf("invalid target %q", value)
		}
		targets = append(targets, target)
	}
	var next atomic.Uint64
	proxy := &httputil.ReverseProxy{Director: func(request *http.Request) {
		target := targets[(next.Add(1)-1)%uint64(len(targets))]
		request.URL.Scheme = target.Scheme
		request.URL.Host = target.Host
		request.Host = target.Host
	}}
	log.Fatal(http.ListenAndServe(*listenAddress, proxy))
}
