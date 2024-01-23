package main

import (
	"context"

	"golang.org/x/crypto/acme/autocert"
)

var certManager = autocert.Manager{
	Prompt: autocert.AcceptTOS,
	// HostPolicy: autocert.HostWhitelist(domain),
	HostPolicy: func(ctx context.Context, host string) error {
		return nil
	}, //your domain here
	Cache: autocert.DirCache("certs"), //folder for storing certificates
	Email: "",
}
