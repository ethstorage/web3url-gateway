package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

type ExtendCache struct {
	autocert.DirCache
}

func (c *ExtendCache) Get(ctx context.Context, name string) ([]byte, error) {
	return c.DirCache.Get(ctx, name)
}

func (c *ExtendCache) Put(ctx context.Context, name string, data []byte) error {
	return c.DirCache.Put(ctx, name, data)
}

func (c *ExtendCache) Delete(ctx context.Context, name string) error {
	return c.DirCache.Delete(ctx, name)
}

var (
	cache = &ExtendCache{
		DirCache: autocert.DirCache("certs"), //folder for storing certificates
	}
	certManager = autocert.Manager{
		Prompt: autocert.AcceptTOS,
		// HostPolicy: autocert.HostWhitelist(domain),
		HostPolicy: func(ctx context.Context, host string) error {
			return nil
		}, //your domain here
		Cache: cache,
		Email: config.AutoCertEmail,
	}
)

func getCertFromPath(domain, path string) (*tls.Certificate, error) {

	var (
		err  error
		data []byte
		cert tls.Certificate
	)

	if data, err = os.ReadFile(path); err != nil {
		return nil, err
	}

	if cert, err = tls.X509KeyPair(data, data); err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}

	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}

	if cert.Leaf.VerifyHostname(domain) != nil {
		return nil, fmt.Errorf("certificate not match %s", domain)

	}

	if cert.Leaf.NotAfter.Before(cert.Leaf.NotBefore) {
		return nil, fmt.Errorf("certificate expired %s", domain)
	}

	return &cert, nil
}

func domainSysCertPath(domain string) string {
	return strings.Join([]string{domain, "cert.path"}, "-")
}

func tryFindSystemCertificate(domain string) (*tls.Certificate, error) {

	var (
		findCert          *tls.Certificate = nil
		err               error
		domainSysCertPath = domainSysCertPath(domain)
	)

	if path, err := cache.Get(context.Background(), domainSysCertPath); err == nil && string(path) != "" {
		if findCert, err = getCertFromPath(domain, string(path)); findCert != nil && err == nil {
			return findCert, err
		} else {
			cache.Delete(context.Background(), domainSysCertPath)
		}
	}

	if config.SystemCertDir == "" {
		return nil, fmt.Errorf("no system cert dir")
	}

	if stat, err := os.Stat(config.SystemCertDir); err != nil {
		return nil, err
	} else if !stat.IsDir() {
		return nil, fmt.Errorf("system cert dir is not a dir")
	}

	filepath.WalkDir(config.SystemCertDir, func(path string, d os.DirEntry, err error) error {
		if err == nil {
			if findCert, err = getCertFromPath(domain, path); findCert != nil && err == nil {
				cache.Put(context.Background(), domainSysCertPath, []byte(path))
				return filepath.SkipDir
			}
		}
		return err
	})

	return findCert, err
}

func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert, err := tryFindSystemCertificate(hello.ServerName); err == nil && cert != nil {
		return cert, nil
	}
	return certManager.GetCertificate(hello)
}
