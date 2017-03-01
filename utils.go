package main

import (
	"crypto/tls"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type CertsReloader struct {
	certLock sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func NewCertsReloader(certPath, keyPath string) (*CertsReloader, error) {
	result := &CertsReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	go result.onReload()

	return result, nil
}

func (reloader *CertsReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(reloader.certPath, reloader.keyPath)
	if err != nil {
		return err
	}
	reloader.certLock.Lock()
	defer reloader.certLock.Unlock()
	logger.Info("Reload new certificates", reloader.certPath, reloader.keyPath)
	reloader.cert = &cert
	return nil
}

func (reloader *CertsReloader) onReload() {
	listener := make(chan os.Signal, 1)
	signal.Notify(listener, syscall.SIGHUP)
	for range listener {
		logger.Info("Receive SIGHUP, reload certs...")
		if err := reloader.reload(); err != nil {
			logger.Info("Error while trying to load new certs : %s , %s, keeping old certificates",
				reloader.certPath, reloader.keyPath)
		}
	}
}

func (reloader *CertsReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		reloader.certLock.RLock()
		defer reloader.certLock.RUnlock()
		return reloader.cert, nil
	}
}
