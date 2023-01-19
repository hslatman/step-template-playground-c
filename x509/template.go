package x509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"

	"github.com/smallstep/certinfo"
)

func Execute(template string, commonName string) (*x509.Certificate, error) {

	if template == "" {
		return nil, errors.New("template can not be empty")
	}

	ca, err := minica.New(
		minica.WithName("Go Playground CA (powered by minica)"),
	)
	if err != nil {
		return nil, err
	}

	s, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		return nil, err
	}

	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, s)
	if err != nil {
		return nil, err
	}

	cr, err = x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	opts := []minica.SignOption{
		minica.WithTemplate(template),
	}

	c, err := ca.SignCSR(cr, opts...)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func Print(c *x509.Certificate) error {
	txt, err := certinfo.CertificateText(c)
	if err != nil {
		return err
	}

	fmt.Println(txt)

	return nil
}
