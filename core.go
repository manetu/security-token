/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"regexp"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/viper"
	"gitlab.com/manetu/platform/manetu-security-token/config"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func randomID() ([]byte, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}

	return token, nil
}

func hexEncode(b []byte) string {
	var buf bytes.Buffer
	for i, f := range b {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

func importHexencode(serial string) []byte {
	reg, err := regexp.Compile(":")
	check(err)

	striped := reg.ReplaceAllString(serial, "")
	b, err := hex.DecodeString(striped)
	check(err)

	return b
}

func exportCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

type Core struct {
	ctx     *crypto11.Context
	Backend config.BackendConfiguration
}

func New() Core {
	viper.SetConfigName("security-tokens")
	viper.AddConfigPath("/etc/manetu/")
	viper.AddConfigPath("$HOME/.manetu")
	viper.AddConfigPath(".")
	var configuration config.Configuration

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
	err := viper.Unmarshal(&configuration)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}

	// Configure PKCS#11 library via configuration file
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       configuration.Pkcs11.Path,
		TokenLabel: configuration.Pkcs11.TokenLabel,
		Pin:        configuration.Pkcs11.Pin,
	})
	check(err)

	return Core{ctx: ctx, Backend: configuration.Backend}
}

func (c Core) Close() error {
	return c.ctx.Close()
}

type Token struct {
	Signer crypto11.Signer
	Cert   *x509.Certificate
}

func (c Core) getToken(serial string) (*Token, error) {

	var id []byte

	if serial == "" {
		certs, err := c.ctx.FindAllPairedCertificates()
		if err != nil {
			return nil, err
		}

		if len(certs) < 1 {
			return nil, errors.New("no security-tokens found")
		}

		id = certs[0].Leaf.SerialNumber.Bytes()
	} else {
		id = importHexencode(serial)
	}

	signer, err := c.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("invalid serial number")
	}

	cert, err := c.ctx.FindCertificate(id, nil, nil)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, errors.New("certificate not found")
	}

	return &Token{
		Signer: signer,
		Cert:   cert,
	}, nil
}

func (c Core) Show(serial string) {
	token, err := c.getToken(serial)
	check(err)

	fmt.Printf("%s\n", exportCert(token.Cert))
}

func (c Core) List() {
	certs, err := c.ctx.FindAllPairedCertificates()
	check(err)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Serial", "Created"})

	for _, x := range certs {
		cert := x.Leaf
		table.Append([]string{hexEncode(cert.SerialNumber.Bytes()), cert.NotBefore.String()})
	}
	table.Render() // Send output
}

func (c Core) computeMRN(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return "mrn:iam:" + cert.Subject.Organization[0] + ":identity:" + hex.EncodeToString(hash[:])
}

func (c Core) Generate() {
	id, err := randomID()
	check(err)

	signer, err := c.ctx.GenerateECDSAKeyPair(id, elliptic.P256())
	check(err)

	now := time.Now()
	duration := time.Hour * 24 * 3650
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(id),
		Subject: pkix.Name{
			Organization: []string{c.Backend.ProviderID},
			SerialNumber: hexEncode(id),
		},
		NotBefore:             now,
		NotAfter:              now.Add(duration),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	check(err)

	cert, err := x509.ParseCertificate(der)
	check(err)

	cp := x509.NewCertPool()
	cp.AddCert(cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: cp,
	})
	check(err)

	err = c.ctx.ImportCertificate(id, cert)
	check(err)

	fmt.Printf("Serial: %s\n", hexEncode(cert.SerialNumber.Bytes()))
	fmt.Printf("MRN: %s\n", c.computeMRN(cert))

	fmt.Printf("%s\n", exportCert(cert))
}

func (c Core) Delete(serial string) {
	id := importHexencode(serial)

	err := c.ctx.DeleteCertificate(id, nil, nil)
	check(err)

	signer, err := c.ctx.FindKeyPair(id, nil)
	check(err)
	if signer == nil {
		fmt.Fprint(os.Stderr, "ERROR: Invalid serial number")
		return
	}

	err = signer.Delete()
	check(err)
}

func (c Core) Login(serial string) {
	token, err := c.getToken(serial)
	check(err)

	mrn := c.computeMRN(token.Cert)

	cajwt, err := createJWT(token.Signer, mrn, c.Backend.TokenURL)
	check(err)

	jwt, err := login(cajwt, mrn, c.Backend.TokenURL)
	check(err)
	fmt.Printf("%s\n", jwt)
}
