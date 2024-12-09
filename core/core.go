/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/manetu/security-token/config"
)

// Check panics if err != nil
func Check(e error) {
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

// HexEncode encodes the raw bytes into hex
func HexEncode(b []byte) string {
	var buf bytes.Buffer
	for i, f := range b {
		if i > 0 {
			_, _ = fmt.Fprintf(&buf, ":")
		}
		_, _ = fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

func importHexencode(serial string) []byte {
	reg, err := regexp.Compile(":")
	Check(err)

	striped := reg.ReplaceAllString(serial, "")
	b, err := hex.DecodeString(striped)
	Check(err)

	return b
}

// ExportCert exports the certificate into a PEM string
func ExportCert(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

type Core struct {
	sync.Mutex
	configuration config.Configuration
	pkcs11Ctx     *crypto11.Context
}

func New() *Core {
	core := &Core{}

	return core
}

// get crypto config on need and store it
func (c *Core) getCryptoCtx() *crypto11.Context {
	c.Lock()
	defer c.Unlock()

	if c.pkcs11Ctx != nil {
		return c.pkcs11Ctx
	}

	viper.SetConfigName("security-tokens")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.manetu")
	viper.AddConfigPath("/etc/manetu/")

	err := viper.ReadInConfig()
	Check(err)

	err = viper.Unmarshal(&c.configuration)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}

	// Configure PKCS#11 library via configuration file
	c.pkcs11Ctx, err = crypto11.Configure(&crypto11.Config{
		Path:       c.configuration.Pkcs11.Path,
		TokenLabel: c.configuration.Pkcs11.TokenLabel,
		Pin:        c.configuration.Pkcs11.Pin,
	})

	Check(err)

	fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())

	return c.pkcs11Ctx
}

func (c *Core) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.pkcs11Ctx == nil {
		return nil
	}

	return c.pkcs11Ctx.Close()
}

type Token struct {
	Signer crypto11.Signer
	Cert   *x509.Certificate
}

func (c *Core) getToken(serial string) (*Token, error) {

	var id []byte

	if serial == "" {
		certs, err := c.getCryptoCtx().FindAllPairedCertificates()
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

	signer, err := c.getCryptoCtx().FindKeyPair(id, nil)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("invalid serial number")
	}

	cert, err := c.getCryptoCtx().FindCertificate(id, nil, nil)
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

func (c *Core) Show(serial string) error {
	token, err := c.getToken(serial)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", ExportCert(token.Cert))
	return nil
}

func (c *Core) List() error {
	certs, err := c.getCryptoCtx().FindAllPairedCertificates()
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Serial", "Realm", "Created"})

	for _, x := range certs {
		cert := x.Leaf
		// there may multiple realms in future ?
		realms := cert.Subject.Organization[0]
		for i := 1; i < len(cert.Subject.Organization); i++ {
			realms += "," + cert.Subject.Organization[i]
		}
		table.Append([]string{HexEncode(cert.SerialNumber.Bytes()), realms, cert.NotBefore.String()})
	}
	table.Render() // Send output
	return nil
}

// ComputeMRN computes MRN given certificate
func ComputeMRN(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return "mrn:iam:" + cert.Subject.Organization[0] + ":identity:" + hex.EncodeToString(hash[:])
}

func (c *Core) Generate(realm string) (*x509.Certificate, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	signer, err := c.getCryptoCtx().GenerateECDSAKeyPair(id, elliptic.P256())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	duration := time.Hour * 24 * 3650
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(id),
		Subject: pkix.Name{
			Organization: []string{realm},
			SerialNumber: HexEncode(id),
		},
		NotBefore:             now,
		NotAfter:              now.Add(duration),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	cp := x509.NewCertPool()
	cp.AddCert(cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: cp,
	})
	if err != nil {
		return nil, err
	}

	err = c.getCryptoCtx().ImportCertificate(id, cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *Core) Delete(serial string) error {
	id := importHexencode(serial)

	err := c.getCryptoCtx().DeleteCertificate(id, nil, nil)
	if err != nil {
		return err
	}

	signer, err := c.getCryptoCtx().FindKeyPair(id, nil)
	if err != nil {
		return err
	}

	if signer == nil {
		_, _ = fmt.Fprint(os.Stderr, "ERROR: Invalid serial number")
		return nil
	}

	return signer.Delete()
}

func (c *Core) Login(tokenUrl string, insecure bool, audience string, signer crypto.Signer, cert *x509.Certificate) (string, error) {
	mrn := ComputeMRN(cert)
	tokenUrl, err := url.JoinPath(tokenUrl, "/oauth/token")
	if err != nil {
		return "", err
	}
	if len(audience) == 0 {
		audience = tokenUrl
	}
	cajwt, err := createJWT(signer, mrn, audience)
	if err != nil {
		return "", err
	}

	jwt, err := login(cajwt, mrn, tokenUrl, insecure)
	if err != nil {
		return "", err
	}

	return jwt, err
}

func (c *Core) LoginPKCS11(url string, insecure bool, audience string, serial string) (string, error) {
	token, err := c.getToken(serial)
	if err != nil {
		return "", err
	}

	return c.Login(url, insecure, audience, token.Signer, token.Cert)
}

func (c *Core) pathToBytes(path string) ([]byte, error) {
	return os.ReadFile(filepath.Clean(path))
}

func (c *Core) LoginX509(url string, insecure bool, audience string, key string, cert string, path bool) (string, error) {
	var (
		kBytes []byte
		cBytes []byte
		err    error
	)

	if path {
		kBytes, err = c.pathToBytes(key)
		if err != nil {
			return "", err
		}
		cBytes, err = c.pathToBytes(cert)
		if err != nil {
			return "", err
		}
	} else {
		kBytes = []byte(key)
		cBytes = []byte(cert)
	}

	getSigner := func(key []byte) (crypto.Signer, error) {
		block, _ := pem.Decode(key)
		if block == nil {
			return nil, fmt.Errorf("error decoding key")
		}

		//try as EC block
		signer, inerr := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported private key: %s", inerr)
		}

		if signer == nil {
			//fall back to generic
			a, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			var (
				ok bool
			)

			if signer, ok = a.(*ecdsa.PrivateKey); !ok {
				return nil, fmt.Errorf("unsupported private key")
			}
		}
		return signer, nil
	}

	signer, err := getSigner(kBytes)
	if err != nil {
		return "", err
	}

	certB, _ := pem.Decode(cBytes)
	xCert, err := x509.ParseCertificate(certB.Bytes)
	if err != nil {
		return "", fmt.Errorf("error parsing cert: %s", err)
	}

	return c.Login(url, insecure, audience, signer, xCert)
}

func decodeP12(p12Data []byte, password string) (*x509.Certificate, crypto.Signer, error) {
	privateKey, cert, err := pkcs12.Decode(p12Data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding PKCS#12 file: %v", err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("private key is not a crypto.Signer")
	}

	if cert == nil {
		return nil, nil, errors.New("certificate not found in PKCS#12 file")
	}

	return cert, signer, nil
}

func (c *Core) LoginPKCS12(url string, insecure bool, audience string, p12 string, password string, path bool) (string, error) {
	var p12Bytes []byte
	var err error

	if path {
		p12Bytes, err = c.pathToBytes(p12)
		if err != nil {
			return "", fmt.Errorf("failed to read .p12 file: %v", err)
		}
	} else {
		p12Bytes = []byte(p12)
	}

	cert, signer, err := decodeP12(p12Bytes, password)
	if err != nil {
		return "", err
	}

	return c.Login(url, insecure, audience, signer, cert)
}
