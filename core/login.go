/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	//lint:ignore SA1019 has dependency with clientcredentials
	"golang.org/x/oauth2/jws"

	"log"
)

func jwsHasher(pub crypto.PublicKey) (string, crypto.Hash, *elliptic.CurveParams) {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		switch pub.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256, pub.Params()
		default:
			log.Fatal("unsupported curve " + pub.Params().Name)
		}
	default:
		log.Fatal("unsupported signer type")
	}

	return "", 0, nil
}

func createJWT(signer crypto.Signer, subject, audience string) (string, error) {
	// Select alg parameter, hash function and signature size based on RFC7518
	alg, hasher, params := jwsHasher(signer.Public())

	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	now := time.Now()
	duration, _ := time.ParseDuration("30s")
	cs := &jws.ClaimSet{
		Iss: subject,
		Sub: subject,
		Aud: audience,
		Iat: now.Unix(),
		Exp: now.Add(duration).Unix(),
		PrivateClaims: map[string]interface{}{
			"jti": uuid.String(),
		},
	}
	hdr := &jws.Header{
		Algorithm: alg,
		Typ:       "JWT",
	}

	// Sign signs digest with the private key, possibly using entropy from
	// rand. For an RSA key, the resulting signature should be either a
	// PKCS #1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
	// key, it should be a DER-serialised, ASN.1 signature structure.
	//
	// This provides a wrapper around crypto.Signer to adapt to
	// golang.org/x/oauth2/jws.Signer expected by EncodeWithSigner.
	f := func(data []byte) ([]byte, error) {
		h := hasher.New()
		h.Write(data)

		s, err := signer.Sign(rand.Reader, h.Sum(nil), hasher)
		if err != nil {
			return nil, err
		}

		var rs struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(s, &rs)
		if err != nil {
			return nil, err
		}

		size := (params.BitSize + 7) / 8
		sig := make([]byte, size*2)

		rBytes := rs.R.Bytes()
		sBytes := rs.S.Bytes()
		copy(sig[size-len(rBytes):], rBytes)
		copy(sig[(size*2)-len(sBytes):], sBytes)
		return sig, nil
	}

	return jws.EncodeWithSigner(hdr, cs, f)
}

func login(jwt, clientID, tokenURL string) (string, error) {
	v := url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {jwt},
	}

	config := clientcredentials.Config{
		ClientID:       clientID,
		TokenURL:       tokenURL,
		EndpointParams: v,
		AuthStyle:      oauth2.AuthStyleInParams,
	}

	token, err := config.Token(context.Background())
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
