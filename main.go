/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/urfave/cli/v2" // imports as package "cli"
	"golang.org/x/crypto/ssh/terminal"

	st "github.com/manetu/security-token/core"
	"github.com/manetu/security-token/version"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprint(os.Stderr, "ERROR: ", r)
		}
	}()

	ctx := st.New()

	defer func() {
		_ = ctx.Close()
	}()

	var (
		url      string
		insecure bool
		audience string
	)

	app := &cli.App{
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "version",
				Usage: "Report version and build information",
				Action: func(c *cli.Context) error {
					fmt.Printf("manetu-security-token, git %s, goVersion %s, buildDate %s\n", version.GitCommit, version.GoVersion, version.BuildDate)
					return nil
				},
			},
			{
				Name:  "generate",
				Usage: "Generate a new security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "realm",
						Usage:    "Set the realm id",
						EnvVars:  []string{"MANETU_REALM"},
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					realm := c.String("realm")
					cert, err := ctx.Generate(realm)
					if err != nil {
						return fmt.Errorf("error during generate: %v", err)
					}
					fmt.Fprintf(os.Stderr, "Serial: %s\n", st.HexEncode(cert.SerialNumber.Bytes()))
					fmt.Fprintf(os.Stderr, "MRN: %s\n", st.ComputeMRN(cert))
					fmt.Printf("%s\n", st.ExportCert(cert))

					return nil
				},
			},
			{
				Name:  "show",
				Usage: "Display the PEM encoded x509 public key for the specified security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "serial",
						Usage: "Security token serial number",
					},
				},
				Action: func(c *cli.Context) error {
					err := ctx.Show(c.String("serial"))
					if err != nil {
						return fmt.Errorf("error during show: %v", err)
					}
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "Enumerate available security tokens",
				Action: func(c *cli.Context) error {
					err := ctx.List()
					if err != nil {
						return fmt.Errorf("error during list: %v", err)
					}
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Remove a security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "serial",
						Usage:    "Security token serial number",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					err := ctx.Delete(c.String("serial"))
					if err != nil {
						return fmt.Errorf("error during delete: %v", err)
					}
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "Acquires an access token from a security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "url",
						Usage:       "The URL of the Manetu endpoint",
						EnvVars:     []string{"MANETU_URL"},
						Destination: &url,
					},
					&cli.BoolFlag{
						Name:        "insecure",
						Usage:       "Allow insecure TLS",
						EnvVars:     []string{"MANETU_INSECURE"},
						Destination: &insecure,
					},
					&cli.StringFlag{
						Name:        "audience",
						Usage:       "Override the audience claim",
						EnvVars:     []string{"MANETU_AUDIENCE"},
						Destination: &audience,
					},
				},
				Subcommands: []*cli.Command{
					{
						Name:  "hsm",
						Usage: "HSM based login",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "serial",
								Usage: "HSM serial number",
							},
						},
						Action: func(c *cli.Context) error {
							jwt, err := ctx.LoginPKCS11(url, insecure, audience, c.String("serial"))
							if err != nil {
								return fmt.Errorf("error during HSM login: %v", err)
							}
							fmt.Printf("%s\n", jwt)
							return nil
						},
					},
					{
						Name:  "pem",
						Usage: "non-HSM protected PEM encoded certificate and key-pair",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "key",
								Usage: "X509 Key (or path)",
							},
							&cli.StringFlag{
								Name:  "cert",
								Usage: "X509 cert (or path)",
							},
							&cli.BoolFlag{
								Name:  "path",
								Usage: "Treat key/cert parameters as paths",
							},
							&cli.StringFlag{
								Name:  "p12",
								Usage: "PKCS12 Bundled Key/Cert (or path)",
							},
							&cli.StringFlag{
								Name:  "password",
								Usage: "Password for .p12 file (if not passed in, user will be prompted)",
							},
						},
						Action: func(c *cli.Context) error {
							if c.String("p12") != "" {
								password := c.String("password")
								if password == "" {
									fmt.Print("Enter password for PKCS#12 file: ")
									bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
									if err != nil {
										return fmt.Errorf("error reading password: %v", err)
									}
									password = string(bytePassword)
									fmt.Println()
								}

								jwt, err := ctx.LoginPKCS12(url, insecure, audience, c.String("p12"), password, c.Bool("path"))
								if err != nil {
									return fmt.Errorf("error during PKCS#12 login: %v", err)
								}
								fmt.Printf("%s\n", jwt)
								return nil
							}

							key := c.String("key")
							cert := c.String("cert")

							if key == "" || cert == "" {
								return fmt.Errorf("both key and cert must be provided for PEM login")
							}

							jwt, err := ctx.LoginX509(url, insecure, audience, key, cert, c.Bool("path"))
							if err != nil {
								return fmt.Errorf("error during PEM login: %v", err)
							}
							fmt.Printf("%s\n", jwt)
							return nil
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
