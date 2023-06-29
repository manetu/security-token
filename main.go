/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2" // imports as package "cli"

	st "github.com/manetu/security-token/core"
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

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "generate",
				Usage: "Generate a new security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "provider",
						Usage: "Set the provider id",
					},
				},
				Action: func(c *cli.Context) error {
					provider := c.String("provider")
					if provider == "" {
						provider = ctx.Backend.ProviderID
					}
					ctx.Generate(provider)
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
					ctx.Show(c.String("serial"))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "Enumerate available security tokens",
				Action: func(c *cli.Context) error {
					ctx.List()
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Remove a security token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "serial",
						Usage: "Security token serial number",
					},
				},
				Action: func(c *cli.Context) error {
					ctx.Delete(c.String("serial"))
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "Acquires an access token from a security token",
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
							ctx.LoginPKCS11(c.String("serial"))
							return nil
						},
					},
					{
						Name:  "x509",
						Usage: "X509 based login",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "key",
								Usage:    "X509 Key (or path)",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "cert",
								Usage:    "X509 cert (or path)",
								Required: true,
							},
							&cli.BoolFlag{
								Name:     "path",
								Usage:    "treat key/cert parameters as paths",
								Required: false,
							},
						},
						Action: func(c *cli.Context) error {
							ctx.LoginX509(c.String("key"), c.String("cert"), c.Bool("path"))
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
