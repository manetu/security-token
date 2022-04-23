/*
Copyright © 2021-2022 Manetu Inc. All Rights Reserved.
*/

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2" // imports as package "cli"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprint(os.Stderr, "ERROR: ", r)
		}
	}()

	ctx := New()
	defer ctx.Close()

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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "serial",
						Usage: "Security token serial number",
					},
				},
				Action: func(c *cli.Context) error {
					ctx.Login(c.String("serial"))
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
