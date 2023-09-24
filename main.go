package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli/v2"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"tasadar.net/tionis/ssh-tools/certs"
	"tasadar.net/tionis/ssh-tools/manage"
	"tasadar.net/tionis/ssh-tools/util/sftp_handler"
	"time"
)

// TODO add ssh subcommand
// TODO implement management and automatic renewals using upstream ssh-tool server
// (implement server in this repo for easier containment?)
// think of new name for this project
// think of ways to make this project importable for a single binary
// across git-tools, ssh-tools, shell-tools, etc
// instant renewal over ssh-tools server and patchbay

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var fishCompletion string
	var signingConf certs.SigningConfig
	var changes certs.ChangeRequest

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("failed to get home dir: ", err)
		return
	}
	var userManager *manage.UserCertManager
	var caManager *manage.CACertManager

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "cert",
				Aliases: []string{"c"},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "ignore-expiry",
						Aliases: []string{"i"},
						Usage:   "ignore expiry date of certificate",
					},
					&cli.DurationFlag{
						Name:    "clock-compensation",
						Aliases: []string{"cc"},
						Usage:   "how much time to add/substract to compensate for clock inaccuracies",
						Value:   3 * time.Minute,
					},
					&cli.StringFlag{
						Name:    "time",
						Aliases: []string{"t"},
						Usage:   "override validity time with pattern (like used by ssh-keygen)",
					},
					&cli.StringSliceFlag{
						Name:    "principal-add",
						Aliases: []string{"pa"},
						Usage:   "principals to add to cert",
					},
					&cli.StringSliceFlag{
						Name:    "principal-rm",
						Aliases: []string{"pr"},
						Usage:   "principals to remove from cert",
					},
					&cli.StringSliceFlag{
						Name:    "principal",
						Aliases: []string{"p"},
						Usage:   "principals to override to cert",
					},
					&cli.StringFlag{
						Name:    "identifier",
						Aliases: []string{"I"},
						Usage:   "override identifier to use",
					},
					&cli.TimestampFlag{
						Name:    "valid-after",
						Aliases: []string{"va"},
						Usage:   "override valid after date",
						Layout:  "2006-01-02 15:04:05",
					},
					&cli.TimestampFlag{
						Name:    "valid-before",
						Aliases: []string{"vb"},
						Usage:   "override valid before date",
						Layout:  "2006-01-02 15:04:05",
					},
				},
				Before: func(c *cli.Context) error {
					userManager = manage.NewUserManager(homeDir)
					signingConf, err = certs.CreateSigningConf(
						c.Duration("clock-compensation"),
						c.Bool("ignore-expiry"))
					if err != nil {
						return fmt.Errorf("failed to get signing conf: %w", err)
					}
					changes = cliFlagsToChangeRequest(c)
					return nil
				},
				Usage: "certificate management",
				Subcommands: []*cli.Command{
					{
						Name:    "create",
						Aliases: []string{"s"},
						Usage:   "create a cert for a local key",
						Flags: []cli.Flag{
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read key from stdin instead of file",
							},
							&cli.PathFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "path to key to sign",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "sign key on remote using sftp",
							},
						},
						Action: func(c *cli.Context) error {
							cert := certs.DefaultUserCert()
							err := cert.ApplyChanges(changes)
							if err != nil {
								return fmt.Errorf("failed to apply changes: %w", err)
							}
							var reader io.Reader
							var writer io.Writer
							var closer func() error

							if c.Bool("stdin") {
								reader = os.Stdin
								writer = os.Stdout
								closer = func() error { return nil }
							} else {
								if c.String("sftp") != "" {
									sftpClient, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									if err != nil {
										return fmt.Errorf("failed to parse get sftp file: %w", err)
									}
									if c.String("identifier") == "" {
										cert.SetIdentifier(sftpClient.Remote.Host + "@tionis.dev")
									}
									keyFile, err := sftpClient.Client.OpenFile(sftpClient.Remote.Path, os.O_RDWR)
									if err != nil {
										return err
									}
									certFile, err := sftpClient.Client.Create(strings.TrimSuffix(sftpClient.Remote.Path, ".pub") + "-cert.pub")
									reader = keyFile
									writer = certFile
									closer = func() error {
										err := keyFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close key file: %w", err)
										}
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return sftpClient.Close()
									}
								} else {
									keyFile, err := os.Open(c.Path("key"))
									if err != nil {
										return fmt.Errorf("failed to open key file: %w", err)
									}
									certFile, err := os.Create(strings.TrimSuffix(c.Path("key"), ".pub") + "-cert.pub")
									if err != nil {
										return fmt.Errorf("failed to create cert file: %w", err)
									}
									reader = keyFile
									writer = certFile
									closer = func() error {
										err := keyFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close key file: %w", err)
										}
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return nil
									}
								}
							}

							bytes, err := io.ReadAll(reader)
							if err != nil {
								return fmt.Errorf("failed to read key: %w", err)
							}
							err = cert.SetKeyFromBytes(bytes)
							if err != nil {
								return fmt.Errorf("failed to set key: %w", err)
							}
							err = cert.Sign(signingConf)
							if err != nil {
								return fmt.Errorf("failed to sign cert: %w", err)
							}

							_, err = writer.Write(cert.MarshalAuthorizedKey())
							if err != nil {
								return fmt.Errorf("failed to write cert: %w", err)
							}
							closeErr := closer()
							if closeErr != nil {
								return fmt.Errorf("failed to close: %w", closeErr)
							}
							return nil
						},
					},
					{
						Name:    "renew",
						Aliases: []string{"r"},
						Usage:   "renew a certificate from stdin or file",
						Flags: []cli.Flag{
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "renew cert on remote using sftp",
							},
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to renew",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
						},
						Action: func(c *cli.Context) error {
							var certBytes []byte
							var writer io.Writer
							var closer func() error

							if c.Bool("stdin") {
								certBytes, err = io.ReadAll(os.Stdin)
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
								writer = os.Stdout
								closer = func() error { return nil }
							} else {
								if c.String("sftp") != "" {
									sftpClient, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									if err != nil {
										return fmt.Errorf("failed to parse get sftp file: %w", err)
									}
									certFile, err := sftpClient.Client.OpenFile(
										sftpClient.Remote.Path,
										os.O_RDWR)
									certBytes, err = io.ReadAll(certFile)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									_, err = certFile.Seek(0, io.SeekStart)
									if err != nil {
										return fmt.Errorf("failed to seek to start of file: %w", err)
									}
									writer = certFile
									closer = func() error {
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return sftpClient.Close()
									}
								} else {
									certFile, err := os.OpenFile(
										c.Path("cert"),
										os.O_RDWR,
										0644)
									if err != nil {
										return fmt.Errorf("failed to create cert file: %w", err)
									}
									certBytes, err = io.ReadAll(certFile)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									_, err = certFile.Seek(0, io.SeekStart)
									if err != nil {
										return fmt.Errorf("failed to seek to start of file: %w", err)
									}
									writer = certFile
									closer = func() error {
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return nil
									}
								}
							}
							cert, err := certs.FromBytes(certBytes)
							if err != nil {
								return fmt.Errorf("failed to parse cert: %w", err)
							}
							err = cert.ApplyChanges(changes)
							if err != nil {
								return fmt.Errorf("failed to apply changes: %w", err)
							}
							err = cert.Sign(signingConf)
							if err != nil {
								return fmt.Errorf("failed to sign cert: %w", err)
							}
							_, err = writer.Write(cert.MarshalAuthorizedKey())
							if err != nil {
								return fmt.Errorf("failed to write cert: %w", err)
							}
							closeErr := closer()
							if closeErr != nil {
								return fmt.Errorf("failed to close: %w", closeErr)
							}
							return nil
						},
					},
					{
						Name:    "info",
						Aliases: []string{"i"},
						Usage:   "get info about a certificate",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to check",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
						},
						Action: func(c *cli.Context) error {
							cert, err := certs.FromFile(c.Path("cert"))
							if err != nil {
								return fmt.Errorf("failed to read cert from file: %w", err)
							}
							indent, err := json.MarshalIndent(cert.Cert, "", "  ")
							if err != nil {
								return fmt.Errorf("failed to marshal cert: %w", err)
							}
							fmt.Println(string(indent))
							return nil
						},
					},
					{
						Name: "auto-renew",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "path to key to sign",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
							},
						},
						Usage: "automatically request renewal of certificate when it has reached " +
							"50% of its validity time window",
						Action: func(c *cli.Context) error {
							cert, err := certs.FromFile(c.Path("cert"))
							if err != nil {
								return fmt.Errorf("failed to read cert from file: %w", err)
							}
							if userManager.RenewalInProgress(cert) {
								log.Println("a cert renewal is already requested, checkinf for reply")
								return userManager.ProcessCertRenewal(cert)
							}
							now := uint64(time.Now().Unix())
							timePassed := now - cert.Cert.ValidAfter
							totalValidTime := cert.Cert.ValidBefore - cert.Cert.ValidAfter
							if timePassed*100/totalValidTime > 50 {
								log.Println("requesting cert renewal, run again to process answer")
								return userManager.RequestCertRenewal(cert)
							}
							log.Println("not renewing cert")
							return nil
						},
					},
				},
			},
			{
				Name:    "manage",
				Aliases: []string{"m"},
				Usage:   "manage certificates across devices",
				Before: func(c *cli.Context) error {
					caManager = manage.NewCAManager(homeDir)
					return nil
				},
				Subcommands: []*cli.Command{
					{
						Name:    "process",
						Aliases: []string{"p"},
						Flags: []cli.Flag{
							&cli.BoolFlag{
								Name:    "renew",
								Aliases: []string{"r"},
								Usage:   "only process renewals (automatically)",
							},
							&cli.BoolFlag{
								Name:    "revoke",
								Aliases: []string{"rv"},
								Usage:   "only process revocations (automatically)",
							},
							&cli.BoolFlag{
								Name:    "new",
								Aliases: []string{"n"},
								Usage:   "only process new requests, must be approved by admin interactively",
							},
						},
						Usage: "process certificate signing requests",
						Action: func(c *cli.Context) error {
							return caManager.ProcessRequests(c.Bool("renew"), c.Bool("revoke"), c.Bool("new"))
						},
					},
					{
						Name:    "update-revocation-list",
						Aliases: []string{"u"},
						Usage:   "update the revocation list",
						Action: func(c *cli.Context) error {
							return caManager.UpdateRevocationList()
						},
					},
					{
						Name:    "revoke",
						Aliases: []string{"rv"},
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to revoke",
							},
						},
						Usage: "revoke a certificate from stdin or file when given as $1",
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							var err error
							if c.Path("cert") != "" {
								cert, err = certs.FromFile(c.Path("cert"))
								if err != nil {
									return fmt.Errorf("failed to read cert from file: %w", err)
								}
							} else {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							}
							return caManager.RevokeCert(cert)
						},
					},
				},
			},
			{
				Name:    "util",
				Aliases: []string{"u"},
				Usage:   "utility functions",
				Subcommands: []*cli.Command{
					{
						Name:    "completions",
						Aliases: []string{"c"},
						Usage:   "generate completions for shell",
						Subcommands: []*cli.Command{
							{
								Name:    "fish",
								Aliases: []string{"f"},
								Usage:   "generate completions for fish shell",
								Action: func(c *cli.Context) error {
									fmt.Println(fishCompletion)
									return nil
								},
							},
						},
					},
				},
			},
		},
	}

	fishCompletion, err = app.ToFishCompletion()
	if err != nil {
		return
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("failed to run app: %v", err)
	}
}

func cliFlagsToChangeRequest(c *cli.Context) certs.ChangeRequest {
	var timePattern, identifier sql.NullString
	if c.String("time") != "" {
		timePattern = sql.NullString{String: c.String("time"), Valid: true}
	}
	if c.String("identifier") != "" {
		identifier = sql.NullString{String: c.String("identifier"), Valid: true}
	}
	var validBefore, validAfter sql.NullTime
	if c.Timestamp("valid-before") != nil {
		validBefore = sql.NullTime{Time: *c.Timestamp("valid-before"), Valid: true}
	}
	if c.Timestamp("valid-after") != nil {
		validAfter = sql.NullTime{Time: *c.Timestamp("valid-after"), Valid: true}
	}
	var extensionsToAdd, extensionsOverride map[string]string
	if c.StringSlice("extension-add") != nil {
		extensionsToAdd = make(map[string]string)
		for _, extension := range c.StringSlice("extension-add") {
			extensionsToAdd[extension] = ""
		}
	}
	if c.StringSlice("extension") != nil {
		extensionsOverride = make(map[string]string)
		for _, extension := range c.StringSlice("extension") {
			extensionsOverride[extension] = ""
		}
	}
	return certs.ChangeRequest{
		IdentifierOverride:  identifier,
		PrincipalsOverride:  c.StringSlice("principal"),
		PrincipalsToAdd:     c.StringSlice("principal-add"),
		PrincipalsToRemove:  c.StringSlice("principal-rm"),
		ExtensionsOverride:  extensionsOverride,
		ExtensionsToAdd:     extensionsToAdd,
		ExtensionsToRemove:  c.StringSlice("extension-rm"),
		ValidAfterOverride:  validAfter,
		ValidBeforeOverride: validBefore,
		TimePattern:         timePattern,
	}
}
