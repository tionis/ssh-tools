package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/hiddeco/sshsig"
	sshToolsAgent "github.com/tionis/ssh-tools/agent"
	"github.com/tionis/ssh-tools/allowed_signers"
	"github.com/tionis/ssh-tools/certs"
	"github.com/tionis/ssh-tools/sigchain"
	"github.com/tionis/ssh-tools/util/sftp_handler"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"
)

// TODO add continuous mode for instant authorized_keys updates
// TODO add ssh subcommand
// TODO implement management and automatic renewals using upstream ssh-tool server
// (implement server in this repo for easier containment?)
// think of new name for this project
// think of ways to make this project importable for a single binary
// across git-tools, ssh-tools, shell-tools, etc
// instant renewal over ssh-tools server and patch bay

// TODO new cli interface:
// ssh-tools
//  agent
//  cert
//    sign (add options for gpg, ssh-agent, yubikey, all cert options, sigchain verification of correct CA, clipboard, etc)
//    renew (add options for renew only if necessary, etc)
//    verify (optionally integrate with sichain)
//    info
//    remote
//      request (request cert renewal)
//      approve (approve cert renewal(s))
//  sigchain (wip interface, will probably change some things there)
//    push (push newest sigchain to remote)
//    pull (pull newest sigchain from remote and apply updates)
//    new (add new sigchain entries to db)
//    generate_allowed_signers
//  internal
//    json
//      sign
//      verify
//  convert
//    allowed_signers
//      openssh_to_json
//      json_to_openssh
//  curl (copy important parts of curls flags to make ssh-signed http requests)
//  proxy (wip: accept a config, then proxy http-sig signed http requests verified with sigchain and
//              forward them (with added headers etc to the destination specified by config))
//  old_util (some more utilities (e.g. completions, etc))

// TODO implementation notes:
// sigchain always saves a verified copy to allowed_signers (default ~/.ssh/allowed_signers)
// working data is saved to ~/.ssh/sigchain.db
// will probably

// TODO
// think about how to approach revocations
// a cert can be revoked by signing it's own revocation or by a CA signing it's revocation
// revocations are seperate from sigchain as they are temporary by nature (revocation entry can be
// removed after the revocation is no longer valid) (what about past validation of signatures though!?!)

// TODO:
// fix cli parsing and write boilerplate
// write sigchain stuff
// build on top of that

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var logger *slog.Logger
	var fishCompletion, manPage string
	var allowedSigners allowed_signers.TrustChecker
	var sigchainManager *sigchain.Manager
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("failed to get home dir: ", err)
		return
	}

	app := &cli.App{
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:    "sigchain_db",
				Aliases: []string{"sd"},
				Usage:   "file to store sigchain data in",
				Value:   path.Join(homeDir, ".ssh", "ssh-tools", "sigchain"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"ll"},
				Usage:   "log level to use",
				Value:   "info",
			},
			&cli.BoolFlag{
				Name:  "log-source",
				Usage: "add source to log output",
			},
		},
		Before: func(c *cli.Context) error {
			logLevel, err := parseLogLevel(c.String("log-level"))
			if err != nil {
				return fmt.Errorf("failed to parse log level: %w", err)
			}
			addSource := c.Bool("log-source")
			if os.Getenv("DEBUG") != "" {
				addSource = true
				logLevel = slog.LevelDebug
			}
			if logLevel == slog.LevelDebug {
				addSource = true
			}
			logger = slog.New(
				slog.NewTextHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource: addSource,
						Level:     logLevel,
					}))
			sigchainManager, err = sigchain.NewSigchainManager(ctx, c.Path("sigchain_db"), logger)
			if err != nil {
				return fmt.Errorf("failed to init sigchain: %w", err)
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name: "sigchain",
				Subcommands: []*cli.Command{
					{
						Name: "get",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "namespace",
								Aliases: []string{"n"},
								Usage:   "namespace to get sigchain for",
							},
							&cli.StringFlag{
								Name:    "hash",
								Aliases: []string{"h"},
								Usage:   "hash to get sigchain entry for (overrides namespace)",
							},
						},
						Action: func(c *cli.Context) error {
							var rawSigchain []sigchain.Entry
							if c.String("hash") != "" {
								rawSigchain, err = sigchainManager.GetSigchainByHash(c.String("hash"))
								if err != nil {
									logger.Error("failed to get sigchain by hash", "error", err)
									return fmt.Errorf("failed to get sigchain by hash: %w", err)
								}
							} else if c.String("namespace") != "" {
								rawSigchain, err = sigchainManager.GetSigchainByNamespace(c.String("namespace"))
								if err != nil {
									logger.Error("failed to get sigchain by namespace", "error", err)
									return fmt.Errorf("failed to get sigchain by namespace: %w", err)
								}
							} else {
								return fmt.Errorf("namespace or hash is required")
							}
							var marshalledSigchain []sigchain.MarshalledEntry
							for _, entry := range rawSigchain {
								marshalledEntry, err := entry.Marshal()
								if err != nil {
									logger.Error("failed to marshal entry", "error", err)
									return fmt.Errorf("failed to marshal entry: %w", err)
								}
								marshalledSigchain = append(marshalledSigchain, marshalledEntry)
							}
							encoded, err := json.Marshal(marshalledSigchain)
							if err != nil {
								logger.Error("failed to marshal sigchain", "error", err)
								return fmt.Errorf("failed to marshal sigchain: %w", err)
							}
							fmt.Println(string(encoded))
							return nil
						},
					},
				},
			},
			{
				Name: "agent", // TODO test this
				Description: "ssh-tools agent server\n" +
					"run as a background daemon to manage keys",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:  "socket",
						Usage: "path to socket to use (defaults to a temporary one)",
					},
					&cli.StringSliceFlag{
						Name:    "sub-agents",
						Aliases: []string{"sa"},
						Usage: "sub-agents to proxy to\n" +
							"format: <name>:<socket-path>",
					},
				},
				Action: func(c *cli.Context) error {
					var socketPath string
					if c.String(socketPath) == "" {
						socketPath, err = getAgentSock()
						if err != nil {
							logger.Error("failed to get agent socket", "error", err)
							return fmt.Errorf("failed to get agent socket: %w", err)
						}
					}
					var subAgents []sshToolsAgent.SubAgent
					for _, subAgent := range c.StringSlice("sub-agents") {
						parts := strings.SplitN(subAgent, ":", 2)
						conn, err := net.Dial("unix", parts[1])
						if err != nil {
							logger.Error("failed to connect to sub-agent", "error", err, "sub-agent", parts)
							return fmt.Errorf("failed to connect to sub-agent: %w", err)
						}
						ag := agent.NewClient(conn)
						subAgents = append(subAgents, sshToolsAgent.SubAgent{
							Name:  parts[0],
							Agent: ag,
						})
					}
					sshToolsAgent.ServeAgent(c.Path("socket"), subAgents)
					return nil
				},
			},
			{
				Name:        "client",
				Description: "client for ssh-tools agent server",
				Subcommands: []*cli.Command{
					{
						Name: "add",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "path to key to add",
							},
							&cli.PathFlag{
								Name: "cert",
								Usage: "path to cert to add\n" +
									"if cert is provided, key is ignored",
							},
							&cli.StringFlag{
								Name: "comment",
								Usage: "comment to use for key\n" +
									"if not provided, the filename is used",
							},
							&cli.BoolFlag{
								Name:    "confirm",
								Aliases: []string{"c"},
								Usage:   "confirm key usage",
							},
							&cli.IntFlag{
								Name:  "lifetime",
								Usage: "lifetime of key in seconds, 0 for unlimited",
								Value: 0,
							},
						},
						Usage: "add a key to the agent",
						Action: func(c *cli.Context) error {
							ag, err := getAgent()
							if err != nil {
								return fmt.Errorf("failed to get agent: %w", err)
							}
							keyToAdd := agent.AddedKey{
								ConfirmBeforeUse: c.Bool("confirm"),
								LifetimeSecs:     uint32(c.Int("lifetime")),
								Comment:          c.String("comment"),
							}
							if c.Path("cert") != "" {
								keyBytes, err := os.ReadFile(c.Path("cert"))
								if err != nil {
									return fmt.Errorf("failed to read cert: %w", err)
								}
								cert, err := ssh.ParsePublicKey(keyBytes)
								if err != nil {
									return fmt.Errorf("failed to parse cert: %w", err)
								}
								switch cert.(type) {
								case *ssh.Certificate:
									keyToAdd.Certificate = cert.(*ssh.Certificate)
								default:
									return fmt.Errorf("not a certificate")
								}
							} else if c.Path("key") != "" {
								keyBytes, err := os.ReadFile(c.Path("key"))
								if err != nil {
									return fmt.Errorf("failed to read key: %w", err)
								}
								key, err := ssh.ParseRawPrivateKey(keyBytes)
								if err != nil {
									return err
								}
								keyToAdd.PrivateKey = key
							} else {
								return fmt.Errorf("no key or cert provided")
							}
							err = ag.Add(keyToAdd)
							if err != nil {
								return fmt.Errorf("failed to add key: %w", err)
							}
							return nil
						},
					},
				},
			},
			{
				Name:    "cert",
				Aliases: []string{"c"},
				Usage:   "certificate management",
				Subcommands: []*cli.Command{
					{
						Name:    "create",
						Aliases: []string{"c"},
						Usage:   "create a cert for a local key",
						Flags: cliFlagAddChangeRequestAndSigningConfig(
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
						),
						Action: func(c *cli.Context) error {
							changes := cliFlagsToChangeRequest(c)
							signingConf, err := cliFlagsToSigningConfig(c)
							if err != nil {
								return fmt.Errorf("failed to parse signing config: %w", err)
							}
							cert := certs.DefaultUserCert()
							err = cert.ApplyChanges(changes)
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
										c.String("sftp"),
										".ssh/id_ed25519.pub")
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

							keyBytes, err := io.ReadAll(reader)
							if err != nil {
								return fmt.Errorf("failed to read key: %w", err)
							}
							err = cert.SetKeyFromBytes(keyBytes)
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
						Flags: cliFlagAddChangeRequestAndSigningConfig(
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
							&cli.BoolFlag{
								Name:  "dont-verify",
								Usage: "don't verify cert before renewal",
							},
						),
						Action: func(c *cli.Context) error {
							changes := cliFlagsToChangeRequest(c)
							signingConf, err := cliFlagsToSigningConfig(c)
							if err != nil {
								return fmt.Errorf("failed to parse signing config: %w", err)
							}
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
										c.String("sftp"),
										".ssh/id_ed25519-cert.pub")
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
									// TODO check if cert is loaded in agent
									// if it is, save it to be replaced after renewal
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
							if !c.Bool("dont-verify") {
								err = allowedSigners.CertChecker.CheckCert(cert.Cert.ValidPrincipals[0], cert.Cert)
								if err != nil {
									return fmt.Errorf("failed to verify cert: %w", err)
								}
							}
							err = cert.Renew(signingConf, changes)
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
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "read cert from remote using sftp",
							},
						},
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							if c.Bool("stdin") {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							} else {
								if c.String("sftp") != "" {
									signingConf, err := cliFlagsToSigningConfig(c)
									if err != nil {
										return fmt.Errorf("failed to parse signing config: %w", err)
									}
									client, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"),
										".ssh/id_ed25519-cert.pub")
									if err != nil {
										return fmt.Errorf("failed to get SFTP client for remote: %w", err)
									}
									open, err := client.Client.Open(client.Remote.Path)
									if err != nil {
										return fmt.Errorf("failed to open cert file: %w", err)
									}
									cert, err = certs.FromReader(open)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									err = open.Close()
									if err != nil {
										return fmt.Errorf("failed to close cert file: %w", err)
									}
									err = client.Close()
									if err != nil {
										return fmt.Errorf("failed to close sftp client: %w", err)
									}
								} else {
									cert, err = certs.FromFile(c.Path("cert"))
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
								}
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
						Name:    "verify",
						Aliases: []string{"v"},
						Usage:   "verify a certificate",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to check",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "read cert from remote using sftp",
							},
						},
						UsageText: "principal to check",
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							if len(c.Args().Slice()) != 1 {
								return fmt.Errorf("principal to check is required")
							}
							if c.Bool("stdin") {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							} else {
								if c.String("sftp") != "" {
									signingConf, err := cliFlagsToSigningConfig(c)
									if err != nil {
										return fmt.Errorf("failed to parse signing config: %w", err)
									}
									client, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"),
										".ssh/id_ed25519-cert.pub")
									open, err := client.Client.Open(client.Remote.Path)
									if err != nil {
										return fmt.Errorf("failed to open cert file: %w", err)
									}
									cert, err = certs.FromReader(open)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									err = open.Close()
									if err != nil {
										return fmt.Errorf("failed to close cert file: %w", err)
									}
									err = client.Close()
									if err != nil {
										return fmt.Errorf("failed to close sftp client: %w", err)
									}
								} else {
									cert, err = certs.FromFile(c.Path("cert"))
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
								}
							}
							err := allowedSigners.CertChecker.CheckCert(c.Args().First(), cert.Cert)
							if err != nil {
								return fmt.Errorf("failed to verify cert: %w", err)
							}
							return nil
						},
					},
					{
						Name: "self-revocation",
						Subcommands: []*cli.Command{
							{
								Name: "create",
								Flags: []cli.Flag{
									&cli.PathFlag{
										Name:    "key",
										Aliases: []string{"k"},
										Usage:   "path to key to revoke itself",
										Value:   path.Join(homeDir, ".ssh", "id_ed25519"),
									},
									&cli.BoolFlag{
										Name:  "stdin",
										Usage: "read key from stdin instead of file",
									},
								},
								Usage: "revoke a ssh key by signing it's own revocation",
								Action: func(c *cli.Context) error {
									var keyBytes []byte
									if c.Bool("stdin") {
										keyBytes, err = io.ReadAll(os.Stdin)
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									} else {
										keyBytes, err = os.ReadFile(c.Path("key"))
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									}
									key, err := ssh.ParsePrivateKey(keyBytes)
									if err != nil {
										return fmt.Errorf("failed to parse key: %w", err)
									}

									//fmt.Println(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
									// TODO embed timestamp in signed statement after which the key is invalid
									pubKeyString := ssh.MarshalAuthorizedKey(key.PublicKey())
									signature, err := sshsig.Sign(
										bytes.NewReader(pubKeyString[:len(pubKeyString)-1]),
										key,
										sshsig.HashSHA512,
										"ssh-revocation")
									if err != nil {
										return fmt.Errorf("failed to sign key: %w", err)
									}

									fmt.Print(string(pubKeyString))
									fmt.Print(string(sshsig.Armor(signature)))
									return nil
								},
							},
							{
								Name: "verify",
								Flags: []cli.Flag{
									&cli.PathFlag{
										Name:    "key",
										Aliases: []string{"k"},
										Usage:   "path to key to validate revocation",
									},
									&cli.BoolFlag{
										Name:  "stdin",
										Usage: "read key from stdin instead of file",
									},
									&cli.BoolFlag{
										Name:    "quiet",
										Aliases: []string{"q"},
									},
								},
								Usage: "validate a self-signed ssh key revocation",
								Action: func(c *cli.Context) error {
									var signatureBytes []byte
									if c.Bool("stdin") {
										signatureBytes, err = io.ReadAll(os.Stdin)
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									} else {
										signatureBytes, err = os.ReadFile(c.Path("key"))
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									}
									parts := strings.Split(string(signatureBytes), "\n")
									pubKeyString := parts[0]
									pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyString))
									signature, err := sshsig.Unarmor([]byte(strings.Join(parts[1:], "\n")))
									if err != nil {
										return err
									}
									err = sshsig.Verify(
										bytes.NewReader([]byte(pubKeyString)),
										signature,
										pubKey,
										sshsig.HashSHA512,
										"ssh-revocation")
									if err != nil {
										return err
									}
									if !c.Bool("quiet") {
										fmt.Printf("key revocation for %s is valid\n", pubKeyString)
									}
									return nil
								},
							},
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
					{
						Name:  "man",
						Usage: "generate man page",
						Action: func(c *cli.Context) error {
							fmt.Println(manPage)
							return nil
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
	manPage, err = app.ToMan()
	if err != nil {
		return
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("failed to run app: %v", err)
	}
}

func parseLogLevel(logLevel string) (slog.Level, error) {
	switch strings.ToLower(logLevel) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level: %s", logLevel)
	}
}

func cliFlagAddChangeRequestAndSigningConfig(flags ...cli.Flag) []cli.Flag {
	return append(append(flags, cliFlagsChangeRequest...), cliFlagsSigningConfig...)
}

var cliFlagsChangeRequest = []cli.Flag{
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
	&cli.TimestampFlag{ // TODO replace with time pattern
		Name:    "valid-after",
		Aliases: []string{"va"},
		Usage:   "override valid after date",
		Layout:  "2006-01-02 15:04:05",
	},
	&cli.TimestampFlag{ // TODO replace with time pattern
		Name:    "valid-before",
		Aliases: []string{"vb"},
		Usage:   "override valid before date",
		Layout:  "2006-01-02 15:04:05",
	},
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

var cliFlagsSigningConfig = []cli.Flag{
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
}

func cliFlagsToSigningConfig(c *cli.Context) (certs.SigningConfig, error) {
	return certs.CreateSigningConf(
		c.Duration("clock-compensation"),
		c.Bool("ignore-expiry"))
}

func getAgentSock() (string, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		globalTmpDir := os.TempDir()
		tmpDir, err := os.MkdirTemp(globalTmpDir, "ssh-tools-agent.*")
		if err != nil {
			return "", fmt.Errorf("failed to create temp dir: %w", err)
		}
		return path.Join(tmpDir, "ssh-tools-agent.sock"), nil
	} else {
		return agentSock, nil
	}
}

func getAgent() (agent.ExtendedAgent, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}
	return agent.NewClient(conn), nil
}
