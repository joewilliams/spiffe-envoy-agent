package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	envoy_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds_v2 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"github.com/mitchellh/cli"
	"google.golang.org/grpc"
)

type dumpCommand struct {
	socketPath    string
	resourceNames []string
}

func newDumpCommand() (cli.Command, error) {
	return &dumpCommand{}, nil
}

func (c *dumpCommand) Run(args []string) int {
	ctx := context.Background()
	if err := c.configure(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	conn, err := grpc.DialContext(ctx, c.socketPath, grpc.WithInsecure(), grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("unix", addr, timeout)
	}))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()

	client := sds_v2.NewSecretDiscoveryServiceClient(conn)
	resp, err := client.FetchSecrets(ctx, &envoy_v2.DiscoveryRequest{
		ResourceNames: args,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if len(resp.Resources) == 0 {
		fmt.Println("No resources found.")
		return 0
	}

	for i, resource := range resp.Resources {
		secret := new(auth.Secret)
		if err := types.UnmarshalAny(&resource, secret); err != nil {
			fmt.Fprintf(os.Stderr, "resource %d failed to parse: %v", i, err)
			continue
		}

		name := secret.Name
		switch secret := secret.Type.(type) {
		case *auth.Secret_TlsCertificate:
			fmt.Println("TLS CERTIFICATE:", name)
			fmt.Println("  certificate chain:")
			if tlsCertificate := secret.TlsCertificate; tlsCertificate != nil {
				if certificateChain := tlsCertificate.CertificateChain; certificateChain != nil {
					writeCertificateDataSource(certificateChain)
				}
				if tlsCertificate.PrivateKey != nil {
					fmt.Println("  private key")
				}
			}
		case *auth.Secret_ValidationContext:
			fmt.Println("VALIDATION CONTEXT:", name)
			if validationContext := secret.ValidationContext; validationContext != nil {
				fmt.Println("  trusted ca:")
				if trustedCa := validationContext.TrustedCa; trustedCa != nil {
					writeCertificateDataSource(trustedCa)
				}
				if len(validationContext.VerifySubjectAltName) > 0 {
					fmt.Printf("  allowed SANs: %q\n", validationContext.VerifySubjectAltName)
				}
			}
		}
	}

	return 0
}

func (c *dumpCommand) Help() string {
	c.configure([]string{"-h"})
	return ""
}

func (c *dumpCommand) Synopsis() string {
	return "Dump SPIFFE Envoy Agent secrets"
}

func (c *dumpCommand) configure(args []string) error {
	f := flag.NewFlagSet("dump", flag.ContinueOnError)
	f.StringVar(&c.socketPath, "socketPath", defaultSocketPath, "SPIFFE Envoy Agent socket path")

	if err := f.Parse(args); err != nil {
		return err
	}

	c.resourceNames = f.Args()

	return nil
}

func writeCertificateDataSource(dataSource *core.DataSource) {
	var pemBytes []byte
	switch spec := dataSource.Specifier.(type) {
	case *core.DataSource_InlineBytes:
		pemBytes = spec.InlineBytes
	default:
		fmt.Fprintf(os.Stderr, "unsupported data source specifier: %T\n", spec)
	}

	var certno int
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certno++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to parse certificate %d: %v", certno, err)
			continue
		}
		fmt.Printf("    %d: uri=%q\n", certno, cert.URIs)
		ioutil.WriteFile(fmt.Sprintf("/tmp/%p-%d.crt.pem", dataSource, certno), pem.EncodeToMemory(block), 644)
	}
}
