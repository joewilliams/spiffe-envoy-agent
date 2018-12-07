package sds

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sdsAPI "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/zeebo/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type clientInfo struct {
	version   int
	streaming bool
	ch        chan *secretInfo
}

type secretInfo struct {
	version      int
	svidSecret   *types.Any
	bundleSecret *types.Any
}

// SDSServer implements sdsAPI.SecretDiscoveryServiceServer
type SDSServer struct {
	tlsCertificateName  string
	validateContextName string
	allowedSpiffeIds    []string
	logger              *logrus.Logger
	clientsCh           chan *clientInfo
}

// NewSDSServer creates a new SDS server according to the given config
func NewSDSServer(log *logrus.Logger, tlsCertificateName string, validateContextName string, allowedSpiffeIds []string) *SDSServer {
	return &SDSServer{
		tlsCertificateName:  tlsCertificateName,
		validateContextName: validateContextName,
		allowedSpiffeIds:    allowedSpiffeIds,
		logger:              log,
		clientsCh:           make(chan *clientInfo),
	}
}

// StreamSecrets is the callback of envoy SDS API
func (s SDSServer) StreamSecrets(stream sdsAPI.SecretDiscoveryService_StreamSecretsServer) error {
	ctx := stream.Context()
	client := &clientInfo{
		ch:        make(chan *secretInfo, 1),
		streaming: true,
	}
	for {
		req, err := stream.Recv()
		if err != nil {
			if status.Code(err) == codes.Canceled || err == io.EOF {
				s.logger.Debugf("stream-secrets: canceled or done.")
				return nil
			}
			s.logger.Errorf("stream-secrets: unable to recv: %+v", err)
			return err
		}
		s.logger.Debugf("stream-secrets: req: names=%q nonce=%q version=%q err=%q", req.ResourceNames, req.ResponseNonce, req.VersionInfo, req.ErrorDetail)

		select {
		case s.clientsCh <- client:
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case secrets := <-client.ch:
			resp, err := s.buildResponse(req, secrets)
			if err != nil {
				s.logger.Errorf("stream-secrets: unable to build response: %+v", err)
				return err
			}
			if err := stream.Send(resp); err != nil {
				s.logger.Errorf("stream-secrets: unable to send: %+v", err)
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// FetchSecrets is the callback of envoy SDS API
func (s *SDSServer) FetchSecrets(ctx context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	client := &clientInfo{
		ch: make(chan *secretInfo, 1),
	}

	select {
	case s.clientsCh <- client:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case secrets := <-client.ch:
		return s.buildResponse(req, secrets)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Run connects to the workload API, handles updates, and serves SDS API clients.
// API calls that happen before Run is called will block until the call is canceled
// or Run is invoked. Run does not return until the provided context is done.
func (s *SDSServer) Run(ctx context.Context, socketPath string) error {
	updateCh := make(chan *workload.X509SVIDResponse, 1)

	go s.streamUpdates(ctx, socketPath, updateCh)

	var clients []*clientInfo

	currentInfo := &secretInfo{}
	var active bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case client := <-s.clientsCh:
			if !client.streaming {
				// this is a non-streaming client; just send the current secrets
				client.version = currentInfo.version
				client.ch <- currentInfo
				continue
			}

			if currentInfo.version == 0 || client.version < currentInfo.version {
				// this is a streaming client that has fallen behind; send the current secrets
				client.version = currentInfo.version
				client.ch <- currentInfo
				continue
			}

			// this is an up-to-date streaming client... add it to the list
			// of clients to be notified on an update.
			clients = append(clients, client)
		case update := <-updateCh:
			nextInfo := &secretInfo{}
			switch {
			case update != nil:
				active = true
				s.logger.Infof("sds: received workload API update with %d SVIDs", len(update.Svids))
				for i, svid := range update.Svids {
					s.logger.Infof("sds: svid[%d]: spiffe_id=%q federates_with=%q", i, svid.SpiffeId, svid.FederatesWith)
				}
				var err error
				nextInfo, err = s.parseUpdate(update)
				if err != nil {
					s.logger.Info("sds: unable to parse x509 update: %v", err)
					continue
				}
			case active:
				// stream was active but has been dropped. send an empty set
				// of secrets to clients.
				s.logger.Infof("sds: workload API update stream not active")
				active = false
			default:
				continue
			}

			nextInfo.version = currentInfo.version + 1
			currentInfo = nextInfo

			// push update to clients and clear the client list
			for _, client := range clients {
				client.version = currentInfo.version
				client.ch <- nextInfo
			}
			clients = clients[:0]
		}
	}
}

func (s *SDSServer) streamUpdates(ctx context.Context, socketPath string, updateCh chan *workload.X509SVIDResponse) {
	for {
		err := s.tryStreamUpdates(ctx, socketPath, updateCh)
		if err == nil {
			return
		}
		s.logger.Errorf("unable to stream updates: %+v", err)

		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *SDSServer) tryStreamUpdates(ctx context.Context, socketPath string, updateCh chan *workload.X509SVIDResponse) error {
	conn, err := grpc.DialContext(ctx, socketPath, grpc.WithInsecure(), grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout("unix", addr, timeout)
	}))
	if err != nil {
		return errs.Wrap(err)
	}
	defer conn.Close()

	client := workload.NewSpiffeWorkloadAPIClient(conn)

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("workload.spiffe.io", "true"))

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return errs.Wrap(err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if status.Code(err) == codes.PermissionDenied {
				updateCh <- nil
				return errors.New("no identity for workload")
			}
			return errs.Wrap(err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case updateCh <- resp:
		}
	}
}

func (s *SDSServer) parseUpdate(svidResponse *workload.X509SVIDResponse) (*secretInfo, error) {
	svidSecretMsg, err := s.createTlsCertificateSecret(svidResponse)
	if err != nil {
		return nil, err
	}

	svidSecret, err := types.MarshalAny(svidSecretMsg)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	bundleSecretMsg, err := s.createValidationContextSecret(svidResponse)
	if err != nil {
		return nil, err
	}

	bundleSecret, err := types.MarshalAny(bundleSecretMsg)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &secretInfo{
		svidSecret:   svidSecret,
		bundleSecret: bundleSecret,
	}, nil
}

func (s *SDSServer) createTlsCertificateSecret(svidResponse *workload.X509SVIDResponse) (*auth.Secret, error) {
	svid := s.getX509Svid(svidResponse)
	key := formatKey(svid.GetX509SvidKey())
	cert, err := encodeCerts(svid.X509Svid)
	if err != nil {
		return nil, err
	}

	return &auth.Secret{
		Name: s.tlsCertificateName,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: &auth.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: cert,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: key,
					},
				},
			},
		},
	}, nil
}

func (s *SDSServer) createValidationContextSecret(svidResponse *workload.X509SVIDResponse) (*auth.Secret, error) {
	svid := s.getX509Svid(svidResponse)
	bundle, err := encodeCerts(svid.Bundle)
	if err != nil {
		return nil, err
	}

	for _, federatedBundle := range svid.FederatesWith {
		fb, err := encodeCerts(svidResponse.FederatedBundles[federatedBundle])
		if err != nil {
			return nil, err
		}

		bundle = append(bundle, fb...)
	}

	return &auth.Secret{
		Name: s.validateContextName,
		Type: &auth.Secret_ValidationContext{
			ValidationContext: &auth.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: bundle,
					},
				},
				VerifySubjectAltName: s.allowedSpiffeIds,
			},
		},
	}, nil
}

func (s *SDSServer) getX509Svid(svidResponse *workload.X509SVIDResponse) *workload.X509SVID {
	return svidResponse.Svids[0]
}

func (s *SDSServer) buildResponse(req *v2.DiscoveryRequest, secrets *secretInfo) (*v2.DiscoveryResponse, error) {
	nonce, err := nextNonce()
	if err != nil {
		return nil, err
	}

	resp := &v2.DiscoveryResponse{
		Nonce:       nonce,
		TypeUrl:     req.TypeUrl,
		VersionInfo: fmt.Sprint(secrets.version),
	}
	svid := false
	if secrets.svidSecret != nil && (len(req.ResourceNames) == 0 || containsString(req.ResourceNames, s.tlsCertificateName)) {
		resp.Resources = append(resp.Resources, *secrets.svidSecret)
		svid = true
	}
	bundle := false
	if secrets.bundleSecret != nil && (len(req.ResourceNames) == 0 || containsString(req.ResourceNames, s.validateContextName)) {
		resp.Resources = append(resp.Resources, *secrets.bundleSecret)
		bundle = true
	}

	s.logger.Debugf("resp: names=%q nonce=%q version=%q svid=%t bundle=%t", req.ResourceNames, resp.Nonce, resp.VersionInfo, svid, bundle)
	return resp, nil
}

func encodeCerts(data []byte) ([]byte, error) {
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	pemData := []byte{}
	for _, cert := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return pemData, nil
}

func formatKey(data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	})
}

func nextNonce() (string, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return "", errs.Wrap(err)
	}
	return hex.EncodeToString(b), nil
}

func containsString(ss []string, str string) bool {
	for _, s := range ss {
		if s == str {
			return true
		}
	}
	return false
}
