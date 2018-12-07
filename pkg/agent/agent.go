package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	authAPI "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	sdsAPI "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-envoy-agent/pkg/auth"
	"github.com/spiffe/spiffe-envoy-agent/pkg/sds"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// Config stores configuration for spiffe-envoy-agent server
type Config struct {
	SocketPath            string
	WorkloadSocketPath    string
	LogPath               string
	LogLevel              logrus.Level
	TlsCertificateName    string
	ValidationContextName string
	AllowedSpiffeIDsX509  []string
	AllowedSpiffeIDsJWT   []string
	JWTMode               auth.Mode
	Audience              string
}

// Run will create and start a new spiffe-envoy-agent server according to the config received.
func Run(c *Config) error {
	// Set up log
	log := logrus.New()
	log.SetLevel(c.LogLevel)

	if c.LogPath != "" {
		file, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.Out = file
			defer file.Close()
		} else {
			log.Warnf("Failed to log to file, using default stderr: %v", err)
		}
	}

	log.Infof("config=%+v", *c)

	// Create UDS listener for envoy
	os.Remove(c.SocketPath)
	grpcListener, err := net.Listen("unix", c.SocketPath)
	if err != nil {
		log.Errorf("Fail to create socket: %v", err)
		return err
	}
	defer grpcListener.Close()

	// Create grpc server
	logPanic := func(p interface{}) error {
		log.Errorf("panic: %v\n%s", p, debug.Stack())
		return grpc.Errorf(codes.Internal, "%s", p)
	}
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(grpc_recovery.WithRecoveryHandler(logPanic)),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(grpc_recovery.WithRecoveryHandler(logPanic)),
		),
	)
	defer grpcServer.Stop()

	if len(c.AllowedSpiffeIDsX509) > 0 {
		if err := validateSpiffeIDs(c.AllowedSpiffeIDsX509...); err != nil {
			log.Errorf("fail trying to validate x509 allowed spiffeIDs: %v \n", err)
			return err
		}
	}

	if len(c.AllowedSpiffeIDsJWT) > 0 {
		if err := validateSpiffeIDs(c.AllowedSpiffeIDsJWT...); err != nil {
			log.Errorf("fail trying to validate JWT allowed spiffeIDs: %v \n", err)
			return err
		}
	}

	if err := validateSpiffeIDs(c.Audience); err != nil {
		log.Errorf("fail trying to validate audience: %v \n", err)
		return err
	}

	sdsServer := sds.NewSDSServer(log, c.TlsCertificateName, c.ValidationContextName, c.AllowedSpiffeIDsX509)
	authServer, err := auth.NewAuthServer(log, c.AllowedSpiffeIDsJWT, c.JWTMode, c.WorkloadSocketPath, c.Audience)
	if err != nil {
		log.Errorf("fail to create authServer: %v", err)
		return err
	}

	// Register server as secret discovery service
	sdsAPI.RegisterSecretDiscoveryServiceServer(grpcServer, sdsServer)
	// Register server with as authorization service
	authAPI.RegisterAuthorizationServer(grpcServer, authServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errch := make(chan error, 2)

	// Start SDS server workload API updates
	log.Info("Running workload API updates...")
	go func() {
		errch <- sdsServer.Run(ctx, c.WorkloadSocketPath)
	}()

	// Start gRPC server
	log.Infof("Starting SDS server at %s ...", c.SocketPath)
	go func() {
		errch <- grpcServer.Serve(grpcListener)
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	select {
	case sig := <-sigc:
		log.Infof("Caught signal %s: shutting down.", sig)
		return nil
	case err := <-errch:
		log.Errorf("%+v", err)
		return err
	}
}

func validateSpiffeIDs(spiffeIDs ...string) error {
	for _, spiffeID := range spiffeIDs {
		if err := idutil.ValidateSpiffeID(spiffeID, idutil.AllowAny()); err != nil {
			return fmt.Errorf("fail to validate SpiffeID %v: %v", spiffeID, err)
		}
	}

	return nil
}
