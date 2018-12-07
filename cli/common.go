package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spiffe-envoy-agent/pkg/auth"
)

const (
	defaultConfigPath            = "/etc/spiffe-envoy-agent.conf"
	defaultSocketPath            = "/tmp/spiffe-envoy-agent.sock"
	defaultWorkloadSocketPath    = "/tmp/agent.sock"
	defaultLogPath               = "" //stderr
	defaultLogLevel              = logrus.InfoLevel
	defaultTlsCertificateName    = "server_cert"
	defaultValidationContextName = "validation_context"
	defaultJWTMode               = auth.FrontEnd
)

func parseLogLevel(level string) logrus.Level {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	default:
		fmt.Fprintf(os.Stderr, "Unknown log level %q. Expected one of: [DEBUG, INFO, WARN, ERROR]. Level will be set to DEBUG", level)
		return logrus.DebugLevel
	}

}

func parseJWTMode(mode string) (auth.Mode, error) {
	switch strings.ToLower(mode) {
	case "back_end":
		return auth.BackEnd, nil
	case "front_end":
		return auth.FrontEnd, nil
	case "both_insecure":
		return auth.BothInsecure, nil
	}
	return 0, fmt.Errorf("Unknown mode. Must be one of: back_end, front_end, both_insecure")
}
