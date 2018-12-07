package cli

import (
	"flag"
	"fmt"

	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl"
	"github.com/mitchellh/cli"
	"github.com/spiffe/spiffe-envoy-agent/pkg/agent"
)

type runConfig struct {
	AgentConfig agentConfig `hcl:"spiffe-envoy-agent"`
}

type agentConfig struct {
	SocketPath            string `hcl:"socket_path"`
	WorkloadSocketPath    string `hcl:"workload_socket_path"`
	LogPath               string `hcl:"log_path"`
	LogLevel              string `hcl:"log_level"`
	TlsCertificateName    string `hcl:"tls_certificate_name"`
	ValidationContextName string `hcl:"validation_context_name"`
	JWTMode               string `hcl:"jwt_mode"`
	ConfigPath            string

	Audience             string     `hcl:"audience"`
	AllowedSpiffeIDsX509 arrayFlags `hcl:"allowed_spiffe_ids_x509"`
	AllowedSpiffeIDsJWT  arrayFlags `hcl:"allowed_spiffe_ids_jwt"`
}

type arrayFlags []string

func (s *arrayFlags) String() string {
	return "Array of strings representation"
}

func (s *arrayFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type runCommand struct {
	sc *agent.Config
}

func newRunCommand() (cli.Command, error) {
	return &runCommand{sc: &agent.Config{}}, nil
}

func (c *runCommand) Run(args []string) int {
	if err := c.run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func (c *runCommand) run(args []string) error {
	clientConfig, err := c.configure(args)
	if err != nil {
		return err
	}

	fileConfig, err := parseFile(clientConfig.AgentConfig.ConfigPath)
	if err != nil {
		return err
	}

	c.sc = newDefaultConfig()

	// Merge configs; client configuration has priority
	if err := c.mergeConfigs(fileConfig, clientConfig); err != nil {
		return err
	}

	if err := agent.Run(c.sc); err != nil {
		return err
	}

	return nil
}

func parseFile(filePath string) (*runConfig, error) {
	c := &runConfig{}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		// Return a friendly error if the file is missing
		if os.IsNotExist(err) {
			msg := "could not find config file %s: please use the -config flag"
			p, err := filepath.Abs(filePath)
			if err != nil {
				p = filePath
				msg = "could not determine CWD; config file not found at %s: use -config"
			}
			return nil, fmt.Errorf(msg, p)
		}
		return nil, err
	}

	hclTree, err := hcl.Parse(string(data))
	if err != nil {
		return nil, err
	}

	if err := hcl.DecodeObject(&c, hclTree); err != nil {
		return nil, err
	}

	return c, nil
}

func newDefaultConfig() *agent.Config {
	return &agent.Config{
		SocketPath:            defaultSocketPath,
		WorkloadSocketPath:    defaultWorkloadSocketPath,
		LogPath:               defaultLogPath,
		LogLevel:              defaultLogLevel,
		TlsCertificateName:    defaultTlsCertificateName,
		ValidationContextName: defaultValidationContextName,
		JWTMode:               defaultJWTMode,
	}
}

func (c *runCommand) mergeConfigs(fileConfig, clientConfig *runConfig) error {
	// CLI > File, merge fileConfig first
	if err := c.mergeConfig(fileConfig); err != nil {
		return err
	}
	if err := c.mergeConfig(clientConfig); err != nil {
		return err
	}
	return nil
}

func (c *runCommand) mergeConfig(rc *runConfig) error {
	// Parse server address
	if rc.AgentConfig.SocketPath != "" {
		c.sc.SocketPath = rc.AgentConfig.SocketPath
	}

	if rc.AgentConfig.WorkloadSocketPath != "" {
		c.sc.WorkloadSocketPath = rc.AgentConfig.WorkloadSocketPath
	}

	if rc.AgentConfig.LogPath != "" {
		c.sc.LogPath = rc.AgentConfig.LogPath
	}

	if rc.AgentConfig.LogLevel != "" {
		c.sc.LogLevel = parseLogLevel(rc.AgentConfig.LogLevel)
	}

	if rc.AgentConfig.TlsCertificateName != "" {
		c.sc.TlsCertificateName = rc.AgentConfig.TlsCertificateName
	}

	if rc.AgentConfig.ValidationContextName != "" {
		c.sc.ValidationContextName = rc.AgentConfig.ValidationContextName
	}

	if rc.AgentConfig.JWTMode != "" {
		var err error
		c.sc.JWTMode, err = parseJWTMode(rc.AgentConfig.JWTMode)
		if err != nil {
			return err
		}
	}

	if len(rc.AgentConfig.AllowedSpiffeIDsX509) > 0 {
		c.sc.AllowedSpiffeIDsX509 = rc.AgentConfig.AllowedSpiffeIDsX509
	}

	if len(rc.AgentConfig.AllowedSpiffeIDsJWT) > 0 {
		c.sc.AllowedSpiffeIDsJWT = rc.AgentConfig.AllowedSpiffeIDsJWT
	}

	if rc.AgentConfig.Audience != "" {
		c.sc.Audience = rc.AgentConfig.Audience
	}
	return nil
}

func (c *runCommand) Help() string {
	c.configure([]string{"-h"})
	return ""
}

func (c *runCommand) Synopsis() string {
	return "Start SPIFFE Envoy Agent service"
}

func (c *runCommand) configure(args []string) (*runConfig, error) {
	rc := &runConfig{}
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	f.StringVar(&rc.AgentConfig.SocketPath, "socketPath", "", "Envoy side-car socket path")
	f.StringVar(&rc.AgentConfig.WorkloadSocketPath, "workloadSocketPath", "", "Workload API socket path")
	f.StringVar(&rc.AgentConfig.LogPath, "logPath", "", "Log file path")
	f.StringVar(&rc.AgentConfig.LogLevel, "logLevel", "", "Log level (INFO, WARN, DEBUG)")
	f.StringVar(&rc.AgentConfig.TlsCertificateName, "tlsCertificateName", "", "Name specified in tls_certificate_sds_secret_configs")
	f.StringVar(&rc.AgentConfig.ValidationContextName, "validationContextName", "", "Name specified in validation_context_sds_secret_config")
	f.Var(&rc.AgentConfig.AllowedSpiffeIDsX509, "spiffeIDX509", "Allowed SpiffeID for x509 attestation")
	f.Var(&rc.AgentConfig.AllowedSpiffeIDsJWT, "spiffeIDJWT", "Allowed SpiffeID for JWT attestation")
	f.StringVar(&rc.AgentConfig.ConfigPath, "configPath", defaultConfigPath, "Path to a envoy side-car config file")
	f.StringVar(&rc.AgentConfig.JWTMode, "jwt_mode", "", "Proxy mode for JWT: back_end, front_end, both_insecure")

	err := f.Parse(args)

	return rc, err
}
