package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	externalAuth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	"github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/ptypes/struct"
	"github.com/sirupsen/logrus"
	workload_dial "github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Mode type will define how this service will behave
type Mode int

const (
	// FrontEnd Mode will insert JWT in header
	FrontEnd Mode = 1 + iota
	// BackEnd Mode will validate JWT header
	BackEnd
	// BothInsecure make the service to figure it out if it should behave as BK or FE
	// However, it is insecure. @TODO: find a secure way of doing smart mode selection.
	BothInsecure
)

func (m Mode) String() string {
	switch m {
	case FrontEnd:
		return "front_end"
	case BackEnd:
		return "back_end"
	case BothInsecure:
		return "insecure"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", m)
	}
}

// AuthServer implements externalAuth.AuthorizationServer interface
type AuthServer struct {
	spiffeClient      workload.SpiffeWorkloadAPIClient
	logger            *logrus.Logger
	acceptedSpiffeIDs []string
	audience          string
	mode              Mode
}

// NewAuthServer creates a new Auth server according to the given config
func NewAuthServer(log *logrus.Logger, spiffeIDs []string, mode Mode, udsPath string, audience string) (*AuthServer, error) {
	spiffeClient, err := getSpiffeClient(udsPath)
	if err != nil {
		return nil, fmt.Errorf("fail to create spiffe client: %v", err)
	}

	return &AuthServer{
		logger:            log,
		acceptedSpiffeIDs: spiffeIDs,
		mode:              mode,
		spiffeClient:      spiffeClient,
		audience:          audience,
	}, nil
}

//JWTsvidHeaderKey is the header key of the JWT-SVID
//@TODO: Ask which will be the best name for this header: should it be custom or should we use: 'authorization'?
const (
	JWTsvidHeaderKey = "authorization"
	bearerStr        = "Bearer "
)

// Check will behave in three differents ways according to the 'mode' value in AuthServer
func (s AuthServer) Check(ctx context.Context, request *externalAuth.CheckRequest) (*externalAuth.CheckResponse, error) {
	s.logger.Debugf("New incoming request. Mode is: %v", s.mode)
	reqHeaders := request.Attributes.GetRequest().GetHttp().GetHeaders()
	s.logger.Debug(mapToString(reqHeaders, "Incoming Headers"))

	svid, hasSVID := parseJWTHeader(reqHeaders[JWTsvidHeaderKey])

	switch s.mode {

	case FrontEnd: // JWT Injection
		if hasSVID {
			err := fmt.Errorf("request already contains a JWT header. Verify mode if expected mode is %v", s.mode)
			s.logger.Errorf("%v", err)
			return nil, err
		}
		// Add a JWT-SVID header with my spiffeID
		return s.injectJWTSVID(ctx)

	case BackEnd: // JWT Validation
		if hasSVID {
			// Validate the JWT-SVID based on accepted spiffeID list
			return s.validateJWTSVID(ctx, svid)
		}
		err := fmt.Errorf("request does not contain a JWT header. Verify mode if expected mode is %v", s.mode)
		s.logger.Errorf("%v", err)
		return nil, err

	case BothInsecure: // Injection & Validation based on header value
		// If headers contains a JWT-SVID
		if hasSVID {
			// Validate the JWT-SVID based on accepted spiffeID list
			return s.validateJWTSVID(ctx, svid)
		}
		// If not, add a JWT-SVID header with my spiffeID
		return s.injectJWTSVID(ctx)

	default:
		err := fmt.Errorf("unknown server mode: %v", s.mode)
		s.logger.Errorf("Error selecting server mode. %v", err)
		return nil, err
	}
}

func (s AuthServer) fetchJWTSVID(ctx context.Context) (*workload.JWTSVID, error) {
	// Create a JWT request and query spiffe client
	jwtRequest := &workload.JWTSVIDRequest{
		Audience: []string{s.audience},
	}
	jwtSVID, err := s.spiffeClient.FetchJWTSVID(withSecurityHeader(ctx), jwtRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to FetchJWTSVID: %v", err)
	}
	if len(jwtSVID.Svids) == 0 {
		return nil, errors.New("no SVID was found in JWT-SVID response")
	}
	s.logger.Debugf("Fetched JWT for spiffeID: %s", jwtSVID.Svids[0].GetSpiffeId())

	return jwtSVID.Svids[0], nil
}

func (s AuthServer) injectJWTSVID(ctx context.Context) (*externalAuth.CheckResponse, error) {
	s.logger.Debug("JWT-SVID header not found: Injecting JWT SVID")

	jwtSVID, err := s.fetchJWTSVID(ctx)
	if err != nil {
		s.logger.Error(err)
		return nil, err
	}

	response := &externalAuth.CheckResponse{}
	headers := []*core.HeaderValueOption{
		{
			Append: &types.BoolValue{
				Value: false, //Default is true
			},
			Header: &core.HeaderValue{
				Key:   JWTsvidHeaderKey,
				Value: fmt.Sprintf("%s%s", bearerStr, jwtSVID.GetSvid()),
			},
		},
	}

	response.HttpResponse = &externalAuth.CheckResponse_OkResponse{
		OkResponse: &externalAuth.OkHttpResponse{
			Headers: headers,
		},
	}

	s.logger.Debugf("Sending response with %v new headers\n", len(response.GetOkResponse().Headers))
	return response, nil
}

func (s AuthServer) validateJWTSVID(ctx context.Context, svid string) (*externalAuth.CheckResponse, error) {
	// Check if JWT signature is valid.
	subject, err := s.validateJWTSVIDViaWorkloadAPI(ctx, svid)
	if err != nil {
		s.logger.Errorf("Invalid JWT Signature: %v", err)
		return forbiddenResponse("%v", err), nil
	}

	// If subject contains an spiffeID included in the list then authorize, deny otherwise
	if !s.isSpiffeIDAccepted(subject) {
		s.logger.Debugf("%s is not in accepted spiffeID lists. Request denied", subject)
		return forbiddenResponse("%q is not an allowed principal", subject), nil
	}

	s.logger.Debugf("%s is an accepted spiffeID. Request accepted", subject)
	return okResponse(), nil
}

func (s AuthServer) isSpiffeIDAccepted(spiffeID string) bool {
	for _, acceptedSpiffeID := range s.acceptedSpiffeIDs {
		if spiffeID == acceptedSpiffeID {
			return true
		}
	}
	return false
}

func (s AuthServer) validateJWTSVIDViaWorkloadAPI(ctx context.Context, svid string) (string, error) {
	// Create a JWT request and query spiffe client
	jwtRequest := &workload.ValidateJWTSVIDRequest{
		Audience: s.audience,
		Svid:     svid,
	}

	response, err := s.spiffeClient.ValidateJWTSVID(withSecurityHeader(ctx), jwtRequest)
	if err != nil {
		// unwrap invalid argument error
		if s, ok := status.FromError(err); ok {
			if s.Code() == codes.InvalidArgument {
				return "", errors.New(s.Message())
			}
		}
		return "", err
	}

	subjectField := response.Claims.Fields["sub"]
	if subjectField == nil {
		return "", errors.New("JWT missing subject claim")
	}

	subject, ok := subjectField.Kind.(*structpb.Value_StringValue)
	if !ok {
		return "", errors.New("JWT subject claim not a string")
	}

	return subject.StringValue, nil
}

// get token from svid
func parseJWTHeader(header string) (string, bool) {
	suffix := strings.TrimPrefix(header, bearerStr)
	if suffix == header {
		return "", false
	}
	return suffix, true
}

// getSpiffeClient creates a spiffe worlkload API client on the given unix domain socket
func getSpiffeClient(socketPath string) (workload.SpiffeWorkloadAPIClient, error) {
	conn, err := workload_dial.Dial(context.Background(), &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		return nil, fmt.Errorf("error connecting to spiffe client: %v", err)
	}

	return workload.NewSpiffeWorkloadAPIClient(conn), nil
}

func mapToString(myMap map[string]string, mapName string) string {
	var mapAsStr string
	for k, v := range myMap {
		mapAsStr = mapAsStr + fmt.Sprintf("\t %s: %s\n", k, v)
	}

	return fmt.Sprintf("%s:\n%s\n", mapName, mapAsStr)
}

func withSecurityHeader(ctx context.Context) context.Context {
	// Set the security header needed for connecting with the workload API
	header := metadata.Pairs("workload.spiffe.io", "true")
	return metadata.NewOutgoingContext(ctx, header)
}

func okResponse() *externalAuth.CheckResponse {
	return &externalAuth.CheckResponse{
		HttpResponse: &externalAuth.CheckResponse_OkResponse{},
	}
}

func forbiddenResponse(format string, args ...interface{}) *externalAuth.CheckResponse {
	return &externalAuth.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.PERMISSION_DENIED),
		},
		HttpResponse: &externalAuth.CheckResponse_DeniedResponse{
			DeniedResponse: &externalAuth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Forbidden,
				},
				Body: fmt.Sprintf(format, args...),
			},
		},
	}
}
