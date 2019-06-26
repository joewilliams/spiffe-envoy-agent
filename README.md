_**IMPORTANT NOTE**: If you are using SPIRE to issue SPIFFE identities, the SPIRE Agent supports the Envoy SDS API natively, and this component is not necessary. [Read more](https://blog.envoyproxy.io/using-spire-to-automatically-deliver-tls-certificates-to-envoy-for-stronger-authentication-be5606ac9c75) about how this works._

# spiffe-envoy-agent
This component allows a user to integrate Envoy proxy with the SPIFFE identity framework.

## How does this integration work?

This agent implements two services:
- [Secret discovery service (SDS)](https://www.envoyproxy.io/docs/envoy/latest/configuration/secret#config-secret-discovery-service): Used to provide Envoy with x509-SVIDs fetched from SPIFFE Workload API.

- [External authorization filter](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/ext_authz_filter): Used for JWT-SVIDs injection and validation in HTTP requests.


<p align="center">
<img src=img/spiffe-envoy-agent.png>
</p>


## Communication between components

When spiffe-envoy-agent starts, it registers with the SPIFFE Workload API and starts listening for requests from Envoy. Communication with the [SPIFFE Workload API](https://github.com/spiffe/spire/blob/master/proto/api/workload/workload.proto) is done using gRPC over a unix domain socket (or UDS). Envoy uses the [xDS API](https://github.com/envoyproxy/data-plane-api/blob/master/XDS_PROTOCOL.md) over UDS to talk to the spiffe-envoy-agent.

### Transport layer: X509-SVID

 For [x509-SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md) management, the spiffe-envoy-agent exposes a [secret discovery service](https://www.envoyproxy.io/docs/envoy/latest/configuration/secret#config-secret-discovery-service), or SDS. A stream is created between the spiffe-envoy-agent and the SPIFFE Workload API. The SPIFFE Workload API updates the stream with new SVIDs according to the configured settings.

 At the same time, Envoy initiates the SDS communication with a [discovery request](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#discoveryrequest) message. The spiffe-envoy-agent establishes a stream and sends Envoy the latest certificate and key in a [discovery response](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#discoveryresponse) message. Certificate updates are then communicated in successive responses every time the SPIFFE Workload API rotates the SVID. Once Envoy applies the configurations received, it is ready to handle TLS connections.

### Application layer: JWT-SVID

On top of mTLS, HTTP requests can be done carrying a [JWT-SVID](https://github.com/spiffe/spiffe/blob/master/standards/JWT-SVID.md) for authentication. In this case, the spiffe-envoy-agent works as an [external authorization filter](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/ext_authz_filter). There are two different cases to handle here.

#### Forward spiffe-envoy-agent (Injection)

Every HTTP request sent to the Envoy forward proxy is handled by the Envoy External Authorization module. This module forwards the request header to the configured spiffe-envoy-agent, which obtains a JWT-SVID for that request from the SPIFFE Workload API. The JWT is then injected as a new header and sent back to Envoy.

<p align="center">
<img src=img/jwt-forward-flow.png align=center>
</p>

#### Reverse spiffe-envoy-agent (Validation)

When the HTTP request arrives at the reverse proxy, it is processed by the Envoy External Authorization module and sent to the spiffe-envoy-agent for validation/authorization. This time, spiffe-envoy-agent verifies the JWT-SVID included in the HTTP header. To do so, it utilizes a validation endpoint exposed over the SPIFFE Workload API. Once validated, spiffe-envoy-agent verifies that the SPIFFE ID in the subject claim matches one of the configured SPIFFE IDs, at which point the request is authorized and sent back to Envoy. If validation fails, or the SPIFFE ID does not match, then the request will be denied. Finally, Envoy forwards the validated and authorized request to the backend service.

<p align="center">
<img src=img/jwt-backward-flow.png align=center>
</p>



## Building spiffe-envoy-agent

### Prerequisites
- [Go 1.11](https://blog.golang.org/go1.11)

### Clone this repository
```
git clone https://github.com/spiffe/spiffe-envoy-agent.git
```

### Build from source

Set Go Modules on and build from the root repository folder:

```
cd spiffe-envoy-agent
GO111MODULE=on go build
```

If you are on darwin, remember to set the target operating system to linux:

```
GO111MODULE=on GOOS=linux go build
```

## Running spiffe-envoy-agent
Sample configuration files are provided for [spiffe-envoy-agent](config-examples/spiffe-envoy-agent.conf) and for [forward](config-examples/frontend-envoy.yaml)/[reverse](config-examples/backend-envoy.yaml) Envoy proxies. There is also a full demo scenario available [here](https://github.com/spiffe/spiffe-example/tree/master/spiffe-envoy-agent).
