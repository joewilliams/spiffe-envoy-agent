# spiffe-envoy-agent
This component allows a user to integrate SPIFFE identity framework to Envoy proxy.

## How does this integration work?

This agent implements two services:
- [Secret discovery service (SDS)](https://www.envoyproxy.io/docs/envoy/latest/configuration/secret#config-secret-discovery-service): Used to provide Envoy with x509-SVIDs fetched from SPIRE.

- [External authorization filter](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/ext_authz_filter): Used for JWT-SVIDs injection and validation in HTTP requests.


<p align="center">
<img src=img/spiffe-envoy-agent.png>
</p>


## Communication between components

When spiffe-envoy-agent starts, it registers with both components: SPIRE agent and Envoy proxy. Agent communication is done using a [Workload API client](https://github.com/spiffe/spire/tree/master/api/workload) through UDS. On the other hand, Envoy communication is ruled by Envoy [xDS protocol](https://github.com/envoyproxy/data-plane-api/blob/master/XDS_PROTOCOL.md) which also uses UDS.

### Transport layer: x509-SVID

 For **x509-SVID** management, the spiffe-envoy-agent will work as a [secret discovery service](https://www.envoyproxy.io/docs/envoy/latest/configuration/secret#config-secret-discovery-service). A stream is created between it and SPIRE agent. SPIRE will update the stream with new SVIDs according to the configured settings.

 At the same time, Envoy initiates the communication with a [discovery request](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#discoveryrequest) message. The spiffe-envoy-agent establishes a stream and sends back the previously fetched certificate and key in a [discovery response](https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#discoveryresponse) message. After that, certificates will be updated in successive responses every time SPIRE rotates a new SVID. Once Envoy applies the configurations received, it is ready to handle TLS connections.

### Application layer: JWT-SVID

On top of mTLS, HTTP requests can be done carrying a **JWT-SVID** for authentication. In this case, the spiffe-envoy-agent will work as an [external authorization filter](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/ext_authz_filter). There are two different cases to handle here.

#### Forward spiffe-envoy-agent (Injection)

Given an initial HTTP request sent to Envoy forward proxy, it will be handled by the Envoy External Authorization module. The module will forward the request header to spiffe-envoy-agent. It will query SPIRE agent to get a JWT-SVID for that request. When it gets the response, spiffe-envoy-agent will inject the JWT as a new header and will send it back to Envoy.

<p align="center">
<img src=img/jwt-forward-flow.png align=center>
</p>

#### Backward spiffe-envoy-agent (Validation)

When the HTTP request arrives at the backward proxy, it is processed by the Envoy External Authorization module and sent to the spiffe-envoy-agent for authorization. This time, it will verify the JWT-SVID. To do so, spiffe-envoy-agent will do an RPC to SPIRE agent to validate the token. If the JWT-SVID is valid and the subject claim is one of the configured to be accepted, then the request will be authorized and sent back to Envoy. Otherwise, it will be denied.
Finally, Envoy will forward the validated and authorized request to the backend service.

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
Sample configuration files are provided for [spiffe-envoy-agent](config-examples/spiffe-envoy-agent.conf) and for [forward](config-examples/frontend-envoy.yaml)/[backward](config-examples/backend-envoy.yaml) Envoy proxies. There is also a full demo scenario available [here](AddlinkToDemo).
