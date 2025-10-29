# gRPC / QUIC Integration

## Overview

The SGE Enterprise API implements high-performance inter-service communication using gRPC over QUIC (HTTP/3), providing efficient binary serialization and reduced latency for service-to-service interactions.

## Architecture

### gRPC Implementation
- **Protocol Buffers**: Version 3 (proto3)
- **Transport**: HTTP/2 with QUIC support
- **Streaming**: Bidirectional streaming support
- **Interceptors**: Authentication and logging middleware

### QUIC Transport
- **HTTP/3**: Next-generation HTTP protocol
- **UDP-based**: Reduced connection overhead
- **0-RTT**: Faster connection establishment
- **Multiplexing**: Efficient request multiplexing

## Service Definitions

### Mail Service
```protobuf
service MailService {
  rpc SendEmail (SendEmailRequest) returns (SendEmailResponse);
  rpc GetEmail (GetEmailRequest) returns (GetEmailResponse);
  rpc ListEmails (ListEmailsRequest) returns (ListEmailsResponse);
}

message SendEmailRequest {
  Email email = 1;
}

message SendEmailResponse {
  string message_id = 1;
  string status = 2;
  int64 timestamp = 3;
}
```

### Search Service
```protobuf
service SearchService {
  rpc Search (SearchRequest) returns (SearchResponse);
  rpc IndexDocument (IndexDocumentRequest) returns (IndexDocumentResponse);
}

message SearchRequest {
  string query = 1;
  repeated string filters = 2;
  int32 limit = 3;
  int32 offset = 4;
}

message SearchResponse {
  repeated SearchResult results = 1;
  int32 total_count = 2;
  int32 query_time_ms = 3;
}
```

## HTTP REST Proxies

### Mail Service Proxy

#### Send Email
```http
POST /api/v1/mail/send
Content-Type: application/json
Authorization: Bearer <token>

{
  "to": ["recipient@example.com"],
  "subject": "Hello",
  "body": "Message content"
}
```

**Response:**
```json
{
  "message_id": "msg_123456",
  "status": "queued",
  "timestamp": 1640995200
}
```

#### Get Email
```http
GET /api/v1/mail/123
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": "123",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "subject": "Hello",
  "body": "Message content",
  "timestamp": 1640995200
}
```

### Search Service Proxy

#### Search
```http
GET /api/v1/search?q=enterprise&limit=10&offset=0
Authorization: Bearer <token>
```

**Response:**
```json
{
  "results": [
    {
      "id": "doc_1",
      "title": "Enterprise Architecture",
      "content": "Enterprise architecture overview...",
      "url": "/docs/architecture",
      "score": 0.95
    }
  ],
  "total_count": 1,
  "query_time_ms": 45
}
```

## Client Implementation

### Rust gRPC Client
```rust
use sky_genesis::mail_service_client::MailServiceClient;
use sky_genesis::{SendEmailRequest, Email};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MailServiceClient::connect("http://localhost:50051").await?;

    let email = Email {
        id: "".to_string(),
        from: "sender@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject: "Test Email".to_string(),
        body: "Hello from gRPC!".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        attachments: vec![],
    };

    let request = tonic::Request::new(SendEmailRequest {
        email: Some(email),
    });

    let response = client.send_email(request).await?;
    println!("Response: {:?}", response);

    Ok(())
}
```

### Go gRPC Client
```go
package main

import (
    "context"
    "log"
    "time"

    pb "github.com/sky-genesis/api/proto"
    "google.golang.org/grpc"
)

func main() {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()

    client := pb.NewMailServiceClient(conn)

    ctx, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()

    email := &pb.Email{
        From:    "sender@example.com",
        To:      []string{"recipient@example.com"},
        Subject: "Test Email",
        Body:    "Hello from gRPC!",
    }

    resp, err := client.SendEmail(ctx, &pb.SendEmailRequest{Email: email})
    if err != nil {
        log.Fatalf("could not send email: %v", err)
    }

    log.Printf("Response: %s", resp.MessageId)
}
```

## Server Implementation

### Service Registration
```rust
use tonic::{transport::Server, Request, Response, Status};
use sky_genesis::{mail_service_server::MailServiceServer, SendEmailResponse};

#[derive(Default)]
pub struct MailServiceImpl;

#[tonic::async_trait]
impl sky_genesis::mail_service_server::MailService for MailServiceImpl {
    async fn send_email(
        &self,
        request: Request<sky_genesis::SendEmailRequest>,
    ) -> Result<Response<sky_genesis::SendEmailResponse>, Status> {
        let req = request.into_inner();

        // Process email sending logic here
        // Integrate with Stalwart or other mail service

        let response = sky_genesis::SendEmailResponse {
            message_id: format!("msg_{}", uuid::Uuid::new_v4()),
            status: "queued".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        Ok(Response::new(response))
    }
}

// Start server
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse()?;
    let mail_service = MailServiceImpl::default();

    Server::builder()
        .add_service(MailServiceServer::new(mail_service))
        .serve(addr)
        .await?;

    Ok(())
}
```

## QUIC Configuration

### Client Configuration
```rust
use quinn::{ClientConfig, Endpoint};

let mut client_config = ClientConfig::with_native_roots();
client_config.alpn_protocols = vec![b"h3".to_vec()];

let mut endpoint = Endpoint::client("[::]:0".parse()?)?;
endpoint.set_default_client_config(client_config);
```

### Server Configuration
```rust
use quinn::{ServerConfig, Endpoint};

let server_config = ServerConfig::with_single_cert(
    cert_chain,
    private_key,
)?;
server_config.alpn_protocols = vec![b"h3".to_vec()];

let endpoint = Endpoint::server(server_config, "[::]:443".parse()?)?;
```

## Load Balancing & Service Discovery

### Service Registration
```rust
use etcd_client::{Client, PutOptions};

let mut client = Client::connect(["localhost:2379"], None).await?;

client.put(
    "/services/mail/1",
    "localhost:50051",
    Some(PutOptions::new().with_lease(lease_id)),
).await?;
```

### Client-side Load Balancing
```rust
use tower::{load::Load, Service};
use tonic::transport::Channel;

let channel = Channel::from_static("http://localhost:50051")
    .load_balance(LoadBalance::RoundRobin::new());

let mut client = MailServiceClient::new(channel);
```

## Monitoring & Observability

### Metrics
- `grpc_requests_total`: Total gRPC requests
- `grpc_request_duration_seconds`: Request duration histogram
- `grpc_responses_total`: Response status codes
- `grpc_active_connections`: Active connections

### Traces
- Request/response spans
- Service method spans
- Serialization/deserialization spans

### Health Checks
```protobuf
service Health {
  rpc Check (HealthCheckRequest) returns (HealthCheckResponse);
}

message HealthCheckResponse {
  enum ServingStatus {
    UNKNOWN = 0;
    SERVING = 1;
    NOT_SERVING = 2;
  }
  ServingStatus status = 1;
}
```

## Security

### mTLS Configuration
```rust
use tonic::transport::{Identity, ClientTlsConfig, ServerTlsConfig};

let client_tls = ClientTlsConfig::new()
    .identity(Identity::from_pem(client_cert, client_key))
    .ca_certificate(ca_cert);

let server_tls = ServerTlsConfig::new()
    .identity(Identity::from_pem(server_cert, server_key));
```

### Authentication Interceptors
```rust
use tonic::{Request, Status};

fn auth_interceptor(mut req: Request<()>) -> Result<Request<()>, Status> {
    let token = req.metadata().get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(token) => {
            // Validate token
            req.extensions_mut().insert(ValidatedToken(token.to_string()));
            Ok(req)
        }
        None => Err(Status::unauthenticated("No valid auth token")),
    }
}
```

## Performance Optimization

### Connection Pooling
```rust
use bb8::Pool;
use bb8_tonic::TonicConnectionManager;

let manager = TonicConnectionManager::<MailServiceClient<Channel>>::new(
    Channel::from_static("http://localhost:50051")
);

let pool = Pool::builder().build(manager).await?;
```

### Compression
```rust
use tonic::codec::CompressionEncoding;

Server::builder()
    .add_service(
        MailServiceServer::new(service)
            .send_compressed(CompressionEncoding::Gzip)
            .accept_compressed(CompressionEncoding::Gzip)
    )
```

### Streaming
```protobuf
service StreamingService {
  rpc UploadFile (stream FileChunk) returns (UploadResponse);
  rpc DownloadFile (DownloadRequest) returns (stream FileChunk);
}
```

## Configuration

### Environment Variables
```bash
GRPC_MAIL_SERVICE_ADDR=localhost:50051
GRPC_SEARCH_SERVICE_ADDR=localhost:50052
GRPC_MAX_MESSAGE_SIZE=4194304
GRPC_KEEPALIVE_TIME=600
GRPC_TIMEOUT=30
```

### Docker Compose
```yaml
version: '3.8'
services:
  mail-service:
    image: sky-genesis/mail-service:latest
    ports:
      - "50051:50051"
    environment:
      - GRPC_PORT=50051

  search-service:
    image: sky-genesis/search-service:latest
    ports:
      - "50052:50052"
    environment:
      - GRPC_PORT=50052
```

## Troubleshooting

### Common Issues
- **Connection Refused**: Check service availability
- **TLS Errors**: Verify certificates
- **Timeout Errors**: Adjust timeout settings
- **Message Size**: Check max message size limits

### Debugging
```bash
# Enable gRPC debug logging
export RUST_LOG=tonic=debug

# Use grpcurl for testing
grpcurl -plaintext localhost:50051 list

grpcurl -plaintext -d '{"email": {"from": "test"}}' \
  localhost:50051 sky_genesis.MailService/SendEmail
```

### Performance Monitoring
```bash
# Use ghz for load testing
ghz --insecure \
    --proto proto/sky_genesis.proto \
    --call sky_genesis.MailService.SendEmail \
    --data '{"email": {"from": "test@example.com"}}' \
    localhost:50051
```

This gRPC/QUIC implementation provides a high-performance, scalable foundation for inter-service communication in the SGE ecosystem.