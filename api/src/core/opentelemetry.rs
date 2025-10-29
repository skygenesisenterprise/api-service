use opentelemetry::{global, KeyValue};
use opentelemetry::trace::{Tracer, Span, TracerProvider};
use opentelemetry::metrics::{Meter, Counter, Histogram, UpDownCounter};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry::sdk::trace::{self, Sampler};
use opentelemetry::sdk::metrics::{self, MeterProvider};
use opentelemetry::sdk::Resource;
use std::sync::Arc;
use tokio::sync::OnceCell;

static OTEL_INIT: OnceCell<OtelComponents> = OnceCell::const_new();

#[derive(Clone)]
pub struct OtelComponents {
    pub tracer: opentelemetry::sdk::trace::Tracer,
    pub meter: opentelemetry::sdk::metrics::Meter,
}

pub async fn init_opentelemetry(service_name: &str, service_version: &str) -> Result<OtelComponents, Box<dyn std::error::Error>> {
    // Create resource
    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.version", service_version.to_string()),
        KeyValue::new("service.namespace", "sky-genesis-enterprise"),
    ]);

    // Initialize tracing
    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317") // OTLP gRPC endpoint
        )
        .with_trace_config(
            trace::config()
                .with_resource(resource.clone())
                .with_sampler(Sampler::AlwaysOn)
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    let tracer = tracer_provider.tracer(service_name);

    // Initialize metrics
    let meter_provider = opentelemetry_otlp::new_pipeline()
        .metrics(opentelemetry::runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317")
        )
        .with_resource(resource)
        .with_period(std::time::Duration::from_secs(30))
        .with_timeout(std::time::Duration::from_secs(10))
        .build()?;

    let meter = meter_provider.meter(service_name);

    let components = OtelComponents { tracer, meter };
    OTEL_INIT.set(components.clone()).ok();

    // Set global defaults
    global::set_tracer_provider(tracer_provider);
    global::set_meter_provider(meter_provider);

    Ok(components)
}

pub fn get_components() -> Option<&'static OtelComponents> {
    OTEL_INIT.get()
}

// Tracing utilities
pub fn create_span(name: &str) -> opentelemetry::trace::Span {
    if let Some(components) = get_components() {
        components.tracer.start(name)
    } else {
        opentelemetry::trace::noop::NoopSpan::new().into()
    }
}

pub fn add_span_attribute(key: &str, value: &str) {
    if let Some(span) = opentelemetry::trace::Span::current().as_ref() {
        span.set_attribute(KeyValue::new(key, value.to_string()));
    }
}

pub fn record_span_event(name: &str, attributes: Vec<KeyValue>) {
    if let Some(span) = opentelemetry::trace::Span::current().as_ref() {
        span.add_event(name.to_string(), attributes);
    }
}

// Metrics utilities
#[derive(Clone)]
pub struct Metrics {
    pub http_requests_total: Counter<u64>,
    pub http_request_duration: Histogram<f64>,
    pub active_connections: UpDownCounter<i64>,
    pub api_key_validations: Counter<u64>,
    pub websocket_connections: UpDownCounter<i64>,
    pub grpc_requests_total: Counter<u64>,
    pub grpc_request_duration: Histogram<f64>,
    pub vault_operations: Counter<u64>,
    pub db_query_duration: Histogram<f64>,
}

impl Metrics {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let components = get_components().ok_or("OpenTelemetry not initialized")?;
        let meter = &components.meter;

        Ok(Metrics {
            http_requests_total: meter
                .u64_counter("http_requests_total")
                .with_description("Total number of HTTP requests")
                .init(),
            http_request_duration: meter
                .f64_histogram("http_request_duration_seconds")
                .with_description("HTTP request duration in seconds")
                .init(),
            active_connections: meter
                .i64_up_down_counter("active_connections")
                .with_description("Number of active connections")
                .init(),
            api_key_validations: meter
                .u64_counter("api_key_validations_total")
                .with_description("Total number of API key validations")
                .init(),
            websocket_connections: meter
                .i64_up_down_counter("websocket_connections")
                .with_description("Number of active WebSocket connections")
                .init(),
            grpc_requests_total: meter
                .u64_counter("grpc_requests_total")
                .with_description("Total number of gRPC requests")
                .init(),
            grpc_request_duration: meter
                .f64_histogram("grpc_request_duration_seconds")
                .with_description("gRPC request duration in seconds")
                .init(),
            vault_operations: meter
                .u64_counter("vault_operations_total")
                .with_description("Total number of Vault operations")
                .init(),
            db_query_duration: meter
                .f64_histogram("db_query_duration_seconds")
                .with_description("Database query duration in seconds")
                .init(),
        })
    }

    pub fn record_http_request(&self, method: &str, path: &str, status: u16, duration: f64) {
        let labels = vec![
            KeyValue::new("method", method.to_string()),
            KeyValue::new("path", path.to_string()),
            KeyValue::new("status", status.to_string()),
        ];

        self.http_requests_total.add(1, &labels);
        self.http_request_duration.record(duration, &labels);
    }

    pub fn update_active_connections(&self, delta: i64) {
        self.active_connections.add(delta, &[]);
    }

    pub fn record_api_key_validation(&self, valid: bool) {
        let labels = vec![KeyValue::new("valid", valid.to_string())];
        self.api_key_validations.add(1, &labels);
    }

    pub fn update_websocket_connections(&self, delta: i64) {
        self.websocket_connections.add(delta, &[]);
    }

    pub fn record_grpc_request(&self, service: &str, method: &str, duration: f64) {
        let labels = vec![
            KeyValue::new("service", service.to_string()),
            KeyValue::new("method", method.to_string()),
        ];

        self.grpc_requests_total.add(1, &labels);
        self.grpc_request_duration.record(duration, &labels);
    }

    pub fn record_vault_operation(&self, operation: &str, success: bool) {
        let labels = vec![
            KeyValue::new("operation", operation.to_string()),
            KeyValue::new("success", success.to_string()),
        ];

        self.vault_operations.add(1, &labels);
    }

    pub fn record_db_query(&self, table: &str, operation: &str, duration: f64) {
        let labels = vec![
            KeyValue::new("table", table.to_string()),
            KeyValue::new("operation", operation.to_string()),
        ];

        self.db_query_duration.record(duration, &labels);
    }
}

// Middleware for automatic tracing and metrics
pub fn trace_request(name: &str) -> opentelemetry::trace::Span {
    let span = create_span(name);
    span.set_attribute(KeyValue::new("component", "http"));
    span
}

pub fn trace_grpc_request(service: &str, method: &str) -> opentelemetry::trace::Span {
    let span = create_span(&format!("{}.{}", service, method));
    span.set_attribute(KeyValue::new("component", "grpc"));
    span.set_attribute(KeyValue::new("service", service.to_string()));
    span.set_attribute(KeyValue::new("method", method.to_string()));
    span
}

pub fn trace_vault_operation(operation: &str) -> opentelemetry::trace::Span {
    let span = create_span(&format!("vault.{}", operation));
    span.set_attribute(KeyValue::new("component", "vault"));
    span.set_attribute(KeyValue::new("operation", operation.to_string()));
    span
}

pub fn trace_db_operation(table: &str, operation: &str) -> opentelemetry::trace::Span {
    let span = create_span(&format!("db.{}.{}", table, operation));
    span.set_attribute(KeyValue::new("component", "database"));
    span.set_attribute(KeyValue::new("table", table.to_string()));
    span.set_attribute(KeyValue::new("operation", operation.to_string()));
    span
}

// Logging integration with OpenTelemetry
pub fn log_with_trace(level: &str, message: &str, attributes: Vec<KeyValue>) {
    // Create a span for the log event
    let mut span = create_span("log");
    span.set_attribute(KeyValue::new("level", level.to_string()));
    span.set_attribute(KeyValue::new("message", message.to_string()));

    for attr in attributes {
        span.set_attribute(attr);
    }

    span.end();
}

// Shutdown function
pub fn shutdown_opentelemetry() {
    global::shutdown_tracer_provider();
    global::shutdown_meter_provider();
}