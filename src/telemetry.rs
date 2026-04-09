//! OpenTelemetry initialisation.
//!
//! Activates only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.  When absent,
//! the behaviour is identical to the pre-OTel version: structured log events
//! go to stderr, controlled by `RUST_LOG`.
//!
//! All existing `tracing::info!` / `debug!` / `warn!` call sites become OTel
//! span events automatically via the `tracing-opentelemetry` bridge layer —
//! no changes to those sites are required.
//!
//! Standard OTel environment variables are honoured:
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`  — collector endpoint (e.g. `http://localhost:4318`)
//! - `OTEL_EXPORTER_OTLP_HEADERS`   — comma-separated `key=value` headers
//! - `OTEL_EXPORTER_OTLP_TIMEOUT`   — export timeout in milliseconds
//! - `OTEL_SERVICE_NAME`             — overrides the default `sf-keyaudit` service name
//! - `OTEL_RESOURCE_ATTRIBUTES`      — additional resource attributes
//! - `RUST_LOG`                      — log level filter (e.g. `debug`, `sf_keyaudit=trace`)

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{SdkTracerProvider, SimpleSpanProcessor};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};

// ── Public API ────────────────────────────────────────────────────────────────

/// Held by `main()` for the lifetime of the process.
///
/// When dropped, flushes any pending spans to the OTLP endpoint and shuts
/// down the SDK cleanly, ensuring in-flight spans are exported before the
/// process exits.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Best-effort flush and shutdown — errors are silently ignored
            // because we are already in the process-exit path.
            let _ = provider.shutdown();
        }
    }
}

/// Initialise the global `tracing` subscriber.
///
/// * **With** `OTEL_EXPORTER_OTLP_ENDPOINT` set: an OpenTelemetry OTLP layer
///   is stacked on the fmt layer, forwarding all spans and events to the
///   configured collector via OTLP/HTTP (protobuf, blocking transport).
///
/// * **Without** the env var: only the fmt layer is active — identical to the
///   pre-OTel `RUST_LOG`-controlled stderr behaviour.
///
/// Returns a [`TelemetryGuard`] that **must** be assigned (`let _guard = …`)
/// in `main` and kept alive until the process is ready to exit.
pub fn init() -> TelemetryGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        match build_provider() {
            Ok(provider) => {
                let tracer = provider.tracer("sf-keyaudit");
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .with(otel_layer)
                    .init();

                return TelemetryGuard { provider: Some(provider) };
            }
            Err(e) => {
                // OTel init failed — fall back to stderr logging.
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .init();
                eprintln!(
                    "warning: OpenTelemetry init failed ({e}); falling back to stderr logging"
                );
                return TelemetryGuard { provider: None };
            }
        }
    }

    // No OTLP endpoint configured — fmt-only subscriber (pre-OTel behaviour).
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    TelemetryGuard { provider: None }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Build an [`SdkTracerProvider`] that exports spans via OTLP/HTTP using a
/// [`SimpleSpanProcessor`] (fully synchronous — no async runtime required).
///
/// Transport settings (endpoint, headers, timeout) are read from the standard
/// OTel environment variables automatically.
fn build_provider() -> Result<SdkTracerProvider, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .map_err(|e| e.to_string())?;

    // `service.name` is the most important resource attribute in OTel.
    // `OTEL_SERVICE_NAME` or `OTEL_RESOURCE_ATTRIBUTES` can override these
    // at runtime without recompilation.
    let resource = opentelemetry_sdk::Resource::builder_empty()
        .with_service_name("sf-keyaudit")
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_span_processor(SimpleSpanProcessor::new(exporter))
        .build();

    // Register as the global OTel tracer provider so that any code using the
    // opentelemetry API directly (e.g. third-party crates) also benefits.
    opentelemetry::global::set_tracer_provider(provider.clone());

    Ok(provider)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::TelemetryGuard;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    #[test]
    fn guard_drop_with_no_provider_is_safe() {
        let g = TelemetryGuard { provider: None };
        drop(g); // must not panic
    }

    #[test]
    fn guard_drop_with_provider_shuts_down_cleanly() {
        // Build an in-memory provider (no actual export target) and verify that
        // dropping the guard calls shutdown without panicking.
        let provider = SdkTracerProvider::builder().build();
        let g = TelemetryGuard { provider: Some(provider) };
        drop(g); // must not panic
    }
}
