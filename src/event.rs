//! Audit event types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single audit log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,

    /// Correlation ID for request tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,

    /// Client IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    /// HTTP method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Request path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Query string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_string: Option<String>,

    /// Host header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// HTTP protocol version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,

    /// Total request duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    /// User ID (from header)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Session ID (from header)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// User agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Request headers (filtered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<HashMap<String, String>>,

    /// Response headers (filtered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,

    /// Request body (truncated, redacted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,

    /// Response body (truncated, redacted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,

    /// Request body size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_size: Option<u64>,

    /// Response body size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_size: Option<u64>,

    /// Route ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,

    /// Upstream server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,

    /// Upstream response time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_duration_ms: Option<u64>,

    /// Agent decisions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_decisions: Option<Vec<AgentDecision>>,

    /// Custom fields from headers
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub custom_fields: Option<HashMap<String, String>>,
}

impl Default for AuditEvent {
    fn default() -> Self {
        Self {
            timestamp: Some(Utc::now()),
            correlation_id: None,
            client_ip: None,
            method: None,
            path: None,
            query_string: None,
            host: None,
            protocol: None,
            status_code: None,
            duration_ms: None,
            user_id: None,
            session_id: None,
            user_agent: None,
            request_headers: None,
            response_headers: None,
            request_body: None,
            response_body: None,
            request_body_size: None,
            response_body_size: None,
            route_id: None,
            upstream: None,
            upstream_duration_ms: None,
            agent_decisions: None,
            custom_fields: None,
        }
    }
}

/// Agent decision record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDecision {
    /// Agent name
    pub agent: String,
    /// Decision (allow, block, etc.)
    pub decision: String,
    /// Reason code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Rule IDs that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_ids: Option<Vec<String>>,
    /// Processing time in microseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
}

/// Builder for creating audit events.
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    pub fn new() -> Self {
        Self {
            event: AuditEvent::default(),
        }
    }

    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.event.correlation_id = Some(id.into());
        self
    }

    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.event.client_ip = Some(ip.into());
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.event.method = Some(method.into());
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.event.path = Some(path.into());
        self
    }

    pub fn query_string(mut self, qs: impl Into<String>) -> Self {
        self.event.query_string = Some(qs.into());
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.event.host = Some(host.into());
        self
    }

    pub fn protocol(mut self, proto: impl Into<String>) -> Self {
        self.event.protocol = Some(proto.into());
        self
    }

    pub fn status_code(mut self, code: u16) -> Self {
        self.event.status_code = Some(code);
        self
    }

    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.event.duration_ms = Some(ms);
        self
    }

    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.event.user_id = Some(id.into());
        self
    }

    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.event.session_id = Some(id.into());
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.event.user_agent = Some(ua.into());
        self
    }

    pub fn request_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.event.request_headers = Some(headers);
        self
    }

    pub fn response_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.event.response_headers = Some(headers);
        self
    }

    pub fn request_body(mut self, body: impl Into<String>) -> Self {
        self.event.request_body = Some(body.into());
        self
    }

    pub fn response_body(mut self, body: impl Into<String>) -> Self {
        self.event.response_body = Some(body.into());
        self
    }

    pub fn request_body_size(mut self, size: u64) -> Self {
        self.event.request_body_size = Some(size);
        self
    }

    pub fn response_body_size(mut self, size: u64) -> Self {
        self.event.response_body_size = Some(size);
        self
    }

    pub fn route_id(mut self, id: impl Into<String>) -> Self {
        self.event.route_id = Some(id.into());
        self
    }

    pub fn upstream(mut self, upstream: impl Into<String>) -> Self {
        self.event.upstream = Some(upstream.into());
        self
    }

    pub fn upstream_duration_ms(mut self, ms: u64) -> Self {
        self.event.upstream_duration_ms = Some(ms);
        self
    }

    pub fn agent_decision(mut self, decision: AgentDecision) -> Self {
        self.event
            .agent_decisions
            .get_or_insert_with(Vec::new)
            .push(decision);
        self
    }

    pub fn custom_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event
            .custom_fields
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> AuditEvent {
        self.event
    }
}

impl Default for AuditEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder() {
        let event = AuditEventBuilder::new()
            .correlation_id("req-123")
            .client_ip("192.168.1.1")
            .method("GET")
            .path("/api/users")
            .status_code(200)
            .duration_ms(42)
            .build();

        assert_eq!(event.correlation_id, Some("req-123".to_string()));
        assert_eq!(event.status_code, Some(200));
    }

    #[test]
    fn test_event_serialization() {
        let event = AuditEventBuilder::new()
            .method("POST")
            .path("/api/login")
            .status_code(401)
            .build();

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"method\":\"POST\""));
        assert!(json.contains("\"status_code\":401"));
        // None fields should be skipped
        assert!(!json.contains("user_id"));
    }

    #[test]
    fn test_agent_decision() {
        let event = AuditEventBuilder::new()
            .agent_decision(AgentDecision {
                agent: "waf".to_string(),
                decision: "block".to_string(),
                reason: Some("SQL injection detected".to_string()),
                rule_ids: Some(vec!["942100".to_string()]),
                duration_us: Some(150),
            })
            .build();

        assert!(event.agent_decisions.is_some());
        assert_eq!(event.agent_decisions.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_custom_fields() {
        let event = AuditEventBuilder::new()
            .custom_field("tenant_id", "tenant-abc")
            .custom_field("environment", "production")
            .build();

        let fields = event.custom_fields.unwrap();
        assert_eq!(fields.get("tenant_id"), Some(&"tenant-abc".to_string()));
    }
}
