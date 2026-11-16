//! gRPC and Protobuf bodies as editable text (roadmap 2.5). Pure decoding lives in `pm_http::protobuf`; per-message
//! gzip in `pm_ai::body`. Nothing here sends traffic.

use pm_http::protobuf::{BodyKind, ProtoError, base64_decode, base64_encode, encode_text};
use pm_policy::{Actor, ActorKind};

use crate::api_types::{ProtobufDecodeRequest, ProtobufDecoded, ProtobufEncodeRequest, ProtobufEncoded, ProtobufPart};
use crate::{Result, Service, ServiceError};

fn invalid(e: ProtoError) -> ServiceError {
    ServiceError::Invalid(e.to_string())
}

fn kind_named(name: &str) -> Result<BodyKind> {
    BodyKind::from_name(&name.trim().to_ascii_lowercase()).ok_or_else(|| {
        ServiceError::Invalid(format!("unknown kind {name:?}: use grpc, grpc-web, grpc-web-text or protobuf"))
    })
}

impl Service {
    /// Decodes a gRPC or Protobuf body into text. For agents the text is redacted and wrapped as untrusted content.
    pub fn protobuf_decode(&self, actor: &Actor, req: &ProtobufDecodeRequest) -> Result<ProtobufDecoded> {
        let annotate = req.annotate.unwrap_or(true);
        let given = [req.exchange_id.is_some(), req.body_b64.is_some(), req.body_text.is_some()];
        if given.iter().filter(|g| **g).count() != 1 {
            return Err(ServiceError::Invalid("give exactly one of exchange_id, body_b64 and body_text".into()));
        }
        let (mut kind, body, mut grpc_encoding, head_status, head_message) = if let Some(id) = req.exchange_id {
            let ex = self.exchange_raw(id)?;
            let raw = match req.part.unwrap_or_default() {
                ProtobufPart::Request => Some(ex.request.as_slice()),
                ProtobufPart::Response => ex.response.as_deref(),
            };
            let raw = raw.ok_or_else(|| ServiceError::NotFound(format!("response of exchange {id}")))?;
            let m = pm_ai::body::protobuf_message(raw)
                .ok_or_else(|| ServiceError::Invalid(format!("exchange {id} has no gRPC or Protobuf body there")))?;
            (Some(m.kind), m.body, m.grpc_encoding, m.grpc_status, m.grpc_message)
        } else {
            let body = match (&req.body_b64, &req.body_text) {
                (Some(b), _) => base64_decode(b.as_bytes()).map_err(invalid)?,
                (_, Some(t)) => t.clone().into_bytes(),
                _ => Vec::new(),
            };
            (None, body, None, None, None)
        };
        if let Some(name) = &req.kind {
            kind = Some(kind_named(name)?);
        } else if let Some(ct) = &req.content_type {
            kind = BodyKind::from_content_type(ct).or(kind);
            if kind.is_none() {
                return Err(ServiceError::Invalid(format!("content type {ct:?} is not gRPC or Protobuf")));
            }
        }
        let kind = kind
            .ok_or_else(|| ServiceError::Invalid("give content_type or kind to say how the body is framed".into()))?;
        if let Some(e) = &req.grpc_encoding {
            grpc_encoding = Some(e.clone());
        }
        let mut r = pm_ai::body::protobuf_render(kind, &body, grpc_encoding.as_deref(), annotate).map_err(invalid)?;
        if kind.is_framed() {
            for (name, value, slot) in
                [("grpc-status", head_status, &mut r.grpc_status), ("grpc-message", head_message, &mut r.grpc_message)]
            {
                if let (None, Some(v)) = (&*slot, value) {
                    r.text.push_str(&format!("# {name}: {v}\n"));
                    *slot = Some(v);
                }
            }
        }
        let agent = actor.kind != ActorKind::Human;
        let text = match (agent, self.redactor_for(actor)) {
            (false, _) => r.text,
            (true, Some(red)) => pm_ai::wrap_untrusted(&red.redact(&r.text)),
            (true, None) => pm_ai::wrap_untrusted(&r.text),
        };
        Ok(ProtobufDecoded {
            kind: kind.name().into(),
            text,
            exact: r.exact,
            messages: r.messages,
            grpc_status: r.grpc_status,
            grpc_message: r.grpc_message,
            notes: r.notes,
            notice: agent.then(|| pm_ai::UNTRUSTED_NOTICE.to_string()),
        })
    }

    /// Encodes edited text back into body bytes.
    pub fn protobuf_encode(&self, req: &ProtobufEncodeRequest) -> Result<ProtobufEncoded> {
        let kind = match &req.kind {
            Some(k) => kind_named(k)?,
            None => BodyKind::Protobuf,
        };
        let bytes = encode_text(kind, &req.text).map_err(invalid)?;
        Ok(ProtobufEncoded { kind: kind.name().into(), body_b64: base64_encode(&bytes), length: bytes.len() })
    }
}
