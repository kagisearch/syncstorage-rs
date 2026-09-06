use super::auth_request::{JwtAuthData};

pub trait EmitApiMetric {
    fn emit_api_metric(&self, label: &str);
}

macro_rules! impl_emit_api_metric {
    ($type:ty) => {
        impl EmitApiMetric for $type {
            fn emit_api_metric(&self, label: &str) {
                self.metrics.incr_with_tag(
                    label,
                    "tokenserver_origin",
                    &self.tokenserver_origin.to_string(),
                );
            }
        }
    };
}

impl_emit_api_metric!(JwtAuthData);
