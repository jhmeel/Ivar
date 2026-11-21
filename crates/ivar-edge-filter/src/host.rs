//! Proxy-Wasm host glue. One VM per gateway worker; the root context owns
//! the logic and HTTP contexts borrow it.

use crate::config::EdgeConfig;
use crate::logic::{EdgeAction, EdgeLogic, RequestView};
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root { logic: None, core_call: None, control_call: None }) });
}}

/// What a call to the core was for: a failed event batch is requeued, a
/// failed feed poll is simply retried on the next tick.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CoreCall {
    Events,
    Feed,
}

struct Root {
    logic: Option<Rc<RefCell<EdgeLogic>>>,
    /// One call to the core at a time: an event batch or, when idle, the
    /// verdict feed. Both answer with verdicts and the feed cursor.
    core_call: Option<(u32, CoreCall)>,
    /// One policy refresh from the control plane at a time, every tick, so
    /// every gateway worker converges on a new signed policy quickly.
    control_call: Option<u32>,
}

fn now_ms(ctx: &dyn Context) -> i64 {
    ctx.get_current_time().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Context for Root {
    fn on_http_call_response(&mut self, token: u32, _headers: usize, body_size: usize, _trailers: usize) {
        let body = self.get_http_call_response_body(0, body_size).unwrap_or_default();
        let now = now_ms(self);
        // Only a 200 carries an ack or a bundle. A 204 means the policy is
        // current; anything else (an unreachable core or control plane
        // answered by the gateway itself) is ignored and the last signed
        // policy stays in force.
        let status = self.get_http_call_response_header(":status").unwrap_or_default();
        let Some(logic) = self.logic.clone() else { return };
        if self.core_call.as_ref().map(|(t, _)| *t) == Some(token) {
            let (_, kind) = self.core_call.take().expect("core call");
            if status == "200" {
                let n = logic.borrow_mut().apply_ack(&body);
                if n > 0 {
                    log::info!("ivar: applied {n} core verdicts");
                }
            } else {
                log::warn!("ivar: core answered {status}, keeping the current state");
                if kind == CoreCall::Events {
                    logic.borrow_mut().requeue_unacked();
                }
            }
        } else if self.control_call == Some(token) {
            self.control_call = None;
            // A 204 means the policy is current; anything else but a 200 (an
            // unreachable control plane answered by the gateway itself) is
            // ignored and the last signed policy stays in force.
            if status == "200" {
                let text = String::from_utf8_lossy(&body).to_string();
                if !text.trim().is_empty() {
                    match logic.borrow_mut().apply_bundle(&text, now) {
                        crate::logic::PolicyUpdate::Applied { version } => log::info!("ivar: policy {version} applied"),
                        crate::logic::PolicyUpdate::Rejected { reason } => log::warn!("ivar: policy update rejected, current policy kept: {reason}"),
                    }
                }
            } else if status != "204" {
                log::warn!("ivar: control plane answered {status}, keeping the current policy");
            }
        }
    }
}

impl RootContext for Root {
    fn on_configure(&mut self, _size: usize) -> bool {
        let cfg: EdgeConfig = match self.get_plugin_configuration().map(|b| serde_json::from_slice(&b)) {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                log::error!("ivar: invalid configuration: {e}");
                return false;
            }
            None => EdgeConfig::default(),
        };
        self.set_tick_period(Duration::from_millis(cfg.tick_ms.max(100)));
        let now = now_ms(self);
        self.logic = Some(Rc::new(RefCell::new(EdgeLogic::new(cfg, now))));
        true
    }

    fn on_tick(&mut self) {
        let Some(logic) = self.logic.clone() else { return };
        if self.core_call.is_none() {
            let (cluster, authority, batch) = {
                let mut l = logic.borrow_mut();
                (l.cfg.core_cluster.clone(), l.cfg.core_authority.clone(), l.drain_outbox())
            };
            match batch {
                Some(body) => {
                    let headers = vec![(":method", "POST"), (":path", "/v1/events"), (":authority", authority.as_str()), ("content-type", "application/json")];
                    match self.dispatch_http_call(&cluster, headers, Some(&body), vec![], Duration::from_secs(2)) {
                        Ok(t) => self.core_call = Some((t, CoreCall::Events)),
                        Err(e) => {
                            logic.borrow_mut().requeue_unacked();
                            log::warn!("ivar: core unreachable, keeping last signed policy: {e:?}");
                        }
                    }
                }
                None => {
                    // Nothing to send: fetch standing verdicts, since each
                    // gateway worker keeps its own cache.
                    let path = logic.borrow().feed_path();
                    let headers = vec![(":method", "GET"), (":path", path.as_str()), (":authority", authority.as_str())];
                    if let Ok(t) = self.dispatch_http_call(&cluster, headers, None, vec![], Duration::from_secs(2)) {
                        self.core_call = Some((t, CoreCall::Feed));
                    }
                }
            }
        }
        if self.control_call.is_none() {
            let (cluster, authority, path) = {
                let l = logic.borrow();
                (l.cfg.control_cluster.clone(), l.cfg.control_authority.clone(), l.policy_path())
            };
            let headers = vec![(":method", "GET"), (":path", path.as_str()), (":authority", authority.as_str())];
            if let Ok(t) = self.dispatch_http_call(&cluster, headers, None, vec![], Duration::from_secs(2)) {
                self.control_call = Some(t);
            }
        }
    }

    fn create_http_context(&self, _id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Request { logic: self.logic.clone()?, view: RequestView::default(), body_keys: vec![], body_seen: false, headers_seen: false }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct Request {
    logic: Rc<RefCell<EdgeLogic>>,
    view: RequestView,
    body_keys: Vec<String>,
    body_seen: bool,
    /// False when a filter ahead of this one (Coraza) answered the request
    /// before its headers reached us.
    headers_seen: bool,
}

impl Request {
    fn read_view(&self, mut engine_alerts: Vec<String>) -> RequestView {
        let header = |n: &str| self.get_http_request_header(n).unwrap_or_default();
        let source = self
            .get_property(vec!["source", "address"])
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        let client_ip = source.rsplit_once(':').map(|(ip, _)| ip.trim_matches(['[', ']']).to_string()).unwrap_or(source);
        engine_alerts.extend(header("x-coraza-rules").split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from));
        RequestView {
            method: header(":method"),
            path: header(":path").split('?').next().unwrap_or("").to_string(),
            client_ip,
            user_agent: header("user-agent"),
            request_id: header("x-request-id"),
            content_type: header("content-type"),
            session: String::new(),
            engine_alerts,
        }
    }

    fn apply(&self, a: EdgeAction) -> Action {
        match a {
            EdgeAction::Continue => Action::Continue,
            EdgeAction::Respond { status, body, headers } => {
                let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                self.send_http_response(status, h, Some(body.as_bytes()));
                Action::Pause
            }
        }
    }
}

impl Context for Request {}

impl HttpContext for Request {
    fn on_http_request_headers(&mut self, _n: usize, end_of_stream: bool) -> Action {
        self.headers_seen = true;
        self.view = self.read_view(vec![]);
        let now = now_ms(self);
        let a = self.logic.borrow_mut().on_request_headers(&self.view, now);
        let action = self.apply(a);
        if action == Action::Continue && !end_of_stream && self.view.content_type.contains("json") {
            // Headers continue; the body is buffered (Pause on each chunk)
            // until it is inspected for field names. A refused request is
            // answered locally and the upstream stream is reset before it
            // ever receives a complete request.
            return Action::Continue;
        }
        action
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream || self.body_seen {
            return if end_of_stream { Action::Continue } else { Action::Pause };
        }
        self.body_seen = true;
        let body = self.get_http_request_body(0, body_size).unwrap_or_default();
        let now = now_ms(self);
        let (a, keys) = self.logic.borrow_mut().on_request_body(&self.view, &body, now);
        self.body_keys = keys;
        self.apply(a)
    }

    fn on_log(&mut self) {
        let status: u32 = self.get_http_response_header(":status").and_then(|s| s.parse().ok()).unwrap_or(0);
        if !self.headers_seen {
            // Coraza with the OWASP Core Rule Set runs ahead of this filter
            // and answered the request itself. Report it as an engine alert so
            // the core correlates the virtual patching block with everything
            // else the source does.
            let alert = if status == 403 { "coraza.crs_block" } else { "coraza.local_reply" };
            self.view = self.read_view(vec![alert.to_string()]);
        }
        let now = now_ms(self);
        self.logic.borrow_mut().on_log(&self.view, &self.body_keys, status, now);
    }
}
