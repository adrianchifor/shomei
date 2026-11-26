use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Extension, Json,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, COOKIE, ORIGIN},
        uri::PathAndQuery,
    },
    response::{Html, IntoResponse},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest;
use serde::Deserialize;
use uuid::Uuid;

use super::{App, HttpUpstream, PREFIX, RequestHost, reverse_endpoint};
use crate::{
    auth::ApiError,
    config::{Endpoint, http_path_is_unambiguous, http_path_matches},
};

pub(super) const HEADER: &str = "x-shomei-browser-approval";
pub(super) const CHECK_PATH: &str = "/api/auth/browser/check";

#[derive(Clone, Copy)]
pub(super) struct Policy<'a> {
    rule: Option<&'a str>,
    ttl: u64,
}

pub(super) fn policy<'a>(site: &'a HttpUpstream, path: &str) -> Option<Policy<'a>> {
    let paths = site.protected_paths.as_ref()?;
    let fresh = Some(Policy { rule: None, ttl: 0 });
    let Ok(decoded) = percent_encoding::percent_decode_str(path).decode_utf8() else {
        return fresh;
    };
    if !http_path_is_unambiguous(&decoded)
        || (decoded.len() != path.len()
            && decoded.matches('/').count() != path.matches('/').count())
        || http_path_matches(&decoded, PREFIX)
    {
        return fresh;
    }
    paths
        .iter()
        .filter(|rule| http_path_matches(&decoded, rule.path()))
        .max_by_key(|rule| rule.path().len())
        .map(|rule| Policy {
            rule: Some(rule.path()),
            ttl: rule.session_ttl(site.protected_session_ttl_seconds),
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    method: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    host: String,
    request: Target,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Probe {
    request: Target,
    approval: Option<Uuid>,
}

pub struct Intent {
    host: Endpoint,
    method: Method,
    target: PathAndQuery,
    rule: Option<String>,
    ttl: u64,
}

impl Intent {
    fn new(host: Endpoint, method: Method, target: PathAndQuery, policy: Policy<'_>) -> Self {
        Self {
            host,
            method,
            target,
            rule: policy.rule.map(str::to_owned),
            ttl: policy.ttl,
        }
    }

    fn parse(app: &App, host: Endpoint, target: Target) -> Result<Self, ApiError> {
        let site = app.upstreams.get(&host).ok_or(ApiError(
            StatusCode::FORBIDDEN,
            "unknown browser approval host",
        ))?;
        const INVALID: ApiError =
            ApiError(StatusCode::BAD_REQUEST, "invalid browser approval target");
        let method: Method = target.method.parse().map_err(|_| INVALID)?;
        if method == Method::CONNECT || !super::safe_return_path(&target.path) {
            return Err(INVALID);
        }
        let target: PathAndQuery = target.path.parse().map_err(|_| INVALID)?;
        let policy = policy(site, target.path()).ok_or(ApiError(
            StatusCode::BAD_REQUEST,
            "browser approval requires a protected path",
        ))?;
        Ok(Self::new(host, method, target, policy))
    }

    fn covers(&self, request: &Self) -> bool {
        self.host == request.host
            && self.method == request.method
            && if self.ttl == 0 {
                self.target == request.target
            } else {
                self.rule == request.rule && request.ttl > 0
            }
    }

    fn cookie_name(&self) -> String {
        let key = format!(
            "{} {} {}",
            self.host,
            self.method,
            self.rule.as_deref().unwrap_or("")
        );
        let hash = digest::digest(&digest::SHA256, key.as_bytes());
        format!(
            "__Host-shomei-action-{}",
            URL_SAFE_NO_PAD.encode(&hash.as_ref()[..16])
        )
    }
}

pub(super) fn intent(app: &App, body: Start) -> Result<Intent, ApiError> {
    let host = Endpoint::parse(&body.host, Some(443))
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid browser approval host"))?;
    Intent::parse(app, host, body.request)
}

struct Permit {
    intent: Intent,
    generation: u64,
    deadline: Instant,
}

pub(super) struct Approvals {
    permits: Mutex<HashMap<Uuid, Permit>>,
    limit: usize,
}

impl Approvals {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            permits: Mutex::new(HashMap::new()),
            limit,
        }
    }

    pub(super) fn issue(
        &self,
        intent: Intent,
        generation: u64,
    ) -> Result<axum::response::Response, ApiError> {
        let reusable = intent.ttl > 0;
        let origin = site_origin(&intent.host);
        let id = self.store(intent, generation)?;
        Ok(Json(serde_json::json!({
            "approval": id,
            "reusable": reusable,
            "site_origin": origin,
        }))
        .into_response())
    }

    fn store(&self, intent: Intent, generation: u64) -> Result<Uuid, ApiError> {
        let mut permits = self.permits.lock().map_err(ApiError::internal)?;
        let now = Instant::now();
        if permits.len() >= self.limit {
            permits.retain(|_, permit| permit.deadline > now && permit.generation == generation);
        }
        if permits.len() >= self.limit {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "too many protected path approvals",
            ));
        }
        let id = Uuid::new_v4();
        let seconds = if intent.ttl > 0 { intent.ttl } else { 30 };
        permits.insert(
            id,
            Permit {
                intent,
                generation,
                deadline: now + Duration::from_secs(seconds),
            },
        );
        Ok(id)
    }

    fn accepts(
        &self,
        id: Uuid,
        intent: &Intent,
        generation: u64,
        consume: bool,
    ) -> Result<bool, ApiError> {
        let mut permits = self.permits.lock().map_err(ApiError::internal)?;
        let Some(permit) = permits.get(&id) else {
            return Ok(false);
        };
        if permit.deadline <= Instant::now() || permit.generation != generation {
            permits.remove(&id);
            return Ok(false);
        }
        if !permit.intent.covers(intent) {
            return Ok(false);
        }
        if consume && permit.intent.ttl == 0 {
            permits.remove(&id);
        }
        Ok(true)
    }
}

pub(super) fn site_origin(host: &Endpoint) -> String {
    let authority = host.to_string();
    let authority = if host.port == 443 {
        authority.strip_suffix(":443").unwrap_or(&authority)
    } else {
        &authority
    };
    format!("https://{authority}")
}

pub(super) fn same_origin_browser(
    headers: &HeaderMap,
    host: &Endpoint,
    require_origin: bool,
) -> bool {
    let mut fetch_sites = headers.get_all("sec-fetch-site").iter();
    if fetch_sites
        .next()
        .is_none_or(|value| value != "same-origin")
        || fetch_sites.next().is_some()
    {
        return false;
    }
    let mut origins = headers.get_all(ORIGIN).iter();
    let valid = match origins.next() {
        Some(value) => value.as_bytes() == site_origin(host).as_bytes(),
        None => !require_origin,
    };
    valid && origins.next().is_none()
}

pub(super) fn authorize(
    app: &App,
    host: &Endpoint,
    request: &Request,
    policy: Policy<'_>,
) -> Result<bool, ApiError> {
    let Some(path) = request.uri().path_and_query().cloned() else {
        return Ok(false);
    };
    let authority = reverse_endpoint(request);
    let generation = app.auth.generation();
    let mut values = request.headers().get_all(HEADER).iter();
    let require_origin = !matches!(*request.method(), Method::GET | Method::HEAD);
    if let Some(value) = values.next() {
        let Some(id) = value.to_str().ok().and_then(|value| value.parse().ok()) else {
            return Ok(false);
        };
        if values.next().is_some()
            || authority.as_ref() != Some(host)
            || !same_origin_browser(request.headers(), host, require_origin)
        {
            return Ok(false);
        }
        let intent = Intent::new(host.clone(), request.method().clone(), path, policy);
        return app.approvals.accepts(id, &intent, generation, true);
    }
    let Some(authority) = authority.filter(|_| policy.ttl > 0) else {
        return Ok(false);
    };
    let headers = request.headers();
    if !headers.contains_key(COOKIE) {
        return Ok(false);
    }
    if (headers.contains_key("sec-fetch-site") || headers.contains_key(ORIGIN))
        && !same_origin_browser(headers, &authority, require_origin)
    {
        return Ok(false);
    }
    let intent = Intent::new(authority, request.method().clone(), path, policy);
    let name = intent.cookie_name();
    let mut tokens = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key.trim() == name).then_some(value)
        });
    let Some(id) = tokens.next().and_then(|value| value.parse().ok()) else {
        return Ok(false);
    };
    if tokens.next().is_some() {
        return Ok(false);
    }
    app.approvals.accepts(id, &intent, generation, false)
}

pub(super) fn issue_cookie(
    app: &App,
    request: &Request,
    policy: Policy<'_>,
    generation: u64,
) -> Result<Option<HeaderValue>, ApiError> {
    let ttl = policy.ttl;
    if ttl == 0 {
        return Ok(None);
    }
    let (Some(host), Some(path)) = (reverse_endpoint(request), request.uri().path_and_query())
    else {
        return Ok(None);
    };
    let intent = Intent::new(host, request.method().clone(), path.clone(), policy);
    let name = intent.cookie_name();
    let id = app.approvals.store(intent, generation)?;
    let cookie = format!("{name}={id}; Path=/; Max-Age={ttl}; Secure; HttpOnly; SameSite=Strict");
    HeaderValue::from_str(&cookie)
        .map(Some)
        .map_err(ApiError::internal)
}

pub(super) async fn check(
    State(app): State<Arc<App>>,
    Extension(RequestHost(host)): Extension<RequestHost>,
    Json(body): Json<Probe>,
) -> Result<impl IntoResponse, ApiError> {
    let intent = Intent::parse(&app, host, body.request)?;
    let ready = if let Some(id) = body.approval {
        app.approvals
            .accepts(id, &intent, app.auth.generation(), false)?
    } else {
        false
    };
    Ok(Json(serde_json::json!({
        "gateway": app.origin,
        "host": intent.host.to_string(),
        "ready": ready,
        "scope": intent.rule.as_deref().filter(|_| intent.ttl > 0),
    })))
}

pub(super) async fn script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../assets/approval.js"),
    )
}

pub(super) async fn stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../assets/approval.css"),
    )
}

pub(super) async fn dialog() -> impl IntoResponse {
    Html(include_str!("../../assets/approval.html"))
}

pub(super) async fn popup() -> impl IntoResponse {
    Html(include_str!("../../assets/approval-popup.html"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_protected_path_approval_cannot_be_reused() {
        let approvals = Approvals::new(1);
        let policy = || Policy {
            rule: Some("/api/jobs"),
            ttl: 60,
        };
        let intent = || {
            Intent::new(
                Endpoint::parse("localhost", Some(443)).unwrap(),
                Method::POST,
                "/api/jobs".parse().unwrap(),
                policy(),
            )
        };
        approvals.issue(intent(), 0).unwrap();
        let id = {
            let mut permits = approvals.permits.lock().unwrap();
            let (&id, permit) = permits.iter_mut().next().unwrap();
            permit.deadline = Instant::now();
            id
        };
        assert!(!approvals.accepts(id, &intent(), 0, true).unwrap());
        assert!(approvals.permits.lock().unwrap().is_empty());
    }
}
