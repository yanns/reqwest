use hyper_util::client::legacy::connect::dns::Name as HyperName;
use tower_service::Service;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use crate::error::BoxError;

/// Alias for an `Iterator` trait object over `SocketAddr`.
pub type Addrs = Box<dyn Iterator<Item = SocketAddr> + Send>;

/// Alias for the `Future` type returned by a DNS resolver.
pub type Resolving = Pin<Box<dyn Future<Output = Result<Addrs, BoxError>> + Send>>;

/// Trait for customizing DNS resolution in reqwest.
pub trait Resolve: Send + Sync {
    /// Performs DNS resolution on a `Name`.
    /// The return type is a future containing an iterator of `SocketAddr`.
    ///
    /// It differs from `tower_service::Service<Name>` in several ways:
    ///  * It is assumed that `resolve` will always be ready to poll.
    ///  * It does not need a mutable reference to `self`.
    ///  * Since trait objects cannot make use of associated types, it requires
    ///    wrapping the returned `Future` and its contained `Iterator` with `Box`.
    ///
    /// Explicitly specified port in the URL will override any port in the resolved `SocketAddr`s.
    /// Otherwise, port `0` will be replaced by the conventional port for the given scheme (e.g. 80 for http).
    fn resolve(&self, name: Name) -> Resolving;
}

/// A name that must be resolved to addresses.
#[derive(Debug)]
pub struct Name(pub(super) HyperName);

/// A more general trait implemented for types implementing `Resolve`.
///
/// Unnameable, only exported to aid seeing what implements this.
pub trait IntoResolve {
    #[doc(hidden)]
    fn into_resolve(self) -> Arc<dyn Resolve>;
}

impl Name {
    /// View the name as a string.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for Name {
    type Err = sealed::InvalidNameError;

    fn from_str(host: &str) -> Result<Self, Self::Err> {
        HyperName::from_str(host)
            .map(Name)
            .map_err(|_| sealed::InvalidNameError { _ext: () })
    }
}

#[derive(Clone)]
pub(crate) struct DynResolver {
    resolver: Arc<dyn Resolve>,
}

impl DynResolver {
    pub(crate) fn new(resolver: Arc<dyn Resolve>) -> Self {
        Self { resolver }
    }

    #[cfg(feature = "socks")]
    pub(crate) fn gai() -> Self {
        Self::new(Arc::new(super::gai::GaiResolver::new()))
    }

    /// Resolve an HTTP host and port, not just a domain name.
    ///
    /// This does the same thing that hyper-util's HttpConnector does, before
    /// calling out to its underlying DNS resolver.
    #[cfg(feature = "socks")]
    pub(crate) async fn http_resolve(
        &self,
        target: &http::Uri,
    ) -> Result<impl Iterator<Item = std::net::SocketAddr>, BoxError> {
        let host = target.host().ok_or("missing host")?;
        let port = target
            .port_u16()
            .unwrap_or_else(|| match target.scheme_str() {
                Some("https") => 443,
                Some("socks4") | Some("socks4a") | Some("socks5") | Some("socks5h") => 1080,
                _ => 80,
            });

        let explicit_port = target.port().is_some();

        let addrs = self.resolver.resolve(host.parse()?).await?;

        Ok(addrs.map(move |mut addr| {
            if explicit_port || addr.port() == 0 {
                addr.set_port(port);
            }
            addr
        }))
    }
}

impl Service<HyperName> for DynResolver {
    type Response = Addrs;
    type Error = BoxError;
    type Future = Resolving;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: HyperName) -> Self::Future {
        self.resolver.resolve(Name(name))
    }
}

pub(crate) struct DnsResolverWithOverrides {
    dns_resolver: Arc<dyn Resolve>,
    overrides: Arc<HashMap<String, Vec<SocketAddr>>>,
}

impl DnsResolverWithOverrides {
    pub(crate) fn new(
        dns_resolver: Arc<dyn Resolve>,
        overrides: HashMap<String, Vec<SocketAddr>>,
    ) -> Self {
        DnsResolverWithOverrides {
            dns_resolver,
            overrides: Arc::new(overrides),
        }
    }
}

impl Resolve for DnsResolverWithOverrides {
    fn resolve(&self, name: Name) -> Resolving {
        match self.overrides.get(name.as_str()) {
            Some(dest) => {
                let addrs: Addrs = Box::new(dest.clone().into_iter());
                Box::pin(std::future::ready(Ok(addrs)))
            }
            None => self.dns_resolver.resolve(name),
        }
    }
}

impl IntoResolve for Arc<dyn Resolve> {
    fn into_resolve(self) -> Arc<dyn Resolve> {
        self
    }
}

impl<R> IntoResolve for Arc<R>
where
    R: Resolve + 'static,
{
    fn into_resolve(self) -> Arc<dyn Resolve> {
        self
    }
}

impl<R> IntoResolve for R
where
    R: Resolve + 'static,
{
    fn into_resolve(self) -> Arc<dyn Resolve> {
        Arc::new(self)
    }
}

/// Shared state tracking the current set of valid IPs per hostname.
/// Updated by `DnsTrackingResolver` on every resolution.
pub(crate) type DnsState = Arc<RwLock<HashMap<String, HashSet<IpAddr>>>>;

/// Attached to each connection; holds the info needed to decide
/// whether the connection's IP is still valid.
#[derive(Clone, Debug)]
pub(crate) struct DnsCheck {
    pub(crate) hostname: String,
    pub(crate) connected_ip: IpAddr,
    pub(crate) dns_state: DnsState,
}

impl DnsCheck {
    /// Returns `true` when the DNS state has been updated **and** this
    /// connection's IP is no longer in the valid set.
    pub(crate) fn is_obsolete(&self) -> bool {
        if let Ok(state) = self.dns_state.read() {
            if let Some(valid_ips) = state.get(&self.hostname) {
                return !valid_ips.contains(&self.connected_ip);
            }
        }
        // No record yet → not obsolete (first resolution hasn't happened through us)
        false
    }
}

/// Resolver wrapper that updates a shared [`DnsState`] on every resolution.
pub(crate) struct DnsTrackingResolver {
    inner: Arc<dyn Resolve>,
    state: DnsState,
}

impl DnsTrackingResolver {
    pub(crate) fn new(inner: Arc<dyn Resolve>, state: DnsState) -> Self {
        Self { inner, state }
    }
}

impl Resolve for DnsTrackingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let state = self.state.clone();
        let hostname = name.as_str().to_string();

        Box::pin(async move {
            let addrs = inner.resolve(name).await?;

            // Collect into a Vec so we can both inspect and return them.
            let addrs_vec: Vec<SocketAddr> = addrs.collect();
            let new_ips: HashSet<IpAddr> = addrs_vec.iter().map(|a| a.ip()).collect();

            if let Ok(mut map) = state.write() {
                map.insert(hostname, new_ips);
            }

            let result: Addrs = Box::new(addrs_vec.into_iter());
            Ok(result)
        })
    }
}

mod sealed {
    use std::fmt;

    #[derive(Debug)]
    pub struct InvalidNameError {
        pub(super) _ext: (),
    }

    impl fmt::Display for InvalidNameError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("invalid DNS name")
        }
    }

    impl std::error::Error for InvalidNameError {}
}
