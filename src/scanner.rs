use crate::parser::Target;
use futures::stream::{self, StreamExt};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Success,
    Redirect,
    Restricted,
    Missing,
    ServerError,
    Other,
    Failed,
}

#[derive(Clone)]
pub struct ScanResult {
    pub host: String,
    pub url: String,
    pub status: Option<u16>,
    pub category: Category,
    pub detail: String,
    pub elapsed_ms: u128,
}

pub struct DiscoveryReport {
    pub passive_count: usize,
    pub brute_count: usize,
    pub permutation_count: usize,
    pub wildcard: bool,
    pub resolved: Vec<String>,
}

pub fn build_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(12))
        .connect_timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent("CheckSu/1.0 (+t.me/goviraq)")
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn build_harvest_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) CheckSu/1.0 (+t.me/goviraq)")
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn classify(status: u16) -> Category {
    match status {
        200..=299 => Category::Success,
        300..=399 => Category::Redirect,
        401 | 403 | 407 | 429 => Category::Restricted,
        404 | 410 => Category::Missing,
        500..=599 => Category::ServerError,
        _ => Category::Other,
    }
}

pub async fn scan_host(client: &Client, host: &str) -> ScanResult {
    let start = Instant::now();

    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{host}");
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let code = status.as_u16();
                let category = classify(code);
                let mut detail = status
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .to_string();

                if category == Category::Redirect {
                    if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
                        if let Ok(value) = location.to_str() {
                            detail = format!("-> {value}");
                        }
                    }
                }

                return ScanResult {
                    host: host.to_string(),
                    url,
                    status: Some(code),
                    category,
                    detail,
                    elapsed_ms: start.elapsed().as_millis(),
                };
            }
            Err(error) => {
                if scheme == "http" {
                    return ScanResult {
                        host: host.to_string(),
                        url: format!("https://{host}"),
                        status: None,
                        category: Category::Failed,
                        detail: shorten_error(&error),
                        elapsed_ms: start.elapsed().as_millis(),
                    };
                }
            }
        }
    }

    ScanResult {
        host: host.to_string(),
        url: format!("https://{host}"),
        status: None,
        category: Category::Failed,
        detail: "No response".to_string(),
        elapsed_ms: start.elapsed().as_millis(),
    }
}

fn shorten_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "Connection timed out".to_string();
    }
    if error.is_connect() {
        return "Connection failed".to_string();
    }
    if error.is_request() {
        return "Invalid request".to_string();
    }
    "Host unreachable".to_string()
}

pub async fn scan_targets(
    client: &Client,
    targets: &[Target],
    concurrency: usize,
) -> Vec<ScanResult> {
    let hosts: Vec<String> = targets.iter().map(|t| t.host.clone()).collect();
    scan_hosts(client, &hosts, concurrency).await
}

pub async fn scan_hosts(
    client: &Client,
    hosts: &[String],
    concurrency: usize,
) -> Vec<ScanResult> {
    stream::iter(hosts.iter().cloned())
        .map(|host| {
            let client = client.clone();
            async move { scan_host(&client, &host).await }
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await
}

pub fn wordlist_size() -> usize {
    wordlist().len()
}

pub async fn discover_subdomains(domain: &str) -> DiscoveryReport {
    let harvest_client = build_harvest_client();
    let resolver = build_resolver();

    let passive = passive_collect(&harvest_client, domain).await;
    let (wildcard, wildcard_ips) = detect_wildcard(&resolver, domain).await;

    let passive_candidates: Vec<String> = passive.iter().cloned().collect();
    let resolved_passive = resolve_batch(&resolver, passive_candidates, 200, &wildcard_ips).await;

    let words = wordlist();
    let brute_count = words.len();
    let brute_candidates: Vec<String> = words
        .iter()
        .map(|word| format!("{word}.{domain}"))
        .filter(|host| !passive.contains(host))
        .collect();
    let resolved_brute = resolve_batch(&resolver, brute_candidates, 600, &wildcard_ips).await;

    let mut seed: Vec<String> = resolved_passive.clone();
    seed.extend(resolved_brute.clone());

    let perm_candidates = permutations(domain, &seed, &passive);
    let permutation_count = perm_candidates.len();
    let resolved_perm = resolve_batch(&resolver, perm_candidates, 600, &wildcard_ips).await;

    let mut resolved: BTreeSet<String> = BTreeSet::new();
    for name in resolved_passive {
        resolved.insert(name);
    }
    for name in resolved_brute {
        resolved.insert(name);
    }
    for name in resolved_perm {
        resolved.insert(name);
    }
    resolved.remove(domain);

    DiscoveryReport {
        passive_count: passive.len(),
        brute_count,
        permutation_count,
        wildcard,
        resolved: resolved.into_iter().collect(),
    }
}

fn build_resolver() -> TokioAsyncResolver {
    let nameservers = [
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
        IpAddr::V4(Ipv4Addr::new(64, 6, 64, 6)),
    ];
    let group = NameServerConfigGroup::from_ips_clear(&nameservers, 53, true);
    let config = ResolverConfig::from_parts(None, vec![], group);

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    opts.cache_size = 8192;
    opts.num_concurrent_reqs = 1024;
    opts.preserve_intermediates = false;
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4Only;

    TokioAsyncResolver::tokio(config, opts)
}

async fn resolve_one(
    resolver: TokioAsyncResolver,
    host: String,
) -> Option<(String, Vec<IpAddr>)> {
    match resolver.lookup_ip(host.as_str()).await {
        Ok(lookup) => {
            let addresses: Vec<IpAddr> = lookup.iter().collect();
            if addresses.is_empty() {
                None
            } else {
                Some((host, addresses))
            }
        }
        Err(_) => None,
    }
}

async fn resolve_batch(
    resolver: &TokioAsyncResolver,
    candidates: Vec<String>,
    concurrency: usize,
    wildcard_ips: &BTreeSet<IpAddr>,
) -> Vec<String> {
    let found: Vec<(String, Vec<IpAddr>)> = stream::iter(candidates)
        .map(|host| {
            let resolver = resolver.clone();
            async move { resolve_one(resolver, host).await }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|result| async move { result })
        .collect()
        .await;

    found
        .into_iter()
        .filter(|(_, addresses)| {
            if wildcard_ips.is_empty() {
                true
            } else {
                addresses.iter().any(|ip| !wildcard_ips.contains(ip))
            }
        })
        .map(|(host, _)| host)
        .collect()
}

async fn detect_wildcard(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> (bool, BTreeSet<IpAddr>) {
    let mut wildcard = false;
    let mut addresses: BTreeSet<IpAddr> = BTreeSet::new();

    for index in 0..4 {
        let host = format!("{}.{domain}", random_label(index));
        if let Some((_, resolved)) = resolve_one(resolver.clone(), host).await {
            wildcard = true;
            for ip in resolved {
                addresses.insert(ip);
            }
        }
    }

    (wildcard, addresses)
}

fn random_label(salt: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let mut seed = (nanos ^ ((salt as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15))) | 1;
    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(18);
    for _ in 0..18 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let index = (seed % charset.len() as u128) as usize;
        out.push(charset[index] as char);
    }
    out
}

fn permutations(domain: &str, resolved: &[String], passive: &BTreeSet<String>) -> Vec<String> {
    let mutators = [
        "dev", "stg", "staging", "prod", "production", "test", "qa", "uat", "api", "admin",
        "internal", "corp", "new", "old", "beta", "alpha", "demo", "app", "apps", "portal",
        "secure", "vpn", "cdn", "static", "assets", "media", "mail", "ns", "gw", "backup",
        "db", "data", "edge", "node", "proxy", "s1", "s2", "v1", "v2", "v3",
    ];
    let suffix = format!(".{domain}");

    let mut labels: BTreeSet<String> = BTreeSet::new();
    let mut harvest_labels = |name: &str| {
        if let Some(stripped) = name.strip_suffix(&suffix) {
            if let Some(first) = stripped.split('.').next() {
                if !first.is_empty() && first.len() <= 40 {
                    labels.insert(first.to_string());
                }
            }
        }
    };
    for name in resolved {
        harvest_labels(name);
    }
    for name in passive {
        harvest_labels(name);
    }

    let mut out: BTreeSet<String> = BTreeSet::new();
    for label in &labels {
        for mutator in mutators {
            if label == mutator {
                continue;
            }
            out.insert(format!("{mutator}-{label}.{domain}"));
            out.insert(format!("{label}-{mutator}.{domain}"));
            out.insert(format!("{mutator}.{label}.{domain}"));
            out.insert(format!("{label}.{mutator}.{domain}"));
        }
        for number in 1..=4 {
            out.insert(format!("{label}{number}.{domain}"));
            out.insert(format!("{label}-{number}.{domain}"));
        }
        if out.len() >= 12000 {
            break;
        }
    }

    out.into_iter().collect()
}

async fn passive_collect(client: &Client, domain: &str) -> BTreeSet<String> {
    let urls = passive_sources(domain);
    let harvested: Vec<BTreeSet<String>> = stream::iter(urls)
        .map(|url| {
            let client = client.clone();
            let domain = domain.to_string();
            async move { fetch_harvest(&client, &url, &domain).await }
        })
        .buffer_unordered(8)
        .collect()
        .await;

    let mut all: BTreeSet<String> = BTreeSet::new();
    for set in harvested {
        for host in set {
            all.insert(host);
        }
    }
    all
}

fn passive_sources(domain: &str) -> Vec<String> {
    vec![
        format!("https://crt.sh/?q=%25.{domain}&output=json"),
        format!("https://api.hackertarget.com/hostsearch/?q={domain}"),
        format!("https://rapiddns.io/subdomain/{domain}?full=1"),
        format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
        format!("https://jldc.me/anubis/subdomains/{domain}"),
        format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=40000"
        ),
        format!(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ),
        format!("https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"),
        format!("https://dns.bufferover.run/dns?q=.{domain}"),
        format!("https://www.google.com/search?q=site:{domain}"),
    ]
}

async fn fetch_harvest(client: &Client, url: &str, domain: &str) -> BTreeSet<String> {
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => harvest(&body, domain),
            Err(_) => BTreeSet::new(),
        },
        Err(_) => BTreeSet::new(),
    }
}

fn harvest(text: &str, domain: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let suffix = format!(".{domain}");

    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let host = token.trim_matches('.').to_lowercase();
        if host.len() <= suffix.len() {
            continue;
        }
        if host.ends_with(&suffix) && is_hostname(&host) {
            out.insert(host);
        }
    }

    out
}

fn is_hostname(host: &str) -> bool {
    if host.len() > 253 || host.contains("..") {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    host.chars().any(|c| c.is_ascii_alphabetic())
}

fn wordlist() -> Vec<&'static str> {
    include_str!("../words.txt")
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}
