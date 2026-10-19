mod parser;
mod scanner;

use parser::{parse_input, ParseOutcome, TargetKind};
use scanner::{build_client, Category, ScanResult};
use std::io::{self, Write};
use std::path::Path;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[38;5;196m";
const RED_DK: &str = "\x1b[38;5;124m";
const WHITE: &str = "\x1b[97m";
const GRAY: &str = "\x1b[38;5;245m";

const BANNER: &str = include_str!("exp.txt");

#[tokio::main]
async fn main() {
    enable_ansi();
    let client = build_client();

    loop {
        let width = term_width();
        clear_screen();
        render_banner(width);
        render_menu(width);

        let choice = prompt(&format!("{RED}{BOLD}CheckSu{RESET}{WHITE} ❯ {RESET}"));
        match choice.trim() {
            "1" => scan_list_flow(&client, width).await,
            "2" => single_flow(&client, width).await,
            "3" => subdomain_flow(&client, width).await,
            "q" | "Q" | "quit" | "exit" => {
                println!("\n{RED}  Session terminated.{RESET} {GRAY}Stay sharp.{RESET}\n");
                break;
            }
            "" => {}
            other => {
                println!("\n{RED}  Unknown option: {WHITE}{other}{RESET}");
                pause();
            }
        }
    }
}

async fn scan_list_flow(client: &reqwest::Client, width: usize) {
    section("SCAN LIST", width);
    println!(
        "{GRAY}  Enter targets (comma / space / newline separated) or a file path.{RESET}"
    );
    let raw = prompt(&format!("{RED}  targets{RESET}{WHITE} ❯ {RESET}"));
    let content = load_input(&raw);
    let outcome = parse_input(&content);

    if !report_parse(&outcome) {
        pause();
        return;
    }

    println!(
        "\n{WHITE}  Scanning {RED}{BOLD}{}{RESET}{WHITE} target(s)...{RESET}",
        outcome.valid.len()
    );
    let mut results = scanner::scan_targets(client, &outcome.valid, 60).await;
    render_results(&mut results, width);
    pause();
}

async fn single_flow(client: &reqwest::Client, width: usize) {
    section("SINGLE DOMAIN SCAN", width);
    let raw = prompt(&format!("{RED}  target{RESET}{WHITE} ❯ {RESET}"));
    let outcome = parse_input(&raw);

    if !report_parse(&outcome) {
        pause();
        return;
    }

    let mut results = scanner::scan_targets(client, &outcome.valid, 10).await;
    render_results(&mut results, width);
    pause();
}

async fn subdomain_flow(client: &reqwest::Client, width: usize) {
    section("SUBDOMAIN FINDER", width);
    let raw = prompt(&format!("{RED}  domain{RESET}{WHITE} ❯ {RESET}"));
    let outcome = parse_input(&raw);

    let target = match outcome.valid.into_iter().next() {
        Some(t) => t,
        None => {
            println!("\n{RED}  No valid domain supplied.{RESET}");
            pause();
            return;
        }
    };

    if target.kind != TargetKind::Domain {
        println!("\n{RED}  Subdomain discovery requires a domain, not an IP address.{RESET}");
        pause();
        return;
    }

    println!(
        "\n{WHITE}  Target domain:{RESET} {RED}{BOLD}{}{RESET}",
        target.host
    );
    println!(
        "{GRAY}  [*] Harvesting passive intelligence (crt.sh, OTX, Anubis, Wayback, RapidDNS, HackerTarget, CertSpotter, URLScan)...{RESET}"
    );
    println!(
        "{GRAY}  [*] Brute forcing {RED}{}{GRAY} SecLists entries over a multi-resolver DNS engine...{RESET}",
        scanner::wordlist_size()
    );
    println!("{GRAY}  [*] Generating intelligent permutations and filtering wildcards...{RESET}");
    let _ = io::stdout().flush();

    let report = scanner::discover_subdomains(&target.host).await;

    println!();
    println!(
        "  {WHITE}{BOLD}Discovery{RESET}   {WHITE}passive {RED}{BOLD}{}{RESET}   {WHITE}brute {RED}{BOLD}{}{RESET}   {WHITE}permutations {RED}{BOLD}{}{RESET}   {WHITE}wildcard {}{RESET}",
        report.passive_count,
        report.brute_count,
        report.permutation_count,
        if report.wildcard {
            format!("{RED}{BOLD}detected")
        } else {
            format!("{GRAY}none")
        }
    );

    if report.resolved.is_empty() {
        println!("\n{RED}  No live subdomains resolved.{RESET}");
        pause();
        return;
    }

    println!(
        "  {WHITE}{BOLD}Resolved{RESET}    {WHITE}{RED}{BOLD}{}{RESET}{WHITE} unique live subdomain(s). Probing HTTP/HTTPS...{RESET}",
        report.resolved.len()
    );

    let mut hosts = vec![target.host.clone()];
    hosts.extend(report.resolved);
    let mut results = scanner::scan_hosts(client, &hosts, 100).await;
    render_results(&mut results, width);
    pause();
}

fn load_input(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && Path::new(trimmed).is_file() {
        if let Ok(content) = std::fs::read_to_string(trimmed) {
            println!("{GRAY}  Loaded list from {WHITE}{trimmed}{RESET}");
            return content;
        }
    }
    raw.to_string()
}

fn report_parse(outcome: &ParseOutcome) -> bool {
    if !outcome.invalid.is_empty() {
        println!("\n{RED}  Rejected {} invalid entr(ies):{RESET}", outcome.invalid.len());
        for bad in &outcome.invalid {
            println!("    {RED_DK}✖ {WHITE}{bad}{RESET}");
        }
    }
    if outcome.valid.is_empty() {
        println!("\n{RED}  No valid targets to scan.{RESET}");
        return false;
    }
    true
}

fn render_banner(width: usize) {
    let lines: Vec<&str> = BANNER.lines().filter(|l| !l.is_empty()).collect();
    let banner_width = lines.iter().map(|l| display_len(l)).max().unwrap_or(0);

    println!();
    if banner_width + 2 <= width {
        for line in &lines {
            let pad = (width.saturating_sub(display_len(line))) / 2;
            println!("{}{RED}{BOLD}{line}{RESET}", " ".repeat(pad));
        }
    } else {
        let compact = "Exp1o5iveM1nd";
        let pad = (width.saturating_sub(compact.len())) / 2;
        println!("{}{RED}{BOLD}{compact}{RESET}", " ".repeat(pad));
    }

    let rule_len = banner_width.min(width.saturating_sub(2)).max(10);
    let pad = (width.saturating_sub(rule_len)) / 2;
    println!("{}{WHITE}{}{RESET}", " ".repeat(pad), "─".repeat(rule_len));

    let tagline = "By t.me/goviraq";
    let tpad = (width.saturating_sub(tagline.len())) / 2;
    println!(
        "{}{WHITE}By {RED}{BOLD}t.me/goviraq{RESET}",
        " ".repeat(tpad)
    );
    println!();
}

fn render_menu(width: usize) {
    center_line("SELECT AN OPERATION", width);
    println!();
    let options = [
        ("1", "Scan List", "Scan a list containing any number of domains / IPs"),
        ("2", "Single Domain Scan", "Scan an individual domain or address"),
        ("3", "Subdomain Finder", "Comprehensive subdomain discovery"),
    ];
    for (key, title, desc) in options {
        println!(
            "   {RED}{BOLD}[{key}]{RESET}  {WHITE}{BOLD}{title:<20}{RESET}{GRAY}{desc}{RESET}"
        );
    }
    println!("   {RED}{BOLD}[q]{RESET}  {WHITE}{BOLD}{:<20}{RESET}{GRAY}Exit CheckSu{RESET}", "Quit");
    println!();
}

fn render_results(results: &mut [ScanResult], width: usize) {
    if results.is_empty() {
        println!("\n{RED}  No results.{RESET}");
        return;
    }

    results.sort_by(|a, b| rank(a.category).cmp(&rank(b.category)).then(a.host.cmp(&b.host)));

    let host_w = results
        .iter()
        .map(|r| r.host.len())
        .max()
        .unwrap_or(16)
        .clamp(16, 44);

    println!();
    println!(
        "  {WHITE}{BOLD}  {:<6}{:<12}{:<host_w$} DETAIL{RESET}",
        "CODE", "STATUS", "HOST"
    );
    println!("  {GRAY}{}{RESET}", "─".repeat(width.saturating_sub(4).min(100)));

    for result in results.iter() {
        let (symbol, label, color) = badge(result.category);
        let code = result
            .status
            .map(|c| c.to_string())
            .unwrap_or_else(|| "—".to_string());
        let scheme = if result.url.starts_with("https") {
            "https"
        } else {
            "http "
        };
        let meta = format!("{scheme}  {:>5}ms  ", result.elapsed_ms);
        let detail = truncate(&result.detail, width.saturating_sub(host_w + 34));
        let host = truncate(&result.host, host_w);
        println!(
            "  {color}{symbol} {RESET}{color}{code:<6}{RESET}{color}{label:<12}{RESET}{WHITE}{host:<host_w$}{RESET} {GRAY}{meta}{detail}{RESET}"
        );
    }

    render_summary(results, width);
}

fn render_summary(results: &[ScanResult], width: usize) {
    let mut success = 0;
    let mut redirect = 0;
    let mut restricted = 0;
    let mut missing = 0;
    let mut errored = 0;
    let mut failed = 0;
    let mut other = 0;

    for result in results {
        match result.category {
            Category::Success => success += 1,
            Category::Redirect => redirect += 1,
            Category::Restricted => restricted += 1,
            Category::Missing => missing += 1,
            Category::ServerError => errored += 1,
            Category::Failed => failed += 1,
            Category::Other => other += 1,
        }
    }

    println!("  {GRAY}{}{RESET}", "─".repeat(width.saturating_sub(4).min(100)));
    println!(
        "  {WHITE}{BOLD}Summary{RESET}  {WHITE}total {RED}{BOLD}{}{RESET}   {WHITE}live {RED}{BOLD}{}{RESET}   {WHITE}redirect {}{}{RESET}   {WHITE}restricted {}{}{RESET}   {WHITE}missing {}{}{RESET}   {WHITE}error {}{}{RESET}   {WHITE}other {}{}{RESET}   {WHITE}failed {RED}{}{RESET}",
        results.len(),
        success,
        WHITE,
        redirect,
        RED,
        restricted,
        GRAY,
        missing,
        RED,
        errored,
        GRAY,
        other,
        failed
    );
    println!();
}

fn badge(category: Category) -> (&'static str, &'static str, &'static str) {
    match category {
        Category::Success => ("✔", "LIVE", WHITE),
        Category::Redirect => ("»", "REDIRECT", WHITE),
        Category::Restricted => ("⚠", "RESTRICTED", RED),
        Category::Missing => ("✖", "NOT FOUND", GRAY),
        Category::ServerError => ("✖", "SRV ERROR", RED),
        Category::Other => ("•", "OTHER", GRAY),
        Category::Failed => ("✖", "FAILED", RED_DK),
    }
}

fn rank(category: Category) -> u8 {
    match category {
        Category::Success => 0,
        Category::Redirect => 1,
        Category::Restricted => 2,
        Category::ServerError => 3,
        Category::Missing => 4,
        Category::Other => 5,
        Category::Failed => 6,
    }
}

fn section(title: &str, width: usize) {
    println!();
    center_line(title, width);
    println!(
        "  {GRAY}{}{RESET}",
        "─".repeat(width.saturating_sub(4).min(100))
    );
}

fn center_line(text: &str, width: usize) {
    let pad = (width.saturating_sub(text.len())) / 2;
    println!("{}{RED}{BOLD}{text}{RESET}", " ".repeat(pad));
}

fn truncate(text: &str, max: usize) -> String {
    let max = max.max(8);
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn display_len(line: &str) -> usize {
    line.chars().count()
}

fn prompt(message: &str) -> String {
    print!("\n{message}");
    let _ = io::stdout().flush();
    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(0) => "q".to_string(),
        Ok(_) => buffer.trim_end_matches(['\r', '\n']).to_string(),
        Err(_) => String::new(),
    }
}

fn pause() {
    print!("\n{GRAY}  Press Enter to return to the menu...{RESET}");
    let _ = io::stdout().flush();
    let mut buffer = String::new();
    let _ = io::stdin().read_line(&mut buffer);
}

fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

fn term_width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
        .max(40)
}

#[cfg(windows)]
fn enable_ansi() {
    extern "system" {
        fn GetStdHandle(handle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
fn enable_ansi() {}
