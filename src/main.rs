fn main() {
    println!(
        "Simple Key Sentry v{} — run `sks scan` to get started",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(0);
}
