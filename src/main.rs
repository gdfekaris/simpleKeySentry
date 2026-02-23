fn main() {
    let exit_code = simple_key_sentry::cli::run();
    std::process::exit(exit_code);
}
