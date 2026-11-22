fn main() {
    let code = fail2ban_rs::client::run_cli(std::env::args().skip(1).collect());
    std::process::exit(code);
}
