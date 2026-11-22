fn main() {
    std::process::exit(fail2ban_rs::server::run_cli(
        std::env::args().skip(1).collect(),
    ));
}
