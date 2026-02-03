fn main() {
    let cfg = tun2::Configuration::default();
    // Try different methods
    let _ = cfg.tun_name("test");
}
