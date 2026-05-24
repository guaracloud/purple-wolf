fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
    // Declare the custom cfg so rustc doesn't emit unexpected_cfgs warnings.
    println!("cargo:rustc-check-cfg=cfg(purple_wolf_no_libinjection)");
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.starts_with("wasm32-") {
        // wasm32 cross-build added by Task 14.
        // For now, skip C compilation on wasm32 targets so the rest of the
        // workspace still builds; injection detector becomes a stub there
        // until Task 14 wires the wasi-sdk cross-build.
        println!("cargo:rustc-cfg=purple_wolf_no_libinjection");
        return;
    }

    cc::Build::new()
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .opt_level(2)
        .compile("injection");
}
