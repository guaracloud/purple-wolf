fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
    println!("cargo:rerun-if-env-changed=WASI_SDK_PATH");
    // Declare the custom cfg so rustc doesn't emit unexpected_cfgs warnings.
    // The cfg itself is no longer used post-Task 14 (libinjection is cross-built
    // to wasm32 via wasi-sdk), but keeping the declaration is benign.
    println!("cargo:rustc-check-cfg=cfg(purple_wolf_no_libinjection)");
    let target = std::env::var("TARGET").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .opt_level(2);

    if target.starts_with("wasm32-") {
        // Cross-compile libinjection to wasm32 via wasi-sdk.
        let sdk = std::env::var("WASI_SDK_PATH").unwrap_or_else(|_| "/opt/wasi-sdk".into());
        let clang = format!("{sdk}/bin/clang");
        let archiver = format!("{sdk}/bin/llvm-ar");
        let sysroot = format!("{sdk}/share/wasi-sysroot");
        build
            .compiler(&clang)
            .archiver(&archiver)
            .flag(&format!("--sysroot={sysroot}"))
            .flag("--target=wasm32-wasi")
            .flag("-fno-exceptions")
            .flag("-D_WASI_EMULATED_PROCESS_CLOCKS");
        println!("cargo:rustc-link-arg=-lwasi-emulated-process-clocks");
    }

    build.compile("injection");
}
