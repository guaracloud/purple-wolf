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
        // Cross-compile libinjection to wasm32 via wasi-sdk. We pass
        // `--target=wasm32-wasip1` to match Rust's target triple
        // (NEW-M12 in the followup review). The older wasi-sdk releases
        // only know `wasm32-wasi`; wasi-sdk 22+ accepts both. The
        // vendored libinjection sources don't touch clocks or threading,
        // so we also no longer pass `-D_WASI_EMULATED_PROCESS_CLOCKS` /
        // `-lwasi-emulated-process-clocks` (NEW-M13) — they were dead
        // flags and pulling the emulator in inflates the final wasm.
        let sdk = std::env::var("WASI_SDK_PATH").unwrap_or_else(|_| "/opt/wasi-sdk".into());
        let clang = format!("{sdk}/bin/clang");
        let archiver = format!("{sdk}/bin/llvm-ar");
        let sysroot = format!("{sdk}/share/wasi-sysroot");
        build
            .compiler(&clang)
            .archiver(&archiver)
            .flag(format!("--sysroot={sysroot}"))
            .flag("--target=wasm32-wasip1")
            .flag("-fno-exceptions");
    }

    build.compile("injection");
}
