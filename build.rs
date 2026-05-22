fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
    cc::Build::new()
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .opt_level(2)
        .compile("injection");
}
