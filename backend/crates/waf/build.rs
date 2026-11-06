fn main() {
    println!("cargo:rerun-if-changed=src/native.cpp");
    println!("cargo:rerun-if-changed=src/native.h");
    let library = pkg_config::Config::new()
        .atleast_version("3.0.9")
        .cargo_metadata(false)
        .probe("modsecurity")
        .expect("libmodsecurity v3 development files required; see backend/Dockerfile");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .file("src/native.cpp")
        .warnings_into_errors(true);
    for path in library.include_paths {
        // Explicit /usr/include breaks GCC include_next ordering.
        if path != std::path::Path::new("/usr/include") {
            build.flag("-isystem").flag(path.to_string_lossy().as_ref());
        }
    }
    build.compile("openwaf_modsecurity_adapter");
    // Link dependencies after the static shim: GNU ld with --as-needed drops
    // libmodsecurity when it appears before the first reference to its symbols.
    pkg_config::Config::new()
        .atleast_version("3.0.9")
        .probe("modsecurity")
        .expect("libmodsecurity link metadata");
}
