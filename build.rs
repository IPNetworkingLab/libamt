fn main() {
    println!("cargo:rerun-if-changed=amt.c");
    println!("cargo:rerun-if-changed=amt.h");

    cc::Build::new()
        .file("amt.c")
        .warnings(true)
        .extra_warnings(true)
        .compile("amt");
}
