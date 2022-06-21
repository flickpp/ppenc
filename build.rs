use std::env;

fn main() {
    let mut inline = "inline";
    let mut static_ = "static";

    for (k, v) in env::vars() {
        if k == "PROFILE" && v == "debug" {
            inline = "";
            static_ = "";
            break;
        }
    }

    cc::Build::new()
        .file("blockcipher.c")
        .file("hash.c")
        .file("cprng.c")
        .file("ppenc.c")
        .flag("--std=c99")
        .define("INLINE", inline)
        .define("STATIC", static_)
        .define("PPENC_64BIT", "")
        .compile("ppenc");
}
