use std::fs;
use std::path::Path;

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let web_build = manifest.join("../../web/build");
    let assets = manifest.join("assets");
    println!("cargo:rerun-if-changed=../../web/build");
    let _ = fs::remove_dir_all(&assets);
    fs::create_dir_all(&assets).expect("create assets");
    if web_build.join("index.html").is_file() {
        copy_dir(&web_build, &assets);
    } else {
        fs::write(
            assets.join("index.html"),
            "<!doctype html><title>SBM</title><p>Dashboard assets are not built. Run npm run build in web/.</p>",
        )
        .expect("placeholder");
    }
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).expect("read web build") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file type");
        let target = to.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir_all(&target).expect("mkdir");
            copy_dir(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), target).expect("copy asset");
        }
    }
}
