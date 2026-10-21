// This crate embeds the workspace migration set via `sqlx::migrate!`, which
// only registers the migration files that exist at compile time. Without a
// directory-level dependency, adding a new migration leaves this crate's
// previously built artifacts with a stale embedded set, and every runtime
// migration then fails with VersionMissing once any rebuilt crate has applied
// the new version.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
    println!("cargo:rerun-if-changed=static");
    let root = std::path::Path::new("static");
    let mut paths = Vec::new();
    collect_assets(root, root, &mut paths);
    paths.sort();
    let output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo output directory"));
    std::fs::write(output.join("dashboard-assets.rs"), format!("&{paths:?}"))
        .expect("write dashboard asset inventory");
}

fn collect_assets(root: &std::path::Path, directory: &std::path::Path, paths: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).expect("read dashboard assets") {
        let entry = entry.expect("read asset entry");
        let kind = entry.file_type().expect("read asset type");
        if kind.is_dir() {
            collect_assets(root, &entry.path(), paths);
        } else if kind.is_file() {
            paths.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("asset in root")
                    .to_str()
                    .expect("UTF-8 asset path")
                    .replace('\\', "/"),
            );
        }
    }
}
