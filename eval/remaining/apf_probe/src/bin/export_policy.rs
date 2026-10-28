use apf_compiler::{frontend, CanonicalPolicy, Projector};
use apf_openshell_projector::OpenShellProjector;
use apf_proto::openshell_sandbox::SandboxPolicy;
use prost::Message;
use serde_json::json;

fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("input policy")).unwrap();
    let mut policy = CanonicalPolicy::default();
    policy.sandbox_policies.insert("default".into(), frontend::parse(&bytes).unwrap());
    let surfaces = OpenShellProjector.project(&policy).unwrap();
    let surface = surfaces.iter().find(|s| s.kind == "openshell.sandbox.v1").unwrap();
    let projected = SandboxPolicy::decode(surface.bytes.as_slice()).unwrap();
    // This exporter is explicitly limited to the file-only comparator policy.
    assert!(projected.network_policies.is_empty());
    assert!(projected.network_middlewares.is_empty());
    let fs = projected.filesystem.unwrap();
    let landlock = projected.landlock.unwrap();
    let process = projected.process.unwrap();
    println!("{}", json!({"version":projected.version,
        "filesystem_policy":{"include_workdir":fs.include_workdir,"read_only":fs.read_only,"read_write":fs.read_write},
        "landlock":{"compatibility":landlock.compatibility},
        "process":{"run_as_user":process.run_as_user,"run_as_group":process.run_as_group},
        "network_policies":{}}));
}
