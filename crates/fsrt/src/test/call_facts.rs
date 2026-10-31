use super::*;
use forge_analyzer::ir::{CallPathPart, Inst, Location, Rvalue};
use forge_permission_resolver::permissions_resolver::PermMap;

/// The recorded facts of every call in the project, as
/// `(path, root binding is imported from, call is an intrinsic)`.
fn call_facts(source: &str) -> Vec<(Vec<String>, Option<(String, String)>, bool)> {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    let permissions = HashSet::new();
    let mut perm_map = PermMap::new(&permissions, &crate::CacheConfig::default());
    let lowered = project
        .with_files_and_sourceroot(
            Path::new("src"),
            project.get_paths(),
            &[],
            &mut perm_map,
            &HashSet::new(),
        )
        .unwrap();
    let mut facts = Vec::new();
    for body in lowered.env.bodies() {
        for (block, data) in body.blocks.iter_enumerated() {
            for (index, inst) in data.insts.iter().enumerate() {
                let (Inst::Assign(_, rvalue) | Inst::Expr(rvalue)) = inst;
                if !matches!(rvalue, Rvalue::Call(..) | Rvalue::Intrinsic(..)) {
                    continue;
                }
                let Some(call) = body.call_facts(Location::new(block, index as u32)) else {
                    continue;
                };
                let path = call
                    .path
                    .iter()
                    .map(|part| match part {
                        CallPathPart::Binding(def) => lowered.env.def_name(*def).to_owned(),
                        CallPathPart::Property(name) | CallPathPart::MemberCall(name) => {
                            name.to_string()
                        }
                        CallPathPart::Unresolved((name, _)) => format!("?{name}"),
                        other => format!("{other:?}"),
                    })
                    .collect();
                let import = call
                    .import
                    .as_ref()
                    .map(|(module, kind)| (module.to_string(), format!("{kind:?}")));
                facts.push((path, import, matches!(rvalue, Rvalue::Intrinsic(..))));
            }
        }
    }
    facts
}

#[test]
fn call_facts_keep_the_callee_path_and_direct_import() {
    let facts = call_facts(
        "import api, { storage } from '@forge/api';
         export async function run() {
             await storage.get('key');
             await api.asApp().requestJira('/rest/api/3/myself');
             helper();
         }
         function helper() {}",
    );
    let storage = facts
        .iter()
        .find(|(path, ..)| path.last().is_some_and(|name| name == "get"))
        .unwrap();
    assert_eq!(storage.0, ["storage", "get"]);
    assert_eq!(
        storage.1,
        Some(("@forge/api".to_owned(), "Named(\"storage\")".to_owned()))
    );
    let helper = facts
        .iter()
        .find(|(path, ..)| path.first().is_some_and(|name| name == "helper"))
        .unwrap();
    assert_eq!(helper.0, ["helper"]);
    assert_eq!(helper.1, None);
    assert!(!helper.2);
}

#[test]
fn call_facts_are_recorded_for_every_call_form() {
    let facts = call_facts(
        "const config = { load() {} };
         export function run(items) {
             items.filter(Boolean);
             config.load();
             new Date();
             unknownGlobal(1);
         }",
    );
    let paths: Vec<_> = facts.iter().map(|(path, ..)| path.join(".")).collect();
    assert_eq!(
        paths,
        ["items.filter", "config.load", "Date", "unknownGlobal"],
        "{facts:?}"
    );
    assert!(
        facts
            .iter()
            .all(|(_, import, intrinsic)| import.is_none() && !intrinsic)
    );
}
