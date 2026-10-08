//! Shared configuration, AST import resolution, and diagnostics for KIB rules.

use super::scope::{build_line_starts, offset_to_line_col};
use super::{has_noqa, FileContext};
use crate::module_probe::{ModuleCheck, ModuleProbe};
use crate::types::{Level, Violation};
use ruff_python_ast::visitor::{walk_stmt, Visitor};
use ruff_python_ast::Stmt;
use ruff_text_size::{Ranged, TextRange};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) struct BoundaryChecker {
    probe: Arc<ModuleProbe>,
    config_dir: Option<PathBuf>,
}

impl BoundaryChecker {
    pub fn new(probe: Arc<ModuleProbe>, config_dir: Option<PathBuf>) -> Self {
        Self { probe, config_dir }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Boundary {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct Settings {
    pub source_roots: Vec<String>,
    pub forbidden: Vec<Boundary>,
    pub independent: Vec<String>,
    pub shared_package_names: Vec<String>,
    allowed: Vec<Boundary>,
    level: Level,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            source_roots: vec!["src".into(), ".".into()],
            forbidden: vec![],
            independent: vec![],
            shared_package_names: vec![],
            allowed: vec![],
            level: Level::Warning,
        }
    }
}

fn valid_module(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            !part.is_empty()
                && part.chars().enumerate().all(|(i, c)| {
                    c == '_'
                        || if i == 0 {
                            c.is_alphabetic()
                        } else {
                            c.is_alphanumeric()
                        }
                })
        })
}

pub(super) fn under(module: &str, root: &str) -> bool {
    module == root
        || module
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn module_for_path(path: &Path, project: &Path, roots: &[String]) -> Option<(String, bool)> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        project.join(path)
    };
    // Most specific roots take precedence; this also supports namespace packages.
    let mut roots: Vec<_> = roots.iter().map(|root| project.join(root)).collect();
    roots.sort_by_key(|root| std::cmp::Reverse(root.components().count()));
    for root in roots {
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        if !matches!(
            relative.extension().and_then(|s| s.to_str()),
            Some("py" | "pyi")
        ) {
            continue;
        }
        let mut parts: Vec<String> = relative
            .with_extension("")
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        let package = parts.last().is_some_and(|part| part == "__init__");
        if package {
            parts.pop();
        }
        let name = parts.join(".");
        if valid_module(&name) {
            return Some((name, package));
        }
    }
    None
}

fn from_module(importer: &str, package: bool, level: u32, module: Option<&str>) -> Option<String> {
    if level == 0 {
        return module.map(str::to_owned);
    }
    let mut parts: Vec<&str> = importer.split('.').collect();
    if !package {
        parts.pop();
    }
    let remove = level as usize - 1;
    if remove >= parts.len() {
        return None;
    }
    parts.truncate(parts.len() - remove);
    if let Some(module) = module {
        parts.extend(module.split('.'));
    }
    Some(parts.join("."))
}

struct Imports<'a> {
    importer: &'a str,
    package: bool,
    probe: &'a ModuleProbe,
    targets: Vec<(String, TextRange)>,
}

impl<'ast> Visitor<'ast> for Imports<'_> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        match stmt {
            Stmt::Import(node) => {
                for alias in &node.names {
                    self.targets.push((alias.name.to_string(), alias.range()));
                }
            }
            Stmt::ImportFrom(node) => {
                if let Some(base) = from_module(
                    self.importer,
                    self.package,
                    node.level,
                    node.module.as_deref(),
                ) {
                    for alias in &node.names {
                        if alias.name.as_str() != "*"
                            && self.probe.check(&base, alias.name.as_str()) == ModuleCheck::Module
                        {
                            self.targets
                                .push((format!("{base}.{}", alias.name), alias.range()));
                        } else {
                            // Object imports depend on their defining module, not a
                            // hypothetical child package with the object's name.
                            self.targets.push((base.clone(), node.range()));
                        }
                    }
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }
}

pub(super) fn sibling(module: &str, root: &str) -> Option<String> {
    let rest = module.strip_prefix(root)?.strip_prefix('.')?;
    Some(rest.split('.').next()?.to_owned())
}

impl BoundaryChecker {
    pub fn check(
        &self,
        ctx: &FileContext,
        cfg: &toml::Value,
        code: &str,
        is_forbidden: fn(&Settings, &Path, &str, &str) -> bool,
    ) -> Vec<Violation> {
        let config_error = |message: String| {
            eprintln!("konform: invalid import-boundaries configuration: {message}");
            vec![Violation {
                rule: code.into(),
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 0,
                message: format!("{code}: invalid import-boundaries configuration: {message}"),
                help: Some(
                    "Correct the import-boundaries configuration before trusting this check."
                        .into(),
                ),
                level: Level::Error,
                fixable: false,
            }]
        };
        let settings = match Settings::deserialize(cfg.clone()) {
            Ok(settings) => settings,
            Err(error) => {
                return config_error(error.to_string());
            }
        };
        let boundaries = settings.forbidden.iter().chain(&settings.allowed);
        if settings.source_roots.is_empty()
            || settings.source_roots.iter().any(|root| root.is_empty())
            || boundaries
                .clone()
                .any(|b| !valid_module(&b.from) || !valid_module(&b.to))
            || settings.independent.iter().any(|root| !valid_module(root))
            || settings
                .shared_package_names
                .iter()
                .any(|name| !valid_module(name) || name.contains('.'))
        {
            return config_error(
                "nonempty source roots, dotted module names, and single-component shared package names are required".into(),
            );
        }
        let project = match self
            .config_dir
            .clone()
            .or_else(|| std::env::current_dir().ok())
        {
            Some(project) => project,
            None => {
                return config_error("cannot determine the project root".into());
            }
        };
        let Some((importer, package)) =
            module_for_path(&ctx.path, &project, &settings.source_roots)
        else {
            return vec![];
        };
        let mut imports = Imports {
            importer: &importer,
            package,
            probe: &self.probe,
            targets: vec![],
        };
        for stmt in ctx.stmts() {
            imports.visit_stmt(stmt);
        }
        let starts = build_line_starts(&ctx.source);
        let noqa = ctx.noqa_lines();
        let mut seen = std::collections::HashSet::new();
        imports.targets.into_iter().filter_map(|(target, range)| {
            if settings.allowed.iter().any(|b| under(&importer, &b.from) && under(&target, &b.to)) {
                return None;
            }
            if !is_forbidden(&settings, &project, &importer, &target) { return None; }
            let (line, col) = offset_to_line_col(&starts, range.start().to_u32());
            let (end_line, end_col) = offset_to_line_col(&starts, range.end().to_u32());
            if !ctx.ignore_noqa
                && (line..=end_line).any(|line| {
                    noqa
                        .get(line - 1)
                        .is_some_and(|comment| has_noqa(comment, code, &ctx.noqa_aliases))
                })
            {
                return None;
            }
            if !seen.insert((line, target.clone())) { return None; }
            Some(Violation {
                rule: code.into(), line, col, end_line, end_col,
                message: format!("{code}: '{importer}' must not import '{target}'"),
                help: Some("Move reusable logic to a neutral module, or configure a reviewed allowed boundary.".into()),
                level: settings.level, fixable: false,
            })
        }).collect()
    }

    pub fn fingerprint(&self) -> u64 {
        self.probe.env_fingerprint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    #[test]
    fn module_names_and_prefixes_respect_components() {
        for name in ["acme", "acme.product_2", "_private.module"] {
            assert!(valid_module(name), "{name}");
        }
        for name in [
            "",
            ".acme",
            "acme.",
            "acme..tests",
            "2acme",
            "acme.bad-name",
        ] {
            assert!(!valid_module(name), "{name}");
        }
        assert!(under("acme.tests", "acme.tests"));
        assert!(under("acme.tests.audio.helpers", "acme.tests"));
        assert!(!under("acme.tests_extra.audio", "acme.tests"));
        assert!(!under("other.acme.tests", "acme.tests"));
        assert_eq!(
            sibling("acme.tests.audio.helpers", "acme.tests"),
            Some("audio".into())
        );
        assert_eq!(sibling("acme.tests", "acme.tests"), None);
        assert_eq!(sibling("acme.tests_extra.audio", "acme.tests"), None);
    }

    #[test]
    fn source_roots_resolve_modules_initializers_and_stubs() {
        let dir = tempfile::tempdir().unwrap();
        let roots = vec![".".into(), "src".into(), "src/vendor".into()];
        for (path, name, package) in [
            ("src/acme/controller.py", "acme.controller", false),
            ("src/acme/__init__.py", "acme", true),
            ("src/acme/api.pyi", "acme.api", false),
            ("src/acme/__init__.pyi", "acme", true),
            ("src/vendor/company/api.py", "company.api", false),
            ("flat.py", "flat", false),
        ] {
            let expected = Some((name.into(), package));
            assert_eq!(
                module_for_path(Path::new(path), dir.path(), &roots),
                expected
            );
            assert_eq!(
                module_for_path(&dir.path().join(path), dir.path(), &roots),
                expected
            );
        }
        for path in [
            "src/acme/readme.md",
            "src/bad-name/api.py",
            "src/__init__.py",
        ] {
            assert_eq!(
                module_for_path(Path::new(path), dir.path(), &["src".into()]),
                None,
                "{path}"
            );
        }
        assert_eq!(
            module_for_path(Path::new("elsewhere/api.py"), dir.path(), &["src".into()]),
            None
        );
    }

    #[test]
    fn relative_imports_resolve_from_module_or_package() {
        for (importer, package, level, module, expected) in [
            (
                "acme.tests.audio.controller",
                false,
                0,
                Some("os.path"),
                Some("os.path"),
            ),
            (
                "acme.tests.audio.controller",
                false,
                1,
                None,
                Some("acme.tests.audio"),
            ),
            (
                "acme.tests.audio",
                true,
                1,
                Some("helpers"),
                Some("acme.tests.audio.helpers"),
            ),
            (
                "acme.tests.audio.controller",
                false,
                2,
                Some("radio"),
                Some("acme.tests.radio"),
            ),
            (
                "acme.tests.audio.controller",
                false,
                3,
                Some("shared"),
                Some("acme.shared"),
            ),
            ("acme.tests.audio.controller", false, 4, None, None),
            ("controller", false, 1, Some("helpers"), None),
        ] {
            assert_eq!(
                from_module(importer, package, level, module).as_deref(),
                expected,
                "{importer}, package={package}, level={level}, module={module:?}"
            );
        }
    }

    #[test]
    fn invalid_settings_report_actionable_error_diagnostics() {
        let (dir, probe) = fixture();
        let checker = BoundaryChecker::new(probe, Some(dir.path().to_path_buf()));
        let ctx =
            FileContext::from_source(dir.path().join("code/acme/lib/controller.py"), "".into());
        for config in [
            "source-roots=[]",
            "source-roots=['']",
            "forbidden=[{from='acme.lib',to='bad-name'}]",
            "allowed=[{from='',to='acme.tests'}]",
            "independent=['acme..tests']",
            "shared-package-names=['acme.shared']",
            "shared-package-names=['']",
            "unknown-setting=true",
            "independent=42",
        ] {
            let cfg = toml::from_str::<toml::Value>(config).unwrap();
            let violations = checker.check(&ctx, &cfg, "KIB002", |_, _, _, _| false);
            assert_eq!(violations.len(), 1, "{config}");
            let violation = &violations[0];
            assert_eq!(violation.rule, "KIB002");
            assert_eq!(violation.level, Level::Error);
            assert_eq!((violation.line, violation.col), (1, 0));
            assert!(violation
                .message
                .contains("invalid import-boundaries configuration"));
            assert!(violation.help.as_deref().unwrap().contains("Correct"));
            assert!(!violation.fixable);
        }
    }

    #[test]
    fn imported_objects_are_deduplicated_but_child_modules_are_distinct() {
        let (dir, probe) = fixture();
        let checker = BoundaryChecker::new(probe, Some(dir.path().to_path_buf()));
        let cfg = toml::from_str::<toml::Value>("source-roots=['code']").unwrap();
        for (source, targets) in [
            (
                "from acme.product_tests.audio.helpers import first, second",
                vec!["acme.product_tests.audio.helpers"],
            ),
            (
                "from acme.product_tests import audio, radio",
                vec!["acme.product_tests.audio", "acme.product_tests.radio"],
            ),
            (
                "from acme.product_tests.audio import *",
                vec!["acme.product_tests.audio"],
            ),
        ] {
            let ctx = FileContext::from_source(
                dir.path().join("code/acme/lib/controller.py"),
                source.into(),
            );
            let violations = checker.check(&ctx, &cfg, "KIB001", |_, _, _, _| true);
            assert_eq!(violations.len(), targets.len(), "{source}");
            for (violation, target) in violations.iter().zip(targets) {
                assert!(
                    violation.message.ends_with(&format!("'{target}'")),
                    "{violation:?}"
                );
            }
        }
    }

    #[test]
    fn diagnostic_ranges_and_levels_match_the_import() {
        let (dir, probe) = fixture();
        let checker = BoundaryChecker::new(probe, Some(dir.path().to_path_buf()));
        let cfg = toml::from_str::<toml::Value>("source-roots=['code']").unwrap();
        let source = "# heading\nimport acme.product_tests.audio as audio\n";
        let ctx = FileContext::from_source(
            dir.path().join("code/acme/lib/controller.py"),
            source.into(),
        );
        let violations = checker.check(&ctx, &cfg, "KIB001", |_, _, _, _| true);
        assert_eq!(violations.len(), 1);
        let violation = &violations[0];
        assert_eq!((violation.line, violation.col), (2, 7));
        assert_eq!((violation.end_line, violation.end_col), (2, 40));
        assert_eq!(violation.level, Level::Warning);
        assert_eq!(
            violation.message,
            "KIB001: 'acme.lib.controller' must not import 'acme.product_tests.audio'"
        );
    }

    fn fixture() -> (tempfile::TempDir, Arc<ModuleProbe>) {
        let dir = tempfile::tempdir().unwrap();
        for module in [
            "code/acme/product_tests/audio/helpers.py",
            "code/acme/product_tests/radio/helpers.py",
            "code/acme/shared/helpers.py",
        ] {
            let path = dir.path().join(module);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        let probe = Arc::new(ModuleProbe::new(
            Path::new("python3"),
            dir.path(),
            &["code".into()],
        ));
        (dir, probe)
    }

    fn check(
        dir: &Path,
        probe: Arc<ModuleProbe>,
        path: &str,
        source: &str,
        independent: bool,
    ) -> Vec<Violation> {
        let rule: Box<dyn Rule> = if independent {
            Box::new(super::super::kib002::Kib002Rule::new(
                probe,
                Some(dir.to_path_buf()),
            ))
        } else {
            Box::new(super::super::kib001::Kib001Rule::new(
                probe,
                Some(dir.to_path_buf()),
            ))
        };
        let ctx = FileContext::from_source(dir.join(path), source.into());
        let cfg = toml::from_str::<toml::Value>(
            "source-roots = ['code']\n\
             forbidden = [{from = 'acme.lib', to = 'acme.product_tests'}]\n\
             independent = ['acme.product_tests']\n",
        )
        .unwrap();
        rule.check(&ctx, &cfg)
    }

    #[test]
    fn forbidden_boundaries_handle_relative_aliases_comments_and_multiline() {
        let (dir, probe) = fixture();
        for source in [
            "import acme.product_tests.audio.helpers as helper",
            "from ..product_tests.audio import helpers",
            "from acme import (\n product_tests, # comment\n)",
            "def run():\n from ..product_tests.audio import helpers",
            "try:\n import acme.product_tests.audio.helpers\nexcept ImportError:\n pass",
        ] {
            assert!(
                !check(
                    dir.path(),
                    Arc::clone(&probe),
                    "code/acme/lib/controller.py",
                    source,
                    false
                )
                .is_empty(),
                "{source}"
            );
        }
        for source in [
            "from acme.shared import helpers",
            "from acme import product_tests_helpers",
            "\"\"\"\nimport acme.product_tests.audio\n\"\"\"",
            "# import acme.product_tests.audio",
        ] {
            assert!(
                check(
                    dir.path(),
                    Arc::clone(&probe),
                    "code/acme/lib/controller.py",
                    source,
                    false
                )
                .is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn sibling_boundaries_are_generic_and_allow_local_and_shared_imports() {
        let (dir, probe) = fixture();
        for source in [
            "from ..audio import helpers",
            "from acme.product_tests import audio",
            "from acme.product_tests.audio.helpers import function",
        ] {
            assert!(
                !check(
                    dir.path(),
                    Arc::clone(&probe),
                    "code/acme/product_tests/radio/controller.py",
                    source,
                    true
                )
                .is_empty(),
                "{source}"
            );
        }
        for source in ["from . import helpers", "from acme.shared import helpers"] {
            assert!(check(
                dir.path(),
                Arc::clone(&probe),
                "code/acme/product_tests/radio/controller.py",
                source,
                true
            )
            .is_empty());
        }
    }

    #[test]
    fn package_initializers_namespace_packages_and_noqa() {
        let (dir, probe) = fixture();
        assert!(!check(
            dir.path(),
            Arc::clone(&probe),
            "code/acme/lib/__init__.py",
            "from ..product_tests.audio import helpers",
            false
        )
        .is_empty());
        assert!(check(
            dir.path(),
            Arc::clone(&probe),
            "code/acme/lib/controller.py",
            "from acme.product_tests.audio import helpers # noqa: KIB001",
            false
        )
        .is_empty());
        assert!(check(
            dir.path(),
            Arc::clone(&probe),
            "code/acme/lib/controller.py",
            "from acme import (\n product_tests, # noqa: KIB001\n)",
            false
        )
        .is_empty());
        assert!(check(
            dir.path(),
            probe,
            "other/controller.py",
            "import acme.product_tests.audio",
            false
        )
        .is_empty());
    }

    #[test]
    fn explicit_exceptions_and_prefix_boundaries() {
        let (dir, probe) = fixture();
        let rule = super::super::kib001::Kib001Rule::new(probe, Some(dir.path().to_path_buf()));
        let ctx = FileContext::from_source(
            dir.path().join("code/acme/lib/controller.py"),
            "import acme.product_tests.audio\nimport acme.product_tests_extra\n".into(),
        );
        let cfg = toml::from_str::<toml::Value>(
            "source-roots=['code']\n\
             forbidden=[{from='acme.lib',to='acme.product_tests'}]\n\
             allowed=[{from='acme.lib.controller',to='acme.product_tests.audio'}]",
        )
        .unwrap();
        assert!(rule.check(&ctx, &cfg).is_empty());
        let ctx = FileContext::from_source(
            dir.path().join("code/acme/lib/controller.py"),
            "from acme.product_tests import audio\n".into(),
        );
        assert!(rule.check(&ctx, &cfg).is_empty());
    }

    #[test]
    fn invalid_config_is_an_error_not_a_clean_check() {
        let (dir, probe) = fixture();
        let rule = super::super::kib001::Kib001Rule::new(probe, Some(dir.path().to_path_buf()));
        let ctx =
            FileContext::from_source(dir.path().join("code/acme/lib/controller.py"), "".into());
        let cfg = toml::from_str::<toml::Value>("forbidden=[{from='',to='acme.tests'}]").unwrap();
        let violations = rule.check(&ctx, &cfg);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].level, Level::Error);
        assert!(violations[0].message.contains("invalid"));
    }
}
