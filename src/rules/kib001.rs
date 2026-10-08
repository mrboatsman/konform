//! # KIB001 — Forbidden import boundaries
//!
//! Checks direct imports crossing configured importing/target module-prefix
//! boundaries. Use this optional policy to keep shared libraries independent of
//! feature or test-suite implementations. No contracts means no restrictions.
//!
//! ## Configuration
//!
//! ```toml
//! [tool.konform.lint]
//! select = ["KIB001"]
//!
//! [tool.konform.lint.import-boundaries]
//! source-roots = ["src"]
//! forbidden = [{ from = "example.lib", to = "example.product_tests" }]
//! allowed = [
//!   { from = "example.lib.integration", to = "example.product_tests.audio" },
//! ]
//! level = "warning"
//! ```
//!
//! `forbidden` and `allowed` default to empty lists. Contracts include descendants
//! and respect dotted components: `example.lib_extra` is not under `example.lib`.
//! `allowed` exempts reviewed prefix pairs for both KIB rules.
//! The default level is `"warning"`; use `"error"` to fail the default CLI threshold,
//! or run with `--level warning` to fail on warning-level findings.
//!
//! `source-roots` defaults to `["src", "."]`. Roots are Python import directories
//! relative to the configuration file, not ownership boundaries. The most specific
//! root wins. Configure `[tool.konform] src` consistently so the filesystem probe
//! finds local submodules. Nonstandard layouts and namespace packages are supported.
//!
//! ## Examples
//!
//! With the configuration above and this layout under `src`:
//!
//! ```text
//! src/
//! └── example/
//!     ├── lib/                    # from = "example.lib": reusable library
//!     │   ├── controller.py
//!     │   └── integration/        # allowed to use the audio suite
//!     │       └── audio_bridge.py
//!     ├── product_tests/          # to = "example.product_tests": test suites
//!     │   ├── audio/
//!     │   │   └── helpers.py
//!     │   └── radio/
//!     │       └── helpers.py
//!     └── shared/                 # neutral code, outside both prefixes
//!         └── helpers.py
//! ```
//!
//! ```python
//! # In src/example/lib/controller.py
//!
//! # Bad: the library depends on a test suite
//! import example.product_tests.audio.helpers
//! from example.product_tests.audio import helpers
//! from ..product_tests.audio import helpers      # relative imports are resolved too
//!
//! # Good: neutral code outside the forbidden target
//! from example.shared import helpers
//! ```
//!
//! Contracts are one-way, and `allowed` narrows them to reviewed pairs:
//!
//! ```python
//! # Good in src/example/product_tests/radio/helpers.py: tests may use the library
//! from example.lib import controller
//!
//! # Good in src/example/lib/integration/audio_bridge.py: allowed pair
//! from example.product_tests.audio import helpers
//!
//! # Still bad there: `allowed` covers the audio suite only
//! from example.product_tests.radio import helpers
//! ```
//!
//! To fix a finding, move what the library needs into neutral code such as
//! `example.shared`, or add a reviewed `allowed` pair.
//!
//! ## Suppression
//!
//! Prefer a local exception with a specific reason when the dependency is unavoidable:
//!
//! ```python
//! from example.product_tests.audio import helpers  # noqa: KIB001 -- Reason: compatibility adapter requires the existing suite API.
//! ```
//!
//! ## Precision and limitations
//!
//! The Python AST handles relative, aliased, nested, inline, and commented multiline
//! imports without matching comments or strings. The filesystem module probe
//! distinguishes imported child modules from objects without executing imports.
//! Package initializers and `.pyi` files are supported.
//!
//! Only direct imports are checked: dynamic imports, re-export origins, transitive
//! paths, and cycles are outside scope. Syntax-invalid files and files outside
//! source roots are not analyzed. Use `--no-cache` after changing package layout.
//! Invalid boundary configuration is reported as an error.
//! No automatic fix is provided; moving code requires an ownership decision.

use super::docs::{RuleDocs, RuleOption};
use super::import_boundaries::{under, BoundaryChecker};
use super::{FileContext, Rule};
use crate::module_probe::ModuleProbe;
use crate::types::Violation;
use std::path::PathBuf;
use std::sync::Arc;

pub struct Kib001Rule {
    checker: BoundaryChecker,
}

impl Kib001Rule {
    pub fn new(probe: Arc<ModuleProbe>, config_dir: Option<PathBuf>) -> Self {
        Self {
            checker: BoundaryChecker::new(probe, config_dir),
        }
    }
}

impl Rule for Kib001Rule {
    fn code(&self) -> &str {
        "KIB001"
    }

    fn category(&self) -> &str {
        "KIB"
    }

    fn config_name(&self) -> &str {
        "import-boundaries"
    }

    fn name(&self) -> &str {
        "Forbidden import boundaries"
    }

    fn description(&self) -> &str {
        "Checks direct imports crossing configured forbidden module boundaries."
    }

    fn check(&self, ctx: &FileContext, cfg: &toml::Value) -> Vec<Violation> {
        self.checker.check(
            ctx,
            cfg,
            self.code(),
            |settings, _project, importer, target| {
                settings
                    .forbidden
                    .iter()
                    .any(|boundary| under(importer, &boundary.from) && under(target, &boundary.to))
            },
        )
    }

    fn fingerprint(&self, _cfg: &toml::Value) -> u64 {
        self.checker.fingerprint()
    }

    fn docs(&self) -> RuleDocs {
        RuleDocs {
            what_it_does: "Checks direct imports against configured forbidden module-prefix boundaries.",
            why_bad: "A reusable package that imports feature or test-suite code becomes coupled to implementation details that should depend on it, not the other way around.",
            options: vec![
                RuleOption {
                    name: "source-roots",
                    ty: "string list",
                    default: "[\"src\", \".\"]".into(),
                    description: "Python import roots relative to the config file.",
                },
                RuleOption {
                    name: "forbidden",
                    ty: "boundary list",
                    default: "[]".into(),
                    description: "One-way importing and target module-prefix pairs to reject.",
                },
                RuleOption {
                    name: "allowed",
                    ty: "boundary list",
                    default: "[]".into(),
                    description: "Reviewed importing/target prefix pairs exempt from both KIB rules.",
                },
                RuleOption {
                    name: "level",
                    ty: "string",
                    default: "\"warning\"".into(),
                    description: "Violation level: warning or error.",
                },
            ],
            ..RuleDocs::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Level;
    use std::path::Path;

    fn rule(dir: &Path) -> Kib001Rule {
        Kib001Rule::new(
            Arc::new(ModuleProbe::new(Path::new("python3"), dir, &["src".into()])),
            Some(dir.to_path_buf()),
        )
    }

    #[test]
    fn no_contracts_means_no_restrictions() {
        let dir = tempfile::tempdir().unwrap();
        let rule = rule(dir.path());
        let ctx = FileContext::from_source(
            dir.path().join("src/library/controller.py"),
            "import product.feature.helpers\n".into(),
        );
        let cfg = toml::from_str::<toml::Value>("").unwrap();
        assert!(rule.check(&ctx, &cfg).is_empty());
        assert!(!rule.fixable());
        assert_eq!(rule.config_name(), "import-boundaries");
    }

    #[test]
    fn contracts_are_directional_and_match_complete_components() {
        let dir = tempfile::tempdir().unwrap();
        let rule = rule(dir.path());
        let cfg = toml::from_str::<toml::Value>(
            "forbidden=[{from='library',to='product.feature'}]\nlevel='error'",
        )
        .unwrap();
        for (path, source, expected) in [
            ("src/library/controller.py", "import product.feature", 1),
            (
                "src/library/nested/controller.py",
                "import product.feature.helpers",
                1,
            ),
            (
                "src/library_extra/controller.py",
                "import product.feature",
                0,
            ),
            (
                "src/library/controller.py",
                "import product.feature_extra",
                0,
            ),
            (
                "src/product/feature/controller.py",
                "import library.helpers",
                0,
            ),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            let violations = rule.check(&ctx, &cfg);
            assert_eq!(violations.len(), expected, "{path}: {source}");
            if expected != 0 {
                assert_eq!(violations[0].rule, "KIB001");
                assert_eq!(violations[0].level, Level::Error);
                assert!(!violations[0].fixable);
            }
        }
    }

    #[test]
    fn documented_example_behaves_as_described() {
        let dir = tempfile::tempdir().unwrap();
        for module in [
            "src/example/lib/controller.py",
            "src/example/lib/integration/audio_bridge.py",
            "src/example/product_tests/audio/helpers.py",
            "src/example/product_tests/radio/helpers.py",
            "src/example/shared/helpers.py",
        ] {
            let path = dir.path().join(module);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        let rule = rule(dir.path());
        let cfg = toml::from_str::<toml::Value>(
            "source-roots = ['src']\n\
             forbidden = [{ from = 'example.lib', to = 'example.product_tests' }]\n\
             allowed = [{ from = 'example.lib.integration', to = 'example.product_tests.audio' }]",
        )
        .unwrap();
        let controller = "src/example/lib/controller.py";
        let bridge = "src/example/lib/integration/audio_bridge.py";
        for (path, source, expected) in [
            (controller, "import example.product_tests.audio.helpers", 1),
            (
                controller,
                "from example.product_tests.audio import helpers",
                1,
            ),
            (controller, "from ..product_tests.audio import helpers", 1),
            (controller, "from example.shared import helpers", 0),
            (
                "src/example/product_tests/radio/helpers.py",
                "from example.lib import controller",
                0,
            ),
            (bridge, "from example.product_tests.audio import helpers", 0),
            (bridge, "from example.product_tests.radio import helpers", 1),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, &cfg).len(), expected, "{path}: {source}");
        }
    }

    #[test]
    fn allowed_contract_does_not_exempt_other_importers_or_targets() {
        let dir = tempfile::tempdir().unwrap();
        let rule = rule(dir.path());
        let cfg = toml::from_str::<toml::Value>(
            "forbidden=[{from='library',to='product'}]\n\
             allowed=[{from='library.adapter',to='product.feature'}]",
        )
        .unwrap();
        for (path, source, expected) in [
            (
                "src/library/adapter.py",
                "import product.feature.helpers",
                0,
            ),
            (
                "src/library/controller.py",
                "import product.feature.helpers",
                1,
            ),
            ("src/library/adapter.py", "import product.other.helpers", 1),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, &cfg).len(), expected, "{path}: {source}");
        }
    }

    #[test]
    fn noqa_aliases_and_ignore_noqa_are_respected() {
        let dir = tempfile::tempdir().unwrap();
        let rule = rule(dir.path());
        let cfg =
            toml::from_str::<toml::Value>("forbidden=[{from='library',to='product'}]").unwrap();
        let mut ctx = FileContext::from_source(
            dir.path().join("src/library/controller.py"),
            "import product.feature # noqa: OLD -- Reason: compatibility adapter\n".into(),
        );
        ctx.noqa_aliases.insert("OLD".into(), "KIB001".into());
        assert!(rule.check(&ctx, &cfg).is_empty());
        ctx.ignore_noqa = true;
        assert_eq!(rule.check(&ctx, &cfg).len(), 1);
    }
}
