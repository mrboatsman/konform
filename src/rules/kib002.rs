//! # KIB002 — Independent sibling packages
//!
//! Automatically detects direct imports between local nested sibling packages.
//! Keep features independent: extract genuinely reusable code into a shared package
//! instead of making one feature depend on another feature's implementation.
//! No library, product, or feature names need to be listed.
//!
//! ## Activation and automatic scope
//!
//! ```toml
//! [tool.konform.lint]
//! select = ["KIB002"]
//! ```
//!
//! The rule compares the first differing components of importing and target module
//! paths. Both branches must be local package directories beneath a common parent.
//! Top-level packages, same-package modules, ancestor imports, and sibling leaf
//! `.py`/`.pyi` modules are allowed. Namespace directories count as packages.
//! Targets outside local source roots are not automatic boundaries.
//!
//! Given this layout under the source root `src`:
//!
//! ```text
//! src/
//! ├── shop/
//! │   ├── catalog/          # feature package
//! │   │   └── pricing.py
//! │   ├── checkout/         # sibling feature package
//! │   │   ├── cart.py
//! │   │   └── tax.py
//! │   └── money.py          # module beside the features, not a package
//! └── common/               # separate top-level package
//!     └── rounding.py
//! ```
//!
//! ```python
//! # In src/shop/checkout/cart.py
//!
//! # Bad: checkout depends on its sibling feature, catalog
//! import shop.catalog.pricing
//! from shop.catalog.pricing import unit_price
//! from ..catalog import pricing
//!
//! # Good
//! from shop.checkout import tax                 # same package
//! from shop import money                        # sibling module, not a package
//! from common.rounding import round_half_even   # different top-level package
//! ```
//!
//! To fix a finding, move the code both features need out of `catalog`: into a
//! module beside the features such as `shop/money.py`, into a top-level package
//! such as `common`, or into a package named in `shared-package-names`.
//!
//! ## Shared sibling packages
//!
//! Configure shared folder names when reusable code lives alongside features:
//!
//! ```toml
//! [tool.konform.lint.import-boundaries]
//! shared-package-names = ["shared"]
//! ```
//!
//! This setting defaults to `[]`. Names are single components, not dotted prefixes;
//! they match at any checked level. `shared` matches `product.shared`, not
//! `product.shared_extra`. The exception is one-way:
//!
//! ```python
//! # Good in src/shop/checkout/cart.py with the setting above
//! import shop.shared.formatting
//!
//! # Still bad in src/shop/shared/formatting.py
//! import shop.catalog.pricing
//! ```
//!
//! Automatic scope is structural, not an ownership inference. `company.shared`
//! and `company.product` are nested siblings, unlike top-level `shared` and
//! `product`. No package name is special by default.
//!
//! ## Optional explicit scope and exceptions
//!
//! ```toml
//! [tool.konform.lint.import-boundaries]
//! source-roots = ["src"]
//! independent = ["example.product_tests"]
//! shared-package-names = ["shared"]
//! allowed = [
//!   { from = "example.product_tests.integration", to = "example.product_tests.audio" },
//! ]
//! level = "warning"
//! ```
//!
//! A nonempty `independent` replaces automatic detection: only different immediate
//! children of those module roots are checked. Within-child imports and imports
//! outside the roots are allowed. Shared-package exceptions apply in this mode too.
//! `allowed` exempts reviewed importing/target prefix pairs for both KIB rules.
//! Prefix matching respects dotted components.
//!
//! `source-roots` defaults to `["src", "."]`, relative to the configuration file.
//! The most specific import root wins. Configure `[tool.konform] src` consistently
//! with these roots so the filesystem probe can find imported submodules.
//! The default level is `"warning"`; use `"error"` to fail the default CLI threshold,
//! or run with `--level warning` to fail on warning-level findings.
//!
//! ## Unavoidable feature dependencies
//!
//! Suppress only this rule on the import and explain why shared extraction does
//! not fit:
//!
//! ```python
//! import shop.catalog.pricing  # noqa: KIB002 -- Reason: checkout must quote the live catalog price.
//! ```
//!
//! ## Precision and limitations
//!
//! The Python AST handles relative, aliased, nested, inline, and commented multiline
//! imports without matching strings or comments. The filesystem probe distinguishes
//! child modules from objects without executing imports. Namespace packages,
//! initializers, and `.pyi` files are supported.
//!
//! These are direct checks: dynamic imports, re-export origins, indirect dependency
//! paths, and cycles require separate analysis. Syntax-invalid files and files
//! outside source roots are not analyzed. Use `--no-cache` after changing package
//! layout. Invalid configuration is reported as an error. No automatic fix is provided.

use super::docs::{RuleDocs, RuleOption};
use super::import_boundaries::{sibling, BoundaryChecker};
use super::{FileContext, Rule};
use crate::module_probe::ModuleProbe;
use crate::types::Violation;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Kib002Rule {
    checker: BoundaryChecker,
}

impl Kib002Rule {
    pub fn new(probe: Arc<ModuleProbe>, config_dir: Option<PathBuf>) -> Self {
        Self {
            checker: BoundaryChecker::new(probe, config_dir),
        }
    }
}

impl Rule for Kib002Rule {
    fn code(&self) -> &str {
        "KIB002"
    }

    fn category(&self) -> &str {
        "KIB"
    }

    fn config_name(&self) -> &str {
        "import-boundaries"
    }

    fn name(&self) -> &str {
        "Independent sibling packages"
    }

    fn description(&self) -> &str {
        "Checks direct imports between local nested sibling packages, with optional parent scopes."
    }

    fn check(&self, ctx: &FileContext, cfg: &toml::Value) -> Vec<Violation> {
        self.checker
            .check(ctx, cfg, self.code(), |settings, project, importer, target| {
                if settings.independent.is_empty() {
                    return settings.source_roots.iter().any(|root| {
                        automatic_siblings(
                            &project.join(root),
                            importer,
                            target,
                            &settings.shared_package_names,
                        )
                    });
                }
                settings.independent.iter().any(|root| {
                    matches!((sibling(importer, root), sibling(target, root)),
                    (Some(from), Some(to)) if from != to && !settings.shared_package_names.contains(&to))
                })
            })
    }

    fn fingerprint(&self, _cfg: &toml::Value) -> u64 {
        self.checker.fingerprint()
    }

    fn docs(&self) -> RuleDocs {
        RuleDocs {
            what_it_does: "Finds direct imports between local nested sibling packages so independent features do not depend on one another.",
            why_bad: "Sibling features become difficult to change independently when they import each other's implementation instead of using neutral shared code.",
            options: vec![
                RuleOption {
                    name: "source-roots",
                    ty: "string list",
                    default: "[\"src\", \".\"]".into(),
                    description: "Python import roots relative to the config file.",
                },
                RuleOption {
                    name: "independent",
                    ty: "string list",
                    default: "[]".into(),
                    description: "Optional module roots whose immediate child packages must remain independent.",
                },
                RuleOption {
                    name: "shared-package-names",
                    ty: "string list",
                    default: "[]".into(),
                    description: "Sibling package names treated as neutral shared dependencies.",
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

fn automatic_siblings(
    root: &Path,
    importer: &str,
    target: &str,
    shared_package_names: &[String],
) -> bool {
    let from: Vec<_> = importer.split('.').collect();
    let to: Vec<_> = target.split('.').collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    if common == 0 || common == from.len() || common == to.len() {
        return false;
    }
    if shared_package_names.iter().any(|name| name == to[common]) {
        return false;
    }
    // A divergent leaf module is not a sibling package.
    let from_branch: PathBuf = from[..=common].iter().collect();
    let to_branch: PathBuf = to[..=common].iter().collect();
    root.join(from_branch).is_dir() && root.join(to_branch).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_scope_distinguishes_packages_from_leaf_modules() {
        let dir = tempfile::tempdir().unwrap();
        for package in ["product/one", "product/two", "product/shared"] {
            std::fs::create_dir_all(dir.path().join(package)).unwrap();
        }
        std::fs::write(dir.path().join("product/helpers.py"), "").unwrap();
        for (importer, target, expected) in [
            ("product.one.controller", "product.two.helpers", true),
            ("product.one", "product.two", true),
            ("product.one.controller", "product.one.helpers", false),
            ("product.one.controller", "product.helpers", false),
            ("product.one.controller", "product", false),
            ("product.one.controller", "shared.helpers", false),
            ("product.one.controller", "external.two.helpers", false),
            ("product.one.controller", "product.missing.helpers", false),
        ] {
            assert_eq!(
                automatic_siblings(dir.path(), importer, target, &[]),
                expected,
                "{importer} -> {target}"
            );
        }
        assert!(!automatic_siblings(
            dir.path(),
            "product.one.controller",
            "product.shared.helpers",
            &["shared".into()]
        ));
        assert!(automatic_siblings(
            dir.path(),
            "product.shared.controller",
            "product.one.helpers",
            &["shared".into()]
        ));
    }

    #[test]
    fn documented_example_behaves_as_described() {
        let dir = tempfile::tempdir().unwrap();
        for module in [
            "src/shop/catalog/pricing.py",
            "src/shop/checkout/cart.py",
            "src/shop/checkout/tax.py",
            "src/shop/shared/formatting.py",
            "src/shop/money.py",
            "src/common/rounding.py",
        ] {
            let path = dir.path().join(module);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "").unwrap();
        }
        let rule = Kib002Rule::new(
            Arc::new(ModuleProbe::new(
                Path::new("python3"),
                dir.path(),
                &["src".into()],
            )),
            Some(dir.path().to_path_buf()),
        );
        let plain: toml::Value = toml::from_str("source-roots=['src']").unwrap();
        let shared: toml::Value =
            toml::from_str("source-roots=['src']\nshared-package-names=['shared']").unwrap();
        let cart = "src/shop/checkout/cart.py";
        for (path, cfg, source, expected) in [
            (cart, &plain, "import shop.catalog.pricing", 1),
            (
                cart,
                &plain,
                "from shop.catalog.pricing import unit_price",
                1,
            ),
            (cart, &plain, "from ..catalog import pricing", 1),
            (cart, &plain, "from . import tax", 0),
            (cart, &plain, "from shop import money", 0),
            (
                cart,
                &plain,
                "from common.rounding import round_half_even",
                0,
            ),
            (cart, &shared, "import shop.shared.formatting", 0),
            (
                "src/shop/shared/formatting.py",
                &shared,
                "import shop.catalog.pricing",
                1,
            ),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, cfg).len(), expected, "{path}: {source}");
        }
    }

    #[test]
    fn explicit_scope_replaces_automatic_scope_and_keeps_shared_exception_directional() {
        let dir = tempfile::tempdir().unwrap();
        for package in [
            "src/company/product/one",
            "src/company/product/two",
            "src/company/product/shared",
            "src/company/other",
        ] {
            std::fs::create_dir_all(dir.path().join(package)).unwrap();
        }
        let rule = Kib002Rule::new(
            Arc::new(ModuleProbe::new(
                Path::new("python3"),
                dir.path(),
                &["src".into()],
            )),
            Some(dir.path().to_path_buf()),
        );
        let cfg = toml::from_str::<toml::Value>(
            "independent=['company.product']\nshared-package-names=['shared']",
        )
        .unwrap();
        for (path, source, expected) in [
            (
                "src/company/product/one/controller.py",
                "import company.product.two.helpers",
                1,
            ),
            (
                "src/company/product/one/controller.py",
                "import company.product.one.helpers",
                0,
            ),
            (
                "src/company/product/one/controller.py",
                "import company.other.helpers",
                0,
            ),
            (
                "src/company/other/controller.py",
                "import company.product.one.helpers",
                0,
            ),
            (
                "src/company/product/one/controller.py",
                "import company.product.shared.helpers",
                0,
            ),
            (
                "src/company/product/shared/controller.py",
                "import company.product.one.helpers",
                1,
            ),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, &cfg).len(), expected, "{path}: {source}");
        }
    }

    #[test]
    fn automatic_scope_checks_each_source_root() {
        let dir = tempfile::tempdir().unwrap();
        for package in ["modules/product/one", "modules/product/two"] {
            std::fs::create_dir_all(dir.path().join(package)).unwrap();
        }
        let rule = Kib002Rule::new(
            Arc::new(ModuleProbe::new(
                Path::new("python3"),
                dir.path(),
                &["src".into(), "modules".into()],
            )),
            Some(dir.path().to_path_buf()),
        );
        let cfg = toml::from_str::<toml::Value>("source-roots=['src','modules']").unwrap();
        let ctx = FileContext::from_source(
            dir.path().join("modules/product/one/controller.py"),
            "import product.two.helpers".into(),
        );
        let violations = rule.check(&ctx, &cfg);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "KIB002");
    }

    #[test]
    fn automatic_detection_requires_no_named_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        for module in [
            "code/product/func1/hello_world.py",
            "code/product/func2/helpers.py",
            "code/product/func2/nested/one/helper.py",
            "code/product/func2/nested/two/helper.py",
            "code/product/shared/helpers.py",
            "code/product/shared_extra/helpers.py",
            "code/shared/hello_world.py",
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
        let rule = Kib002Rule::new(probe, Some(dir.path().to_path_buf()));
        let cfg: toml::Value = toml::from_str("source-roots=['code']").unwrap();
        for source in [
            "import product.func1.hello_world",
            "from ..func1 import hello_world",
            "from product import func1 as first",
            "def run():\n from product.func1.hello_world import hello",
            "from product.func1 import (\n hello_world, # comment\n)",
        ] {
            let ctx = FileContext::from_source(
                dir.path().join("code/product/func2/controller.py"),
                source.into(),
            );
            let violations = rule.check(&ctx, &cfg);
            assert_eq!(violations.len(), 1, "{source}");
            assert_eq!(violations[0].rule, "KIB002");
        }
        for source in [
            "import shared.hello_world",
            "from . import helpers",
            "import product.func2.helpers",
            "from product import constant",
            "import product",
            "import external.func1.helpers",
            "# import product.func1.hello_world",
            "\"\"\"\nimport product.func1.hello_world\n\"\"\"",
            "import product.func1.hello_world # noqa: KIB002",
            "import product.func1.hello_world # noqa: KIB002 -- Reason: exercises the real feature integration.",
        ] {
            let ctx = FileContext::from_source(
                dir.path().join("code/product/func2/controller.py"),
                source.into(),
            );
            assert!(rule.check(&ctx, &cfg).is_empty(), "{source}");
        }
        for source in [
            "import product.func1.hello_world # Reason: integration dependency",
            "import product.func1.hello_world # noqa: KIB001 -- Reason: integration dependency",
        ] {
            let ctx = FileContext::from_source(
                dir.path().join("code/product/func2/controller.py"),
                source.into(),
            );
            assert_eq!(rule.check(&ctx, &cfg).len(), 1, "{source}");
        }
        let source =
            "import product.func1.hello_world # noqa: KIB002 -- Reason: integration dependency";
        let mut ctx = FileContext::from_source(
            dir.path().join("code/product/func2/controller.py"),
            source.into(),
        );
        ctx.ignore_noqa = true;
        assert_eq!(rule.check(&ctx, &cfg).len(), 1);
        for path in [
            "code/product/func2/__init__.py",
            "code/product/func2/controller.pyi",
            "code/product/func2/nested/two/controller.py",
        ] {
            let source = if path.contains("nested") {
                "from ..one import helper"
            } else {
                "import product.func1.hello_world"
            };
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, &cfg).len(), 1, "{path}");
        }
        let allowed: toml::Value = toml::from_str(
            "source-roots=['code']\n\
             allowed=[{from='product.func2',to='product.func1'}]",
        )
        .unwrap();
        let ctx = FileContext::from_source(
            dir.path().join("code/product/func2/controller.py"),
            "import product.func1.hello_world".into(),
        );
        assert!(rule.check(&ctx, &allowed).is_empty());
        let explicit: toml::Value =
            toml::from_str("source-roots=['code']\nindependent=['other.parent']").unwrap();
        assert!(rule.check(&ctx, &explicit).is_empty());

        let shared: toml::Value =
            toml::from_str("source-roots=['code']\nshared-package-names=['shared']").unwrap();
        for (path, source, expected) in [
            (
                "code/product/func2/controller.py",
                "from product.shared import helpers",
                0,
            ),
            (
                "code/product/func2/controller.py",
                "from ..shared import helpers",
                0,
            ),
            (
                "code/product/func2/controller.py",
                "from product.shared_extra import helpers",
                1,
            ),
            (
                "code/product/shared/controller.py",
                "from product.func1 import hello_world",
                1,
            ),
        ] {
            let ctx = FileContext::from_source(dir.path().join(path), source.into());
            assert_eq!(rule.check(&ctx, &shared).len(), expected, "{source}");
        }
        let ctx = FileContext::from_source(
            dir.path().join("code/product/func2/controller.py"),
            "from product.shared import helpers".into(),
        );
        assert_eq!(rule.check(&ctx, &cfg).len(), 1);
        let shared_explicit: toml::Value = toml::from_str(
            "source-roots=['code']\nshared-package-names=['shared']\nindependent=['product']",
        )
        .unwrap();
        assert!(rule.check(&ctx, &shared_explicit).is_empty());
        let invalid: toml::Value =
            toml::from_str("shared-package-names=['product.shared']").unwrap();
        let violations = rule.check(&ctx, &invalid);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].level, crate::types::Level::Error);
    }
}
