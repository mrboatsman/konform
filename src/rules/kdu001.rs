//! # KDU001 — Duplicated constants
//!
//! Flags a constant or container whose value is also defined in another module
//! of the project. Service endpoints, ids, package names, URLs, commands and
//! lookup tables belong in one shared module and should be imported from there.
//!
//! This is a project rule: it compares definitions across all checked files,
//! which line-based duplicate-code checkers such as arid or Pylint `R0801`
//! cannot do for single-line constants or for the same value under another name.
//!
//! An assignment is a duplicate when another module assigns
//!
//! - the same dict, set, list or tuple, under any name. Dict and set item order
//!   is ignored and containers may be nested. Module- and class-level containers
//!   are compared by their normalized source, so lists of enum members or pytest
//!   markers count too. Function-level containers count only when they are plain
//!   literals, since they may refer to local variables. Containers with a single
//!   item need an `UPPER_CASE` name.
//! - at module level, to an `UPPER_CASE` name, the same string (at least
//!   `min-string-length` characters) under any name, or the same number, bytes
//!   or short string under the same name.
//!
//! `None`, booleans and empty strings, dunder names and `ignore-names` are never
//! compared. Every definition of a duplicated value is reported, with the other
//! definitions listed in the message.
//!
//! ## Configuration
//!
//! ```toml
//! [tool.konform.lint]
//! select = ["KDU"]
//!
//! [tool.konform.lint.duplicated-constants]
//! min-string-length = 4           # shorter strings are compared by name and value
//! ignore-names = ["pytestmark"]   # names that are never compared
//! paths = ["src"]                 # always collect these, see "Partial runs"
//! level = "warning"
//! ```
//!
//! All keys are optional; the values above are the defaults, except `paths`,
//! which defaults to `[]`.
//!
//! ## Partial runs
//!
//! Only the files of the current run are reported, but a duplicate needs its
//! other half. With `paths` set, konform also collects the definitions of every
//! Python file under those paths (relative to the configuration file), so
//! `konform check changed.py` or a pre-commit hook still finds a value that
//! `changed.py` copies from an unchanged module. Without `paths`, only the files
//! of the run are compared with each other.
//!
//! ## Examples
//!
//! ```python
//! # In tests/api/test_client.py
//!
//! # Bad: the same URL is defined in shared/config.py as API_URL
//! API_ENDPOINT = "https://api.example.com"
//!
//! # Bad: same dict as in shared/config.py, keys in another order
//! SERVICE_TIMEOUTS = {"search": 30, "storage": 60}
//!
//! # Good: import the shared definition
//! from shared import config
//!
//! API_ENDPOINT = config.API_URL
//! SERVICE_TIMEOUTS = config.SERVICE_TIMEOUTS
//! ```
//!
//! ## Suppression
//!
//! Suppress an intentional copy on the line of its name. The suppressed
//! definition is then ignored when looking for duplicates:
//!
//! ```python
//! RECORD_ID = "A123"  # noqa: KDU001 -- Reason: frozen copy of the legacy test data.
//! ```
//!
//! `per-file-ignores` work the same way for whole files, and
//! `konform check --add-noqa` marks every current definition at once.
//!
//! ## Precision and limitations
//!
//! Values are compared by AST, so formatting, quotes and comments do not matter.
//! Names, attributes, calls and subscripts inside containers are compared by
//! their text, not by what they refer to. Tuple unpacking, attribute targets and
//! `:=` assignments are not collected. Syntax-invalid files are skipped.
//! The language server does not report this rule, because it sees one file at a
//! time. No automatic fix is provided; moving a constant is a refactoring.

use super::docs::{RuleDocs, RuleOption};
use super::project::{Fact, FactRef, ProjectRule};
use super::scope::{build_line_starts, offset_to_line_col};
use super::{FileContext, Rule};
use crate::types::{Level, Violation};
use ruff_python_ast::statement_visitor::{walk_stmt, StatementVisitor};
use ruff_python_ast::{Expr, Number, Operator, Stmt, UnaryOp};
use ruff_text_size::Ranged;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const CODE: &str = "KDU001";

/// Longest value shown in a message; longer ones are cut with `...`.
const MAX_VALUE_LENGTH: usize = 60;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct Settings {
    min_string_length: usize,
    ignore_names: Vec<String>,
    paths: Vec<String>,
    level: Level,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            ignore_names: vec!["pytestmark".into()],
            paths: vec![],
            level: Level::Warning,
        }
    }
}

fn settings(cfg: &toml::Value) -> Result<Settings, String> {
    Settings::deserialize(cfg.clone()).map_err(|e| e.to_string())
}

pub struct Kdu001Rule;

impl Rule for Kdu001Rule {
    fn code(&self) -> &str {
        CODE
    }

    fn category(&self) -> &str {
        "KDU"
    }

    fn config_name(&self) -> &str {
        "duplicated-constants"
    }

    fn name(&self) -> &str {
        "Duplicated constants"
    }

    fn description(&self) -> &str {
        "Flags constants and containers whose value is also defined in another module."
    }

    fn check(&self, _ctx: &FileContext, _cfg: &toml::Value) -> Vec<Violation> {
        vec![]
    }

    fn project(&self) -> Option<&dyn ProjectRule> {
        Some(self)
    }

    fn docs(&self) -> RuleDocs {
        RuleDocs {
            what_it_does: "Finds constants and literal containers whose value is also defined in another project module.",
            why_bad: "Duplicated constants drift apart when one copy changes, and repeated values hide the shared meaning they represent.",
            options: vec![
                RuleOption {
                    name: "min-string-length",
                    ty: "integer",
                    default: "4".into(),
                    description: "Minimum string length compared across different names.",
                },
                RuleOption {
                    name: "ignore-names",
                    ty: "string list",
                    default: "[\"pytestmark\"]".into(),
                    description: "Names excluded from duplicate checks.",
                },
                RuleOption {
                    name: "paths",
                    ty: "string list",
                    default: "[]".into(),
                    description: "Additional project paths collected during partial runs.",
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

impl ProjectRule for Kdu001Rule {
    fn collect(&self, ctx: &FileContext, cfg: &toml::Value) -> Vec<Fact> {
        // Invalid settings are reported once, by `finish`.
        let Ok(settings) = settings(cfg) else {
            return vec![];
        };
        let mut collector = Collector {
            ctx,
            settings: &settings,
            scope: Scope::Module,
            starts: build_line_starts(&ctx.source),
            noqa: ctx.noqa_lines(),
            facts: vec![],
        };
        collector.visit_body(ctx.stmts());
        collector.facts
    }

    fn finish(&self, facts: &[FactRef<'_>], cfg: &toml::Value) -> Vec<(usize, Violation)> {
        let settings = match settings(cfg) {
            Ok(settings) => settings,
            Err(error) => {
                eprintln!("konform: invalid duplicated-constants configuration: {error}");
                return vec![];
            }
        };
        let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, fact) in facts.iter().enumerate() {
            if fact.fact.rule == CODE {
                groups
                    .entry(fact.fact.key.as_str())
                    .or_default()
                    .push(index);
            }
        }
        let mut violations = vec![];
        for mut group in groups.into_values() {
            let files: BTreeSet<_> = group.iter().map(|&i| facts[i].path).collect();
            if files.len() < 2 {
                continue;
            }
            group.sort_by_key(|&i| (facts[i].path, facts[i].fact.line, facts[i].fact.col));
            for &index in &group {
                let fact = facts[index].fact;
                let others = group
                    .iter()
                    .filter(|&&other| other != index)
                    .map(|&other| {
                        let FactRef { path, fact } = facts[other];
                        format!("{}:{} ({})", path.display(), fact.line, fact.name)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                violations.push((
                    index,
                    Violation {
                        rule: CODE.into(),
                        line: fact.line as usize,
                        col: fact.col as usize,
                        end_line: fact.end_line as usize,
                        end_col: fact.end_col as usize,
                        message: format!(
                            "{CODE}: '{}' = {} is also defined in {others}",
                            fact.name, fact.display
                        ),
                        help: Some(
                            "Define the value once in a shared module and import it from there."
                                .into(),
                        ),
                        level: settings.level,
                        fixable: false,
                    },
                ));
            }
        }
        violations
    }

    fn paths(&self, cfg: &toml::Value) -> Vec<String> {
        settings(cfg).map(|s| s.paths).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Module,
    Class,
    Function,
}

struct Collector<'a> {
    ctx: &'a FileContext,
    settings: &'a Settings,
    scope: Scope,
    starts: Vec<u32>,
    noqa: Vec<&'a str>,
    facts: Vec<Fact>,
}

impl<'a> StatementVisitor<'a> for Collector<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::ClassDef(node) => self.within(Scope::Class, &node.body),
            Stmt::FunctionDef(node) => self.within(Scope::Function, &node.body),
            Stmt::Assign(node) => {
                for target in &node.targets {
                    self.record(target, &node.value);
                }
            }
            Stmt::AnnAssign(node) => {
                if let Some(value) = &node.value {
                    self.record(&node.target, value);
                }
            }
            _ => walk_stmt(self, stmt),
        }
    }
}

impl<'a> Collector<'a> {
    fn within(&mut self, scope: Scope, body: &'a [Stmt]) {
        let outer = std::mem::replace(&mut self.scope, scope);
        self.visit_body(body);
        self.scope = outer;
    }

    fn record(&mut self, target: &Expr, value: &Expr) {
        let Expr::Name(target) = target else {
            return;
        };
        let name = target.id.as_str();
        let Some((key, display)) =
            duplicate_key(name, value, self.scope, self.settings, &self.ctx.source)
        else {
            return;
        };
        let (line, col) = offset_to_line_col(&self.starts, target.range.start().to_u32());
        let (end_line, end_col) = offset_to_line_col(&self.starts, target.range.end().to_u32());
        if !self.ctx.ignore_noqa
            && self
                .noqa
                .get(line - 1)
                .is_some_and(|comment| super::has_noqa(comment, CODE, &self.ctx.noqa_aliases))
        {
            return;
        }
        self.facts.push(Fact {
            rule: CODE.into(),
            key,
            name: name.into(),
            display,
            line: line as u32,
            col: col as u32,
            end_line: end_line as u32,
            end_col: end_col as u32,
        });
    }
}

fn is_constant_name(name: &str) -> bool {
    let rest = name.strip_prefix('_').unwrap_or(name);
    rest.starts_with(|c: char| c.is_ascii_uppercase())
        && rest
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The grouping key and the displayed value of `name = value`, or `None` when
/// the assignment is not compared.
fn duplicate_key(
    name: &str,
    value: &Expr,
    scope: Scope,
    settings: &Settings,
    source: &str,
) -> Option<(String, String)> {
    if settings.ignore_names.iter().any(|n| n == name)
        || (name.starts_with("__") && name.ends_with("__"))
    {
        return None;
    }
    let constant = is_constant_name(name);
    if let Some(size) = container_size(value) {
        if size == 0 || (size == 1 && !constant) {
            return None;
        }
        if scope == Scope::Function && !is_literal(value) {
            return None;
        }
        let text = canonical(value, source);
        return Some((format!("value:{text}"), shorten(&text)));
    }
    if scope != Scope::Module || !constant {
        return None;
    }
    let (text, string_length) = scalar(value)?;
    match string_length {
        Some(0) => None,
        Some(length) if length >= settings.min_string_length => {
            Some((format!("value:{text}"), shorten(&text)))
        }
        _ => Some((format!("name:{name}:{text}"), shorten(&text))),
    }
}

fn container_size(value: &Expr) -> Option<usize> {
    match value {
        Expr::Dict(node) => Some(node.items.len()),
        Expr::Set(node) => Some(node.elts.len()),
        Expr::List(node) => Some(node.elts.len()),
        Expr::Tuple(node) => Some(node.elts.len()),
        _ => None,
    }
}

/// The canonical text of a module-level scalar constant, and for strings their
/// length in characters (`None` for other scalars). `None` for values that are
/// never compared (`None`, booleans, non-literals) and for empty bytes.
fn scalar(value: &Expr) -> Option<(String, Option<usize>)> {
    match value {
        Expr::StringLiteral(node) => {
            let text = node.value.to_str();
            Some((py_repr(text), Some(text.chars().count())))
        }
        Expr::BytesLiteral(node) => (!node.value.is_empty()).then(|| (canonical(value, ""), None)),
        Expr::NumberLiteral(node) => Some((number(&node.value), None)),
        Expr::EllipsisLiteral(_) => Some(("Ellipsis".into(), None)),
        Expr::UnaryOp(node) => signed_number(node.op, &node.operand).map(|text| (text, None)),
        _ => None,
    }
}

fn signed_number(op: UnaryOp, operand: &Expr) -> Option<String> {
    let Expr::NumberLiteral(node) = operand else {
        return None;
    };
    let text = number(&node.value);
    match op {
        UnaryOp::UAdd => Some(text),
        UnaryOp::USub if text == "0" => Some(text),
        UnaryOp::USub => Some(format!("-{text}")),
        _ => None,
    }
}

fn number(value: &Number) -> String {
    match value {
        Number::Int(int) => int.to_string(),
        Number::Float(float) => format!("{float:?}"),
        Number::Complex { imag, .. } => format!("{imag:?}j"),
    }
}

/// Would Python's `ast.literal_eval` accept `expr`?
fn is_literal(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_)
        | Expr::BytesLiteral(_)
        | Expr::NumberLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NoneLiteral(_)
        | Expr::EllipsisLiteral(_) => true,
        Expr::Tuple(node) => node.elts.iter().all(is_literal),
        Expr::List(node) => node.elts.iter().all(is_literal),
        Expr::Set(node) => node.elts.iter().all(is_literal),
        Expr::Dict(node) => node
            .items
            .iter()
            .all(|item| item.key.as_ref().is_some_and(is_literal) && is_literal(&item.value)),
        Expr::Call(node) => {
            matches!(&*node.func, Expr::Name(name) if name.id.as_str() == "set")
                && node.arguments.args.is_empty()
                && node.arguments.keywords.is_empty()
        }
        Expr::UnaryOp(node) => {
            matches!(node.op, UnaryOp::UAdd | UnaryOp::USub)
                && matches!(&*node.operand, Expr::NumberLiteral(_))
        }
        Expr::BinOp(node) => {
            let real = match &*node.left {
                Expr::NumberLiteral(left) => Some(&left.value),
                Expr::UnaryOp(left) if matches!(left.op, UnaryOp::UAdd | UnaryOp::USub) => {
                    match &*left.operand {
                        Expr::NumberLiteral(operand) => Some(&operand.value),
                        _ => None,
                    }
                }
                _ => None,
            };
            matches!(node.op, Operator::Add | Operator::Sub)
                && matches!(real, Some(Number::Int(_) | Number::Float(_)))
                && matches!(&*node.right, Expr::NumberLiteral(right) if matches!(right.value, Number::Complex { .. }))
        }
        _ => false,
    }
}

/// Normalized source of `expr`: dict and set items sorted, strings quoted
/// consistently, whitespace and comments dropped.
fn canonical(expr: &Expr, source: &str) -> String {
    let join = |items: &[Expr]| {
        items
            .iter()
            .map(|e| canonical(e, source))
            .collect::<Vec<_>>()
    };
    match expr {
        Expr::Dict(node) => {
            let mut items: Vec<String> = node
                .items
                .iter()
                .map(|item| match &item.key {
                    Some(key) => format!(
                        "{}: {}",
                        canonical(key, source),
                        canonical(&item.value, source)
                    ),
                    None => format!("**{}", canonical(&item.value, source)),
                })
                .collect();
            items.sort();
            format!("{{{}}}", items.join(", "))
        }
        Expr::Set(node) => {
            let mut items = join(&node.elts);
            items.sort();
            format!("{{{}}}", items.join(", "))
        }
        Expr::List(node) => format!("[{}]", join(&node.elts).join(", ")),
        Expr::Tuple(node) => {
            let comma = if node.elts.len() == 1 { "," } else { "" };
            format!("({}{comma})", join(&node.elts).join(", "))
        }
        Expr::StringLiteral(node) => py_repr(node.value.to_str()),
        Expr::BytesLiteral(node) => {
            let mut text = String::from("b'");
            for byte in node.value.bytes() {
                match byte {
                    b'\\' => text.push_str("\\\\"),
                    b'\'' => text.push_str("\\'"),
                    b'\n' => text.push_str("\\n"),
                    b'\r' => text.push_str("\\r"),
                    b'\t' => text.push_str("\\t"),
                    0x20..=0x7e => text.push(byte as char),
                    _ => text.push_str(&format!("\\x{byte:02x}")),
                }
            }
            text.push('\'');
            text
        }
        Expr::NumberLiteral(node) => number(&node.value),
        Expr::BooleanLiteral(node) => if node.value { "True" } else { "False" }.into(),
        Expr::NoneLiteral(_) => "None".into(),
        Expr::EllipsisLiteral(_) => "...".into(),
        Expr::Name(node) => node.id.to_string(),
        Expr::Attribute(node) => {
            format!("{}.{}", canonical(&node.value, source), node.attr.as_str())
        }
        Expr::Call(node) => {
            let mut arguments = join(&node.arguments.args);
            arguments.extend(
                node.arguments
                    .keywords
                    .iter()
                    .map(|keyword| match &keyword.arg {
                        Some(arg) => {
                            format!("{}={}", arg.as_str(), canonical(&keyword.value, source))
                        }
                        None => format!("**{}", canonical(&keyword.value, source)),
                    }),
            );
            format!(
                "{}({})",
                canonical(&node.func, source),
                arguments.join(", ")
            )
        }
        Expr::Subscript(node) => format!(
            "{}[{}]",
            canonical(&node.value, source),
            canonical(&node.slice, source)
        ),
        Expr::Starred(node) => format!("*{}", canonical(&node.value, source)),
        Expr::UnaryOp(node) => match signed_number(node.op, &node.operand) {
            Some(text) => text,
            None if node.op == UnaryOp::Not => format!("not {}", canonical(&node.operand, source)),
            None => format!("{}{}", node.op.as_str(), canonical(&node.operand, source)),
        },
        Expr::BinOp(node) => format!(
            "({} {} {})",
            canonical(&node.left, source),
            node.op.as_str(),
            canonical(&node.right, source)
        ),
        _ => source
            .get(expr.range().start().to_usize()..expr.range().end().to_usize())
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// Python's `repr()` of a `str`.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn shorten(text: &str) -> String {
    if text.chars().count() <= MAX_VALUE_LENGTH {
        return text.into();
    }
    let mut short: String = text.chars().take(MAX_VALUE_LENGTH - 3).collect();
    short.push_str("...");
    short
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Collect each `(file stem, source)` and run `finish`, returning
    /// `(stem, name) -> message` for every reported definition.
    fn run_with(cfg: &str, modules: &[(&str, &str)]) -> BTreeMap<(String, String), String> {
        let cfg: toml::Value = toml::from_str(cfg).unwrap();
        let paths: Vec<PathBuf> = modules
            .iter()
            .map(|(stem, _)| PathBuf::from(format!("{stem}.py")))
            .collect();
        let collected: Vec<Vec<Fact>> = modules
            .iter()
            .zip(&paths)
            .map(|((_, source), path)| {
                let ctx = FileContext::from_source(path.clone(), dedent(source));
                Kdu001Rule.collect(&ctx, &cfg)
            })
            .collect();
        let refs: Vec<FactRef<'_>> = paths
            .iter()
            .zip(&collected)
            .flat_map(|(path, facts)| facts.iter().map(move |fact| FactRef { path, fact }))
            .collect();
        Kdu001Rule
            .finish(&refs, &cfg)
            .into_iter()
            .map(|(index, violation)| {
                let stem = refs[index].path.file_stem().unwrap().to_string_lossy();
                (
                    (stem.into_owned(), refs[index].fact.name.clone()),
                    violation.message,
                )
            })
            .collect()
    }

    fn run(modules: &[(&str, &str)]) -> BTreeMap<(String, String), String> {
        run_with("", modules)
    }

    fn keys(found: &BTreeMap<(String, String), String>) -> Vec<(&str, &str)> {
        found
            .keys()
            .map(|(stem, name)| (stem.as_str(), name.as_str()))
            .collect()
    }

    fn dedent(source: &str) -> String {
        let indent = source
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.len() - line.trim_start().len())
            .min()
            .unwrap_or(0);
        source
            .lines()
            .map(|line| line.get(indent..).unwrap_or("").to_owned() + "\n")
            .collect()
    }

    #[test]
    fn same_name_and_value_in_two_modules_is_reported() {
        let found = run(&[
            (
                "connectivity",
                "USAGE_MODE_DID = \"DD 0A\"\nTIMEOUT = 30\nOFFSET = -1\n",
            ),
            (
                "test_usage_mode",
                "USAGE_MODE_DID: str = 'DD 0A'\nTIMEOUT = 30\nOFFSET = -1\n",
            ),
        ]);
        assert_eq!(
            keys(&found),
            [
                ("connectivity", "OFFSET"),
                ("connectivity", "TIMEOUT"),
                ("connectivity", "USAGE_MODE_DID"),
                ("test_usage_mode", "OFFSET"),
                ("test_usage_mode", "TIMEOUT"),
                ("test_usage_mode", "USAGE_MODE_DID"),
            ]
        );
    }

    #[test]
    fn containers_are_reported_regardless_of_name_and_order() {
        let found = run(&[
            (
                "a",
                r#"
                ECU_TIMEOUTS = {"TCA": 60, "PAK": [1, 2]}
                ECUS = {"TCA", "PAK"}
                RANGES = [(1, 2), (3, -4)]
                SESSIONS = (1, 2, 3)
                "#,
            ),
            (
                "b",
                r#"
                TIMEOUTS = {"PAK": [1, 2], "TCA": 60}
                SUPPORTED_ECUS = {"PAK", "TCA"}
                RANGES_COPY = [(1, 2), (3, -4)]
                SESSION_IDS = (1, 2, 3)
                "#,
            ),
        ]);
        assert_eq!(found.len(), 8);
        assert_eq!(
            found[&("a".into(), "ECU_TIMEOUTS".into())],
            "KDU001: 'ECU_TIMEOUTS' = {'PAK': [1, 2], 'TCA': 60} is also defined in b.py:2 (TIMEOUTS)"
        );
    }

    #[test]
    fn renamed_string_lists_all_other_locations() {
        let found = run(&[
            ("a", "GOOGLE_DNS_IP = \"8.8.8.8\"\n"),
            ("b", "GOOGLE_PUBLIC_DNS = \"8.8.8.8\"\n"),
            ("c", "GOOGLE_DHCP_IP = \"8.8.8.8\"\n"),
        ]);
        assert_eq!(found.len(), 3);
        assert_eq!(
            found[&("a".into(), "GOOGLE_DNS_IP".into())],
            "KDU001: 'GOOGLE_DNS_IP' = '8.8.8.8' is also defined in \
             b.py:1 (GOOGLE_PUBLIC_DNS), c.py:1 (GOOGLE_DHCP_IP)"
        );
        assert_eq!(
            found[&("b".into(), "GOOGLE_PUBLIC_DNS".into())],
            "KDU001: 'GOOGLE_PUBLIC_DNS' = '8.8.8.8' is also defined in \
             a.py:1 (GOOGLE_DNS_IP), c.py:1 (GOOGLE_DHCP_IP)"
        );
    }

    #[test]
    fn unrelated_values_and_scopes_are_ignored() {
        let found = run(&[
            (
                "a",
                r#"
                TIMEOUT = 30
                STATE = "on"
                ENABLED = True
                NOTHING = None
                ADDRESS = "10.0.0.1"
                ADDRESS = "10.0.0.1"
                EMPTY = {}
                BLANK = ""
                PAIR = (1, 2)
                ORDER = [3, 4]
                single = ["DIM"]
                pytestmark = [pytest.mark.owner("x"), pytest.mark.project("v436")]
                __all__ = ["TIMEOUT", "STATE"]
                FIRST, SECOND = "abcd", "efgh"
                self_url = "https://example.com"

                class Ids:
                    ECU_ID = "1D12"

                def helper():
                    ECU_ID = "1D12"
                    result = {"id": request.param, "ok": True}
                "#,
            ),
            (
                "b",
                r#"
                DELAY = 30
                MODE = "on"
                ENABLED = True
                NOTHING = None
                log_path = "10.0.0.1"
                EMPTY = {}
                BLANK = ""
                PAIR = [1, 2]
                ORDER = [4, 3]
                single = ["DIM"]
                pytestmark = [pytest.mark.owner("x"), pytest.mark.project("v436")]
                __all__ = ["TIMEOUT", "STATE"]
                FIRST, SECOND = "abcd", "efgh"
                obj.URL = "https://example.com"

                class Other:
                    ECU_ID = "1D12"

                def fixture():
                    result = {"id": request.param, "ok": True}
                "#,
            ),
        ]);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn containers_referencing_names_are_compared_by_source() {
        let found = run(&[
            (
                "a",
                r#"
                MODES = [Mode.ON, Mode.OFF]
                platform_dependent_markers = {
                    "SPA2": [pytest.mark.project("v551"), pytest.mark.type_designation("100")],
                    "SPA3": [pytest.mark.project("v436")],  # comment
                }

                class Data:
                    eda0 = (f"F121{BCD}", f"F125{BCD}")
                "#,
            ),
            (
                "b",
                r#"
                MODES = [Mode.ON,
                         Mode.OFF]
                platform_dependent_markers = {
                    "SPA3": [pytest.mark.project('v436')],
                    "SPA2": [pytest.mark.project('v551'), pytest.mark.type_designation('100')],
                }
                eda0_programming = (f"F121{BCD}",  f"F125{BCD}")
                "#,
            ),
        ]);
        assert_eq!(
            keys(&found),
            [
                ("a", "MODES"),
                ("a", "eda0"),
                ("a", "platform_dependent_markers"),
                ("b", "MODES"),
                ("b", "eda0_programming"),
                ("b", "platform_dependent_markers"),
            ]
        );
    }

    #[test]
    fn literal_containers_in_functions_are_reported() {
        let found = run(&[
            (
                "a",
                r#"
                def screens():
                    displays = ["DIM", "CSD"]
                "#,
            ),
            (
                "b",
                r#"
                def test_monitor():
                    try:
                        displays = ["DIM", "CSD"]
                    finally:
                        pass
                "#,
            ),
        ]);
        assert_eq!(keys(&found), [("a", "displays"), ("b", "displays")]);
    }

    #[test]
    fn short_strings_and_numbers_need_the_same_name() {
        let found = run(&[
            ("a", "MODE = 'on'\nRETRIES = 3\nSCALE = 1.5\n"),
            ("b", "STATE = 'on'\nATTEMPTS = 3\nSCALE = 1.50\n"),
        ]);
        assert_eq!(keys(&found), [("a", "SCALE"), ("b", "SCALE")]);
    }

    #[test]
    fn min_string_length_and_ignore_names_are_configurable() {
        let modules = [
            ("a", "MODE = 'on'\npytestmark = [1, 2]\nMARKS = [3, 4]\n"),
            ("b", "STATE = 'on'\npytestmark = [1, 2]\nOTHER = [3, 4]\n"),
        ];
        assert_eq!(keys(&run(&modules)), [("a", "MARKS"), ("b", "OTHER")]);
        let found = run_with(
            "min-string-length = 2\nignore-names = ['MARKS', 'OTHER']",
            &modules,
        );
        assert_eq!(
            keys(&found),
            [
                ("a", "MODE"),
                ("a", "pytestmark"),
                ("b", "STATE"),
                ("b", "pytestmark"),
            ]
        );
    }

    #[test]
    fn duplicates_within_one_file_only_are_not_reported() {
        assert!(run(&[("a", "A_URL = 'https://x'\nB_URL = 'https://x'\n")]).is_empty());
        // ... but are listed once another module has the value too.
        let found = run(&[
            ("a", "A_URL = 'https://x'\nB_URL = 'https://x'\n"),
            ("b", "C_URL = 'https://x'\n"),
        ]);
        assert_eq!(found.len(), 3);
        assert!(found[&("b".into(), "C_URL".into())].ends_with("a.py:1 (A_URL), a.py:2 (B_URL)"));
    }

    #[test]
    fn noqa_hides_the_definition() {
        let cfg = toml::Value::Table(Default::default());
        let ctx = FileContext::from_source(
            Path::new("b.py").into(),
            "ECU_ID = '1D12'  # noqa: KDU001 -- frozen copy\nOTHER_ID = '1D13'\n".into(),
        );
        let facts = Kdu001Rule.collect(&ctx, &cfg);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].name, "OTHER_ID");

        assert!(run(&[
            ("a", "ECU_ID = '1D12'\n"),
            ("b", "ECU_ID = '1D12'  # noqa: KDU001\n"),
        ])
        .is_empty());
        // A noqa in an unrelated module does not hide the others.
        assert_eq!(
            run(&[
                ("a", "ECU_ID = '1D12'\n"),
                ("b", "ECU_ID = '1D12'\n"),
                ("z", "OTHER = 1  # noqa: KDU001\n"),
            ])
            .len(),
            2
        );
    }

    #[test]
    fn violation_points_at_the_name_with_the_configured_level() {
        let cfg: toml::Value = toml::from_str("level = 'error'").unwrap();
        let a = FileContext::from_source("a.py".into(), "\nX_ID: str = '1D12'\n".into());
        let b = FileContext::from_source("b.py".into(), "X_ID = '1D12'\n".into());
        let fa = Kdu001Rule.collect(&a, &cfg);
        let fb = Kdu001Rule.collect(&b, &cfg);
        let refs = [
            FactRef {
                path: Path::new("a.py"),
                fact: &fa[0],
            },
            FactRef {
                path: Path::new("b.py"),
                fact: &fb[0],
            },
        ];
        let violations = Kdu001Rule.finish(&refs, &cfg);
        let (index, v) = &violations[0];
        assert_eq!(*index, 0);
        assert_eq!((v.line, v.col, v.end_line, v.end_col), (2, 0, 2, 4));
        assert_eq!(v.level, Level::Error);
        assert!(!v.fixable);
    }

    #[test]
    fn invalid_configuration_reports_nothing() {
        assert!(run_with(
            "unknown-key = 1",
            &[("a", "X = [1, 2]\n"), ("b", "Y = [1, 2]\n")]
        )
        .is_empty());
        assert!(Kdu001Rule
            .paths(&toml::from_str("paths = ['src']").unwrap())
            .contains(&"src".to_owned()));
    }

    #[test]
    fn canonical_forms() {
        let expr = |source: &str| {
            let parsed = ruff_python_parser::parse_expression(source).unwrap();
            canonical(parsed.expr(), source)
        };
        assert_eq!(expr("{'b': 1, **x, 'a': (1,)}"), "{'a': (1,), 'b': 1, **x}");
        assert_eq!(expr("{\"it's\", 'b'}"), "{\"it's\", 'b'}");
        assert_eq!(
            expr("[b'a\\n', -0, +1, -2.5, 3j, None, ...]"),
            "[b'a\\n', 0, 1, -2.5, 3.0j, None, ...]"
        );
        assert_eq!(
            expr("[f(a,  *b, k = 1, **c), x[1:2], not y]"),
            "[f(a, *b, k=1, **c), x[1:2], not y]"
        );
        assert_eq!(py_repr("tab\there\\"), "'tab\\there\\\\'");
        assert_eq!(shorten(&"x".repeat(70)), format!("{}...", "x".repeat(57)));
    }

    #[test]
    fn literal_detection_matches_ast_literal_eval() {
        let literal = |source: &str| {
            let parsed = ruff_python_parser::parse_expression(source).unwrap();
            is_literal(parsed.expr())
        };
        for source in [
            "[1, 'a', b'b', None, True, (1,), {1: {2}}]",
            "set()",
            "-1",
            "1 + 2j",
            "-1 - 2j",
        ] {
            assert!(literal(source), "{source}");
        }
        for source in [
            "[x]", "{**a}", "set([1])", "not 1", "1 + 2", "[f'{x}']", "[*a]",
        ] {
            assert!(!literal(source), "{source}");
        }
    }

    #[test]
    fn constant_names() {
        for name in ["A", "_A", "ECU_ID", "A1_B2", "_PRIVATE_X"] {
            assert!(is_constant_name(name), "{name}");
        }
        for name in ["", "_", "a", "Ab", "__A", "1A", "A-B"] {
            assert!(!is_constant_name(name), "{name}");
        }
    }
}
