//! Cross-file ("project") rules.
//!
//! A normal [`super::Rule`] sees one [`FileContext`] at a time, and its
//! results are cached per file. A project rule needs every file before it can
//! decide anything (e.g. "this value is also defined in another module"), so
//! it runs in two steps:
//!
//! 1. [`ProjectRule::collect`] runs per file, alongside the normal rules, and
//!    returns [`Fact`]s. Facts depend only on that one file, so they are
//!    cached with the file's violations.
//! 2. [`ProjectRule::finish`] runs once per check over the facts of all files
//!    and turns them into violations. It is cheap and never cached, so editing
//!    one file updates the findings in every other file.
//!
//! `# noqa` and `per-file-ignores` act in step 1: a suppressed definition is
//! not collected, so it neither gets reported nor counts as a duplicate of
//! another one.

use super::FileContext;
use crate::types::Violation;
use bincode::{Decode, Encode};
use std::path::Path;

/// One piece of per-file information a project rule needs in its
/// [`ProjectRule::finish`] step, e.g. one constant definition.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Fact {
    /// Code of the rule that collected this fact (facts of all project rules
    /// are stored together).
    pub rule: String,
    /// Grouping key: facts with equal keys are compared with each other.
    pub key: String,
    /// The name the fact is about, e.g. the assigned variable.
    pub name: String,
    /// Short text describing the fact in messages, e.g. the assigned value.
    pub display: String,
    /// 1-based line and 0-based column of the start of the fact.
    pub line: u32,
    pub col: u32,
    /// 1-based line and 0-based column of the end of the fact.
    pub end_line: u32,
    pub end_col: u32,
}

/// A [`Fact`] together with the file it was collected from.
#[derive(Debug, Clone, Copy)]
pub struct FactRef<'a> {
    /// Path of the file, as displayed to the user.
    pub path: &'a Path,
    pub fact: &'a Fact,
}

/// The cross-file part of a rule. See the module documentation.
pub trait ProjectRule: Send + Sync {
    /// Collect the facts of one file, honoring `# noqa` and per-file ignores.
    fn collect(&self, ctx: &FileContext, cfg: &toml::Value) -> Vec<Fact>;

    /// Turn the facts of all files into violations. Each returned violation
    /// belongs to the file of `facts[index]`.
    fn finish(&self, facts: &[FactRef<'_>], cfg: &toml::Value) -> Vec<(usize, Violation)>;

    /// Extra paths, relative to the configuration directory, whose files are
    /// collected even when they are not part of the current run. Their facts
    /// take part in `finish`, but only the files of the run are reported.
    /// This keeps partial runs (pre-commit, a single file) from missing a
    /// duplicate whose other half is outside the run.
    fn paths(&self, _cfg: &toml::Value) -> Vec<String> {
        vec![]
    }
}
