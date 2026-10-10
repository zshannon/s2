//! Conservative admission bounds for native Biscuit evaluation.
//!
//! Biscuit's timeout is cooperative between complete queries/iterations. Do
//! not admit user-controlled joins, fact generation, or expanding expressions
//! and rely on that timeout to interrupt them. Authorization remains native.
use biscuit_auth::builder::{Binary, BlockBuilder, Op, Predicate, Term, Unary};

use crate::{AuthError, Result, biscuit::required_checks};

const MAX_FACTS: usize = 512;
const MAX_CUSTOM_QUERIES: usize = 64;
const MAX_CUSTOM_WORK: usize = 4096;
const MAX_EXPRESSION_OPS: usize = 16;
const MAX_TERMS: usize = 8;
const MAX_NAME_BYTES: usize = 128;
pub(crate) const MAX_TERM_BYTES: usize = 1024;
const AMBIENT_FACTS: usize = 7;

fn scalar(term: &Term, variables: bool) -> bool {
    match term {
        Term::Integer(_) | Term::Date(_) | Term::Bool(_) | Term::Null => true,
        Term::Str(value) => value.len() <= MAX_TERM_BYTES,
        Term::Bytes(value) => value.len() <= MAX_TERM_BYTES,
        Term::Variable(name) => variables && name.len() <= MAX_NAME_BYTES,
        _ => false,
    }
}
fn predicate(predicate: &Predicate, variables: bool) -> bool {
    predicate.name.len() <= MAX_NAME_BYTES
        && predicate.terms.len() <= MAX_TERMS
        && predicate.terms.iter().all(|term| scalar(term, variables))
}
fn bounded_op(op: &Op) -> bool {
    match op {
        Op::Value(term) => scalar(term, true),
        Op::Unary(Unary::Negate | Unary::Parens | Unary::Length | Unary::TypeOf) => true,
        Op::Binary(
            Binary::LessThan
            | Binary::GreaterThan
            | Binary::LessOrEqual
            | Binary::GreaterOrEqual
            | Binary::Equal
            | Binary::NotEqual
            | Binary::HeterogeneousEqual
            | Binary::HeterogeneousNotEqual
            | Binary::Prefix
            | Binary::Suffix
            | Binary::And
            | Binary::Or,
        ) => true,
        _ => false,
    }
}

pub(crate) fn validate_policy_budget(blocks: &[BlockBuilder]) -> Result<()> {
    let facts = blocks.iter().map(|block| block.facts.len()).sum::<usize>();
    if facts > MAX_FACTS {
        return Err(AuthError::InvalidGrant);
    }
    let mut queries = 0usize;
    let mut work = 0usize;
    for (index, block) in blocks.iter().enumerate() {
        // No derivation means the literal facts plus the fixed ambient context
        // are the complete upper bound on facts an accepted query can visit.
        if !block.rules.is_empty()
            || block
                .facts
                .iter()
                .any(|fact| !predicate(&fact.predicate, false))
        {
            return Err(AuthError::InvalidGrant);
        }
        let required = required_checks(index)?.checks;
        if required.iter().any(|check| {
            block
                .checks
                .iter()
                .filter(|candidate| *candidate == check)
                .count()
                != 1
        }) {
            return Err(AuthError::InvalidGrant);
        }
        for check in &block.checks {
            if required.contains(check) {
                // These exact checks only join a singleton ambient fact with
                // indexed profile facts. Their count is fixed at five/block.
                continue;
            }
            if check.queries.is_empty() {
                return Err(AuthError::InvalidGrant);
            }
            for query in &check.queries {
                let ops = query
                    .expressions
                    .iter()
                    .map(|expression| expression.ops.len())
                    .sum::<usize>();
                if query.body.len() > 1
                    || !predicate(&query.head, true)
                    || query.body.iter().any(|body| !predicate(body, true))
                    || ops > MAX_EXPRESSION_OPS
                    || query
                        .expressions
                        .iter()
                        .flat_map(|expression| &expression.ops)
                        .any(|op| !bounded_op(op))
                {
                    return Err(AuthError::InvalidGrant);
                }
                queries += 1;
                // Count every possible fact visit and scalar expression step,
                // regardless of the query's origin filters or early success.
                let visits = if query.body.is_empty() {
                    1
                } else {
                    facts + AMBIENT_FACTS
                };
                let terms = query.body.first().map_or(0, |body| body.terms.len());
                work = work.saturating_add(visits.saturating_mul(1 + terms + ops));
                if queries > MAX_CUSTOM_QUERIES || work > MAX_CUSTOM_WORK {
                    return Err(AuthError::InvalidGrant);
                }
            }
        }
    }
    Ok(())
}
