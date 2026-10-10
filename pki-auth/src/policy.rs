//! Conservative admission bounds for native Biscuit evaluation.
//!
//! Biscuit's timeout is cooperative between complete queries/iterations. Do
//! not admit user-controlled joins, fact generation, or expanding expressions
//! and rely on that timeout to interrupt them. Authorization remains native.
use biscuit_auth::{
    builder::{Binary, BlockBuilder, Op, Predicate, Term, Unary},
    datalog::SymbolTable,
    format::schema,
};
use prost::Message;

use crate::{AuthError, Result, biscuit::required_checks};

const MAX_FACTS: usize = 512;
const MAX_CUSTOM_QUERIES: usize = 64;
const MAX_CUSTOM_WORK: usize = 4096;
const MAX_EXPRESSION_OPS: usize = 16;
const MAX_TERMS: usize = 8;
const MAX_NAME_BYTES: usize = 128;
pub(crate) const MAX_TERM_BYTES: usize = 1024;
const AMBIENT_FACTS: usize = 7;
// Bound materialization before Biscuit expands interned references into owned
// strings. The canonical profile has eleven queries per block (five checks).
const MAX_SERIALIZED_ITEMS: usize = 4096;
const NATIVE_QUERIES_PER_BLOCK: usize = 11;

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

pub(crate) fn validate_serialized_policy(encoded: &[u8]) -> Result<()> {
    let container = schema::Biscuit::decode(encoded).map_err(|_| AuthError::InvalidGrant)?;
    let (mut items, mut facts, mut queries) = (0, 0, 0);
    for (index, signed) in std::iter::once(&container.authority)
        .chain(&container.blocks)
        .enumerate()
    {
        // Every appended v2 block must be externally signed, so it has its own
        // symbol table; unsigned blocks must not grow the authority table.
        if index > 0 && signed.external_signature.is_none() {
            return Err(AuthError::Delegation);
        }
        let block =
            schema::Block::decode(signed.block.as_slice()).map_err(|_| AuthError::InvalidGrant)?;
        validate_raw_block(&block, &mut items, &mut facts, &mut queries)?;
    }
    Ok(())
}

fn raw_scalar(term: &schema::Term, variables: bool, symbols: &SymbolTable) -> bool {
    use schema::term::Content;
    match &term.content {
        Some(Content::Integer(_) | Content::Date(_) | Content::Bool(_) | Content::Null(_)) => true,
        Some(Content::String(id)) => symbols
            .get_symbol(*id)
            .is_some_and(|symbol| symbol.len() <= MAX_TERM_BYTES),
        Some(Content::Bytes(bytes)) => bytes.len() <= MAX_TERM_BYTES,
        Some(Content::Variable(id)) => {
            variables
                && symbols
                    .get_symbol(u64::from(*id))
                    .is_some_and(|name| name.len() <= MAX_NAME_BYTES)
        }
        _ => false,
    }
}
fn raw_predicate(predicate: &schema::Predicate, variables: bool, symbols: &SymbolTable) -> bool {
    symbols
        .get_symbol(predicate.name)
        .is_some_and(|name| name.len() <= MAX_NAME_BYTES)
        && predicate.terms.len() <= MAX_TERMS
        && predicate
            .terms
            .iter()
            .all(|term| raw_scalar(term, variables, symbols))
}
fn raw_scopes(scopes: &[schema::Scope]) -> bool {
    scopes.len() <= 2
        && scopes.iter().all(|scope| {
            matches!(
                scope.content,
                Some(schema::scope::Content::ScopeType(0 | 1))
            )
        })
}
fn validate_raw_block(
    block: &schema::Block,
    items: &mut usize,
    facts: &mut usize,
    queries: &mut usize,
) -> Result<()> {
    if !block.rules.is_empty()
        || block
            .symbols
            .iter()
            .any(|symbol| symbol.len() > MAX_TERM_BYTES)
        || !raw_scopes(&block.scope)
    {
        return Err(AuthError::InvalidGrant);
    }
    // One copy of the compact table is bounded by the encoded-token limit.
    // All per-reference name/value lookups below borrow instead of cloning.
    let symbols = SymbolTable::from(block.symbols.clone()).map_err(|_| AuthError::InvalidGrant)?;
    *facts += block.facts.len();
    if *facts > MAX_FACTS {
        return Err(AuthError::InvalidGrant);
    }
    *items += block.scope.len();
    for fact in &block.facts {
        if !raw_predicate(&fact.predicate, false, &symbols) {
            return Err(AuthError::InvalidGrant);
        }
        *items += 1 + fact.predicate.terms.len();
    }
    for check in &block.checks {
        if check.queries.is_empty() {
            return Err(AuthError::InvalidGrant);
        }
        *queries += check.queries.len();
        if *queries > crate::MAX_GRANT_BLOCKS * NATIVE_QUERIES_PER_BLOCK + MAX_CUSTOM_QUERIES {
            return Err(AuthError::InvalidGrant);
        }
        *items += 1;
        for query in &check.queries {
            let ops = query
                .expressions
                .iter()
                .map(|expression| expression.ops.len())
                .sum::<usize>();
            if query.body.len() > 2
                || !raw_predicate(&query.head, true, &symbols)
                || query
                    .body
                    .iter()
                    .any(|body| !raw_predicate(body, true, &symbols))
                || query.expressions.len() > MAX_EXPRESSION_OPS
                || ops > MAX_EXPRESSION_OPS
                || !raw_scopes(&query.scope)
                || query
                    .expressions
                    .iter()
                    .flat_map(|expression| &expression.ops)
                    .any(|op| match &op.content {
                        Some(schema::op::Content::Value(term)) => !raw_scalar(term, true, &symbols),
                        Some(schema::op::Content::Unary(_) | schema::op::Content::Binary(_)) => {
                            false
                        }
                        _ => true,
                    })
            {
                return Err(AuthError::InvalidGrant);
            }
            // Every expanded predicate name/term and expression value is
            // charged before any owned builder strings are constructed.
            *items += 2
                + query.head.terms.len()
                + query
                    .body
                    .iter()
                    .map(|body| 1 + body.terms.len())
                    .sum::<usize>()
                + 2 * ops
                + query.expressions.len()
                + query.scope.len();
        }
    }
    if *items > MAX_SERIALIZED_ITEMS {
        return Err(AuthError::InvalidGrant);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_term() -> schema::Term {
        schema::Term {
            content: Some(schema::term::Content::String(1025)),
        }
    }
    fn raw_block() -> schema::Block {
        schema::Block {
            symbols: vec!["item".into(), "x".repeat(MAX_TERM_BYTES)],
            ..Default::default()
        }
    }
    fn admitted(block: &schema::Block) -> Result<()> {
        validate_raw_block(block, &mut 0, &mut 0, &mut 0)
    }
    #[test]
    fn raw_symbol_budget_precedes_owned_string_conversion() {
        let mut block = raw_block();
        block.symbols[1].push('x');
        assert!(matches!(admitted(&block), Err(AuthError::InvalidGrant)));
    }
    #[test]
    fn raw_predicate_budget_precedes_repeated_symbol_expansion() {
        let mut block = raw_block();
        block.facts.push(schema::Fact {
            predicate: schema::Predicate {
                name: 1024,
                terms: vec![string_term(); MAX_TERMS + 1],
            },
        });
        assert!(matches!(admitted(&block), Err(AuthError::InvalidGrant)));
    }
    #[test]
    fn raw_conversion_item_budget_is_aggregate() {
        let mut block = raw_block();
        block.facts = vec![
            schema::Fact {
                predicate: schema::Predicate {
                    name: 1024,
                    terms: vec![string_term(); MAX_TERMS]
                }
            };
            MAX_FACTS
        ];
        assert!(matches!(admitted(&block), Err(AuthError::InvalidGrant)));
    }
    #[test]
    fn raw_predicate_names_are_bounded_before_conversion() {
        let mut block = raw_block();
        block.symbols[0] = "x".repeat(MAX_NAME_BYTES + 1);
        block.facts.push(schema::Fact {
            predicate: schema::Predicate {
                name: 1024,
                terms: vec![],
            },
        });
        assert!(matches!(admitted(&block), Err(AuthError::InvalidGrant)));
    }
    #[test]
    fn raw_variable_names_are_bounded_before_conversion() {
        let mut block = raw_block();
        block.symbols[1] = "x".repeat(MAX_NAME_BYTES + 1);
        block.checks.push(schema::Check {
            queries: vec![schema::Rule {
                head: schema::Predicate {
                    name: 27,
                    terms: vec![],
                },
                body: vec![schema::Predicate {
                    name: 1024,
                    terms: vec![schema::Term {
                        content: Some(schema::term::Content::Variable(1025)),
                    }],
                }],
                ..Default::default()
            }],
            kind: Some(0),
        });
        assert!(matches!(admitted(&block), Err(AuthError::InvalidGrant)));
    }
    #[test]
    fn raw_scalar_boundary_remains_admissible() {
        let mut block = raw_block();
        block.facts.push(schema::Fact {
            predicate: schema::Predicate {
                name: 1024,
                terms: vec![string_term(); MAX_TERMS],
            },
        });
        admitted(&block).unwrap();
    }
}
