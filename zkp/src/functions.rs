//! Predicate functions and the circuit inputs they fill.
//!
//! The set of predicates is open-ended (a predicate applies to any claim), so the generic layer is a registry, not a
//! field per predicate: adding a function is registering one, and nothing in [`crate::request::Request`] has to
//! learn about it. The registry is an ordinary value passed to the check, not global state, so two verifiers in one
//! process can know different vocabularies.

use std::collections::BTreeMap;

use siros_verifier_core::{Error, Result};

use crate::dates::Date;

pub const FUNCTION_AGE_CHECK: &str = "age_check";
pub const INPUT_EARLIEST: &str = "earliest";
pub const INPUT_CUTOFF: &str = "cutoff";

/// The bounds that DISABLE an age check (SPEC section 3). Sentinels rather than absent values, because the circuit
/// takes both bounds every time.
pub const NO_LOWER_BOUND: &str = "0000-00-00";
pub const NO_UPPER_BOUND: &str = "9999-12-31";

/// The shortest span between two set bounds, counted inclusively. A narrower window identifies a birth date instead
/// of checking an age: a one-day window is a birth-date oracle the verifier could walk.
pub const MINIMUM_RANGE_DAYS: i64 = 365;

/// Validates one function's own values.
pub type ValueCheck = fn(&BTreeMap<String, Vec<u8>>) -> Result<()>;

/// One predicate's contribution to a circuit request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitInput {
    pub function_id: String,
    pub values: BTreeMap<String, Vec<u8>>,
}

/// A predicate function this verifier can express.
#[derive(Clone)]
pub struct Function {
    pub id: String,
    /// The circuit input names this function fills: exactly these, no more and no fewer.
    pub inputs: Vec<String>,
    /// Validates this function's own values, which the generic layer cannot (it does not know "earliest" is a date).
    pub check: Option<ValueCheck>,
    /// A privacy floor this function imposes on its own parameters, in words.
    pub minimum_selectivity: Option<String>,
}

#[derive(Clone)]
pub struct FunctionRegistry {
    functions: BTreeMap<String, Function>,
}

impl FunctionRegistry {
    pub fn empty() -> Self {
        Self {
            functions: BTreeMap::new(),
        }
    }

    /// The vocabulary rulebook v0.4 defines: `age_check`.
    pub fn with_builtins() -> Self {
        let mut r = Self::empty();
        r.register(Function {
            id: FUNCTION_AGE_CHECK.into(),
            inputs: vec![INPUT_EARLIEST.into(), INPUT_CUTOFF.into()],
            check: Some(check_age_check_values),
            minimum_selectivity: Some(
                "the range between a set earliest and cutoff birth date is at least 365 days"
                    .into(),
            ),
        })
        .expect("builtin is valid");
        r
    }

    /// Add a function. Re-registering an id replaces it.
    pub fn register(&mut self, f: Function) -> Result<()> {
        if f.id.is_empty() {
            return Err(Error::Policy("a predicate function needs an id".into()));
        }
        if f.inputs.is_empty() {
            return Err(Error::Policy(format!(
                "function {:?} fills no circuit inputs",
                f.id
            )));
        }
        self.functions.insert(f.id.clone(), f);
        Ok(())
    }

    pub fn lookup(&self, id: &str) -> Option<&Function> {
        self.functions.get(id)
    }

    pub fn ids(&self) -> Vec<&str> {
        self.functions.keys().map(String::as_str).collect()
    }

    /// Refuse an input that does not fill exactly what its function declares.
    pub fn check_input(&self, input: &CircuitInput) -> Result<()> {
        let f = self.lookup(&input.function_id).ok_or_else(|| {
            Error::Policy(format!(
                "{:?} is not a registered predicate function; registered: {:?}",
                input.function_id,
                self.ids()
            ))
        })?;
        for name in &f.inputs {
            if input.values.get(name).is_none_or(Vec::is_empty) {
                return Err(Error::Policy(format!(
                    "function {:?} leaves circuit input {name:?} unset",
                    input.function_id
                )));
            }
        }
        if let Some(check) = f.check {
            check(&input.values)
                .map_err(|e| Error::Policy(format!("function {:?}: {e}", input.function_id)))?;
        }
        for name in input.values.keys() {
            if !f.inputs.contains(name) {
                // A value no circuit reads: the request would mean something other than it appears to.
                return Err(Error::Policy(format!(
                    "function {:?} sets {name:?}, which it does not fill",
                    input.function_id
                )));
            }
        }
        Ok(())
    }
}

/// The circuits' E and C: the earliest and cutoff birth dates, as `YYYY-MM-DD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeBounds {
    pub earliest: String,
    pub cutoff: String,
}

/// The rulebook's `age_check` parameters. Each bound is a `YYYY-MM-DD` date or absent. Exactly the four comparisons
/// the rulebook defines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgeCheck {
    /// Born on or after (inclusive lower bound).
    pub ge: Option<String>,
    /// Born after (one day later than `ge`).
    pub gt: Option<String>,
    /// Born on or before (inclusive upper bound).
    pub le: Option<String>,
    /// Born before (one day earlier than `le`).
    pub lt: Option<String>,
}

impl AgeCheck {
    /// Map to the circuits' inclusive bounds. The circuits compare inclusively, so the exclusive forms shift by a day:
    /// passing them unchanged would widen the window by a day at each end, which is a wrong answer for everyone born
    /// on the boundary.
    pub fn bounds(&self) -> Result<AgeBounds> {
        if self.ge.is_some() && self.gt.is_some() {
            return Err(Error::Policy(
                "age_check sets both ge and gt; they are two spellings of one lower bound".into(),
            ));
        }
        if self.le.is_some() && self.lt.is_some() {
            return Err(Error::Policy(
                "age_check sets both le and lt; they are two spellings of one upper bound".into(),
            ));
        }
        let mut earliest = NO_LOWER_BOUND.to_owned();
        let mut cutoff = NO_UPPER_BOUND.to_owned();
        if let Some(d) = &self.ge {
            Date::parse(d, "ge")?;
            earliest = d.clone();
        } else if let Some(d) = &self.gt {
            earliest = Date::parse(d, "gt")?.shifted(1, "gt", d)?;
        }
        if let Some(d) = &self.le {
            Date::parse(d, "le")?;
            cutoff = d.clone();
        } else if let Some(d) = &self.lt {
            cutoff = Date::parse(d, "lt")?.shifted(-1, "lt", d)?;
        }
        let b = AgeBounds { earliest, cutoff };
        b.check_range()?;
        Ok(b)
    }
}

impl AgeBounds {
    /// The minimum span applies only when BOTH bounds are set: one bound alone reveals only which side of a date the
    /// subject falls on, while the pair narrows a birth date to a window.
    fn check_range(&self) -> Result<()> {
        if self.earliest == NO_LOWER_BOUND || self.cutoff == NO_UPPER_BOUND {
            return Ok(());
        }
        let e = Date::parse(&self.earliest, "the earliest birth date")?.to_days();
        let c = Date::parse(&self.cutoff, "the cutoff birth date")?.to_days();
        if c <= e {
            return Err(Error::Policy(format!(
                "the cutoff birth date {} is not after the earliest {}, so no birth date satisfies the request",
                self.cutoff, self.earliest
            )));
        }
        let days = c - e + 1;
        if days < MINIMUM_RANGE_DAYS {
            return Err(Error::Policy(format!(
                "the age range {}..{} spans {days} days; the rulebook requires at least {MINIMUM_RANGE_DAYS}, because \
                 a narrower window identifies a birth date rather than checking an age",
                self.earliest, self.cutoff
            )));
        }
        Ok(())
    }

    pub fn circuit_input(&self) -> CircuitInput {
        CircuitInput {
            function_id: FUNCTION_AGE_CHECK.into(),
            values: BTreeMap::from([
                (
                    INPUT_EARLIEST.to_owned(),
                    self.earliest.clone().into_bytes(),
                ),
                (INPUT_CUTOFF.to_owned(), self.cutoff.clone().into_bytes()),
            ]),
        }
    }
}

/// Validates an `age_check` contribution built by hand rather than through [`AgeCheck::bounds`]. The sentinels are
/// the one exception to "is a date": they are how "no bound" is spelled.
fn check_age_check_values(values: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let get = |k: &str| {
        String::from_utf8_lossy(values.get(k).map_or(&[][..], Vec::as_slice)).into_owned()
    };
    for (input, sentinel) in [
        (INPUT_EARLIEST, NO_LOWER_BOUND),
        (INPUT_CUTOFF, NO_UPPER_BOUND),
    ] {
        let v = get(input);
        if v != sentinel {
            Date::parse(&v, input)?;
        }
    }
    AgeBounds {
        earliest: get(INPUT_EARLIEST),
        cutoff: get(INPUT_CUTOFF),
    }
    .check_range()
}
