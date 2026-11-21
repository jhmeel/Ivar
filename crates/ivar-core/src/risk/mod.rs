//! Risk scoring (section 10.1).
//!
//! Each finding adds to the risk of every entity that acted in it. Risk
//! decays over time, so old evidence stops counting. For timescale k:
//!
//! R_e(k)(t) = 1 minus the product over rule families f of
//!             (1 minus max over findings i in f of c_i * w_i * 2^(-(t - t_i) / h_k))
//!
//! Three rules keep the score accurate under repeated or adversarial evidence:
//! group by rule family, score on two timescales, attribute evidence by role.

mod ledger;
mod score;

pub use ledger::{Contribution, EntityLedger};
pub use score::{family_score, RiskAssessment, RiskEngine};
