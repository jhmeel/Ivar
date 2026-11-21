//! Minting, attesting, narrowing and verifying intent tokens.

use super::chains::chain_for;
use biscuit_auth::builder::{Algorithm, AuthorizerBuilder, BlockBuilder};
use biscuit_auth::datalog::RunLimits;
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey, ThirdPartyRequest};
use ivar_contracts::IntentClaims;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum IntentError {
    #[error("no intent token presented")]
    Missing,
    #[error("unknown action {0}")]
    UnknownAction(String),
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("intent chain refused: {0}")]
    Refused(String),
    #[error("token revoked")]
    Revoked,
    #[error("intent already used")]
    Replayed,
}

/// Bounds for one authorization. Facts and iterations are the deterministic
/// bounds; the time limit only stops a pathological token and is generous
/// enough for a cold WebAssembly start.
const AUTHORIZER_LIMITS: RunLimits = RunLimits { max_facts: 1000, max_iterations: 100, max_time: std::time::Duration::from_millis(100) };

fn malformed(e: impl std::fmt::Display) -> IntentError {
    IntentError::Malformed(e.to_string())
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.:@/".contains(c) || c == '-')
}

fn ed_keypair(seed: &[u8; 32]) -> Result<KeyPair, IntentError> {
    let pk = PrivateKey::from_bytes(seed, Algorithm::Ed25519).map_err(malformed)?;
    Ok(KeyPair::from(&pk))
}

/// Mints tokens where the intent starts (the origin step).
pub struct IntentIssuer {
    root: KeyPair,
}

impl IntentIssuer {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, IntentError> {
        Ok(IntentIssuer { root: ed_keypair(seed)? })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.root.public().to_bytes())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &self,
        intent_id: &str,
        action: &str,
        subject: &str,
        limits: &BTreeMap<String, i64>,
        expiry_ms: i64,
    ) -> Result<String, IntentError> {
        let chain = chain_for(action).ok_or_else(|| IntentError::UnknownAction(action.into()))?;
        for s in [intent_id, action, subject] {
            if !valid_ident(s) {
                return Err(malformed(format!("invalid identifier {s:?}")));
            }
        }
        let mut code = format!(
            "intent_id({intent_id:?});\nintent({action:?});\nallowed_action({action:?});\nsubject({subject:?});\nstep({origin:?});\nexpires({expiry_ms});\n\
             check if now_ms($t), $t <= {expiry_ms};\n\
             check if action($a), allowed_action($a);\n\
             check if request_subject($s), subject($s);\n",
            origin = chain.steps[0]
        );
        for (name, limit) in limits {
            if !valid_ident(name) {
                return Err(malformed(format!("invalid limit name {name:?}")));
            }
            code.push_str(&format!("limit({name:?}, {limit});\ncheck if measure({name:?}, $x), $x <= {limit};\n"));
        }
        let token = Biscuit::builder().code(&code).map_err(malformed)?.build(&self.root).map_err(malformed)?;
        token.to_base64().map_err(malformed)
    }
}

/// What a narrowing step may tighten. Each field can only make the token smaller.
#[derive(Debug, Clone, Default)]
pub struct Narrowing {
    pub max: BTreeMap<String, i64>,
    pub expiry_ms: Option<i64>,
}

impl Narrowing {
    fn code(&self) -> Result<String, IntentError> {
        let mut code = String::new();
        for (name, limit) in &self.max {
            if !valid_ident(name) {
                return Err(malformed(format!("invalid limit name {name:?}")));
            }
            code.push_str(&format!("check if measure({name:?}, $x), $x <= {limit};\n"));
        }
        if let Some(e) = self.expiry_ms {
            code.push_str(&format!("check if now_ms($t), $t <= {e};\n"));
        }
        Ok(code)
    }
}

/// A later step in the chain (session, ledger, payout instruction ...). It
/// attests with its own key, so the chain cannot be forged by the holder.
pub struct StepAttestor {
    pub step: String,
    key: KeyPair,
}

impl StepAttestor {
    pub fn from_seed(step: &str, seed: &[u8; 32]) -> Result<Self, IntentError> {
        Ok(StepAttestor { step: step.into(), key: ed_keypair(seed)? })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.public().to_bytes())
    }

    /// Append this step's attestation, optionally narrowing further.
    pub fn attest(&self, token_b64: &str, root_public_hex: &str, narrowing: &Narrowing) -> Result<String, IntentError> {
        let root = PublicKey::from_bytes_hex(root_public_hex, Algorithm::Ed25519).map_err(malformed)?;
        let token = Biscuit::from_base64(token_b64, root).map_err(malformed)?;
        let req: ThirdPartyRequest = token.third_party_request().map_err(malformed)?;
        let code = format!("step({:?});\n{}", self.step, narrowing.code()?);
        let block = req.create_block(&self.key.private(), BlockBuilder::new().code(&code).map_err(malformed)?).map_err(malformed)?;
        token.append_third_party(self.key.public(), block).map_err(malformed)?.to_base64().map_err(malformed)
    }
}

/// Narrow a token without a step key (any holder may narrow, none may widen).
pub fn narrow(token_b64: &str, root_public_hex: &str, narrowing: &Narrowing) -> Result<String, IntentError> {
    let root = PublicKey::from_bytes_hex(root_public_hex, Algorithm::Ed25519).map_err(malformed)?;
    let token = Biscuit::from_base64(token_b64, root).map_err(malformed)?;
    token
        .append(BlockBuilder::new().code(narrowing.code()?).map_err(malformed)?)
        .map_err(malformed)?
        .to_base64()
        .map_err(malformed)
}

pub struct VerifyRequest<'a> {
    pub token: Option<&'a str>,
    pub action: &'a str,
    pub subject: &'a str,
    pub measures: &'a BTreeMap<String, i64>,
    pub now_ms: i64,
}

/// Verifies tokens at the point of action.
pub struct IntentVerifier {
    root_public_hex: String,
    /// Step name to the public key that must attest it.
    step_keys: BTreeMap<String, String>,
    revoked: BTreeSet<String>,
    consumed: BTreeSet<String>,
    last_intent_id: Option<String>,
}

impl IntentVerifier {
    pub fn new(root_public_hex: &str, step_keys: BTreeMap<String, String>) -> Self {
        IntentVerifier { root_public_hex: root_public_hex.into(), step_keys, revoked: BTreeSet::new(), consumed: BTreeSet::new(), last_intent_id: None }
    }

    pub fn revoke(&mut self, revocation_id_hex: &str) {
        self.revoked.insert(revocation_id_hex.into());
    }

    /// Verify and, on success, mark the intent as used (one action per intent).
    pub fn verify_and_consume(&mut self, r: &VerifyRequest) -> Result<IntentClaims, IntentError> {
        let claims = self.verify(r)?;
        let key = format!("{}:{}", r.action, self.last_intent_id.take().unwrap_or_default());
        if !self.consumed.insert(key) {
            return Err(IntentError::Replayed);
        }
        Ok(claims)
    }

    pub fn verify(&mut self, r: &VerifyRequest) -> Result<IntentClaims, IntentError> {
        let token_b64 = r.token.filter(|t| !t.is_empty()).ok_or(IntentError::Missing)?;
        let chain = chain_for(r.action).ok_or_else(|| IntentError::UnknownAction(r.action.into()))?;
        if !valid_ident(r.subject) {
            return Err(malformed("invalid subject"));
        }
        let root = PublicKey::from_bytes_hex(&self.root_public_hex, Algorithm::Ed25519).map_err(malformed)?;
        let token = Biscuit::from_base64(token_b64, root).map_err(malformed)?;
        for id in token.revocation_identifiers() {
            if self.revoked.contains(&hex::encode(id)) {
                return Err(IntentError::Revoked);
            }
        }
        let mut code = format!(
            "now_ms({});\naction({:?});\nrequest_subject({:?});\ncheck if intent({:?});\n",
            r.now_ms, r.action, r.subject, r.action
        );
        for (name, v) in r.measures {
            if !valid_ident(name) {
                return Err(malformed("invalid measure"));
            }
            code.push_str(&format!("measure({name:?}, {v});\n"));
        }
        for step in &chain.steps[1..] {
            let key = self
                .step_keys
                .get(*step)
                .ok_or_else(|| IntentError::Refused(format!("no key registered for step {step}")))?;
            code.push_str(&format!("check if step({step:?}) trusting ed25519/{key};\n"));
        }
        code.push_str("allow if true;\n");
        let mut authz = AuthorizerBuilder::new().code(&code).map_err(malformed)?.set_limits(AUTHORIZER_LIMITS).build(&token).map_err(malformed)?;
        authz.authorize().map_err(|e| IntentError::Refused(format!("{e:?}")))?;

        let ids: Vec<(String,)> = authz.query("data($i) <- intent_id($i)").map_err(malformed)?;
        let subject: Vec<(String,)> = authz.query("data($s) <- subject($s)").map_err(malformed)?;
        let limits: Vec<(String, i64)> = authz.query("data($n, $v) <- limit($n, $v)").map_err(malformed)?;
        let expires: Vec<(i64,)> = authz.query("data($e) <- expires($e)").map_err(malformed)?;
        self.last_intent_id = ids.first().map(|i| i.0.clone());
        Ok(IntentClaims {
            intent_type: r.action.into(),
            chain: chain.steps.iter().map(|s| s.to_string()).collect(),
            allowed_action: r.action.into(),
            limits: limits.into_iter().map(|(n, v)| (n, v as f64)).collect(),
            expiry: expires.first().map(|e| e.0).unwrap_or(0),
            subject: subject.first().map(|s| s.0.clone()).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        issuer: IntentIssuer,
        session: StepAttestor,
        ledger: StepAttestor,
        instruction: StepAttestor,
        verifier: IntentVerifier,
    }

    fn fixture() -> Fixture {
        let issuer = IntentIssuer::from_seed(&[1; 32]).unwrap();
        let session = StepAttestor::from_seed("authenticated_session", &[2; 32]).unwrap();
        let ledger = StepAttestor::from_seed("ledger_entry", &[3; 32]).unwrap();
        let instruction = StepAttestor::from_seed("payout_instruction", &[4; 32]).unwrap();
        let keys = [&session, &ledger, &instruction].iter().map(|s| (s.step.clone(), s.public_key_hex())).collect();
        let verifier = IntentVerifier::new(&issuer.public_key_hex(), keys);
        Fixture { issuer, session, ledger, instruction, verifier }
    }

    fn full_chain(f: &Fixture, amount_limit: i64) -> String {
        let limits = [("amount".to_string(), amount_limit)].into_iter().collect();
        let t = f.issuer.mint("int_1", "payout", "ses_7f3a", &limits, 10_000).unwrap();
        let root = f.issuer.public_key_hex();
        let t = f.session.attest(&t, &root, &Narrowing::default()).unwrap();
        let t = f.ledger.attest(&t, &root, &Narrowing { max: [("amount".into(), 2_500)].into_iter().collect(), expiry_ms: None }).unwrap();
        f.instruction.attest(&t, &root, &Narrowing::default()).unwrap()
    }

    fn req<'a>(token: Option<&'a str>, amount: &'a BTreeMap<String, i64>, now: i64) -> VerifyRequest<'a> {
        VerifyRequest { token, action: "payout", subject: "ses_7f3a", measures: amount, now_ms: now }
    }

    fn amount(v: i64) -> BTreeMap<String, i64> {
        [("amount".to_string(), v)].into_iter().collect()
    }

    #[test]
    fn full_chain_verifies_within_limits() {
        let mut f = fixture();
        let t = full_chain(&f, 5_000);
        let c = f.verifier.verify(&req(Some(&t), &amount(2_000), 100)).unwrap();
        assert_eq!(c.chain.len(), 4);
        assert_eq!(c.limits["amount"], 5_000.0);
        assert_eq!(c.subject, "ses_7f3a");
    }

    #[test]
    fn stolen_credential_without_chain_is_refused() {
        let mut f = fixture();
        assert_eq!(f.verifier.verify(&req(None, &amount(1), 1)), Err(IntentError::Missing));
        let limits = [("amount".to_string(), 5_000)].into_iter().collect();
        let origin_only = f.issuer.mint("int_2", "payout", "ses_7f3a", &limits, 10_000).unwrap();
        assert!(matches!(f.verifier.verify(&req(Some(&origin_only), &amount(1), 1)), Err(IntentError::Refused(_))));
    }

    #[test]
    fn narrowing_cannot_be_widened_and_expiry_holds() {
        let mut f = fixture();
        let t = full_chain(&f, 5_000);
        assert!(f.verifier.verify(&req(Some(&t), &amount(3_000), 1)).is_err(), "ledger narrowed to 2500");
        let wider = narrow(&t, &f.issuer.public_key_hex(), &Narrowing { max: amount(1_000_000), expiry_ms: Some(99_999_999) }).unwrap();
        assert!(f.verifier.verify(&req(Some(&wider), &amount(3_000), 1)).is_err());
        assert!(f.verifier.verify(&req(Some(&t), &amount(100), 20_000)).is_err(), "expired");
    }

    #[test]
    fn wrong_subject_or_action_or_forged_step_is_refused() {
        let mut f = fixture();
        let t = full_chain(&f, 5_000);
        let a = amount(1);
        let other = VerifyRequest { token: Some(&t), action: "payout", subject: "ses_attacker", measures: &a, now_ms: 1 };
        assert!(f.verifier.verify(&other).is_err());
        let forger = StepAttestor::from_seed("ledger_entry", &[9; 32]).unwrap();
        let limits = [("amount".to_string(), 5_000)].into_iter().collect();
        let root = f.issuer.public_key_hex();
        let t2 = f.issuer.mint("int_3", "payout", "ses_7f3a", &limits, 10_000).unwrap();
        let t2 = f.session.attest(&t2, &root, &Narrowing::default()).unwrap();
        let t2 = forger.attest(&t2, &root, &Narrowing::default()).unwrap();
        let t2 = f.instruction.attest(&t2, &root, &Narrowing::default()).unwrap();
        assert!(f.verifier.verify(&req(Some(&t2), &a, 1)).is_err());
    }

    #[test]
    fn one_action_per_intent() {
        let mut f = fixture();
        let t = full_chain(&f, 5_000);
        let a = amount(10);
        assert!(f.verifier.verify_and_consume(&req(Some(&t), &a, 1)).is_ok());
        assert_eq!(f.verifier.verify_and_consume(&req(Some(&t), &a, 2)), Err(IntentError::Replayed));
    }
}
