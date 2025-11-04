use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOrigin {
    BuiltIn,
    RulePack { source: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,/÷÷/
    pub name: String,
    pub short_description: String,
    pub full_description: String,
    pub default_severity: Severity,
    pub origin: RuleOrigin,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirPackage {
    pub crate_name: String,
}

pub trait Rule: Send + Sync {
    fn metadata(&self) -> &RuleMetadata;
    fn evaluate(&self, package: &MirPackage) -> Vec<Finding>;

    fn cache_key(&self) -> String {
        serde_json::to_string(self.metadata()).unwrap_or_default()
    }
}

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn run(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            findings.extend(rule.evaluate(package));
        }
        findings
    }

    pub fn cache_fingerprint(&self) -> String {
        let mut joined = String::new();
        for rule in &self.rules {
            joined.push_str(&rule.cache_key());
            joined.push('\0');
        }
        joined
    }
}

pub struct BoxIntoRawRule {
    metadata: RuleMetadata,
}

impl BoxIntoRawRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA001".to_string(),
                name: "box-into-raw".to_string(),
                short_description: "Conversion of managed pointer into raw pointer".to_string(),
                full_description: "Detects conversions such as Box::into_raw".to_string(),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for BoxIntoRawRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        vec![Finding {
            rule_id: self.metadata.id.clone(),
            message: format!("evaluated crate {}", package.crate_name),
        }]
    }
}

pub fn run_rule(rule: &dyn Rule, package: &MirPackage) -> Vec<Finding> {
    rule.evaluate(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_serializes() {
        let rule = BoxIntoRawRule::new();
        let json = rule.cache_key();
        assert!(json.contains("box-into-raw"));
    }

    #[test]
    fn evaluate_returns_finding() {
        let rule = BoxIntoRawRule::new();
        let pkg = MirPackage {
            crate_name: "demo".to_string(),
        };
        let mut engine = RuleEngine::new();
        engine.register_rule(Box::new(rule));
        let findings = engine.run(&pkg);
        assert_eq!(findings.len(), 1);
    }
}
