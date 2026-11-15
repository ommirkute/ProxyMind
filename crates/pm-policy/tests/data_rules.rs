//! Defaults of the `data` section of the rules of engagement.

use pm_policy::Roe;

const SCOPE: &str = "version: 1\nscope:\n  include: [\"http://shop.test/\"]\n";

#[test]
fn cloud_models_are_allowed_and_secrets_redacted_by_default() {
    let roe = Roe::parse(SCOPE).unwrap();
    assert!(roe.data.allow_cloud_models, "most people use a cloud model, so it is on unless the ROE says no");
    assert!(roe.data.redact_before_llm);
    let roe = Roe::parse(&format!("{SCOPE}data:\n  redact_before_llm: true\n")).unwrap();
    assert!(roe.data.allow_cloud_models, "a data section that does not mention it keeps the default");
}

#[test]
fn an_engagement_can_keep_its_data_on_the_machine() {
    let roe = Roe::parse(&format!("{SCOPE}data:\n  allow_cloud_models: false\n")).unwrap();
    assert!(!roe.data.allow_cloud_models);
    assert!(roe.data.redact_before_llm);
}
