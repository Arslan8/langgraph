use apf_policy_eval::{CedarEvaluator,PolicyRuleDoc,PolicyRuleRole,EvalInput,Evaluator};
use serde_json::json;
fn main(){
 let schema=r#"namespace APF {entity User; entity Tool; action "file::read" appliesTo {principal:[User],resource:[Tool],context:{args:{path:String}}};}"#;
 let grant=PolicyRuleDoc{name:"alice-read".into(),schema:Some(schema.into()),definition:r#"permit(principal,action == APF::Action::"file::read",resource) when {context.args.path == "/fixtures/alice" || context.args.path == "/fixtures/bob"};"#.into(),data:json!({}),role:PolicyRuleRole::Grant};
 let forbid=PolicyRuleDoc{name:"operator-forbid-bob".into(),schema:Some(schema.into()),definition:r#"forbid(principal,action,resource) when {context.args.path == "/fixtures/bob"};"#.into(),data:json!({}),role:PolicyRuleRole::Control};
 let ev=CedarEvaluator::from_policy_rules(&[grant,forbid],&[],&[],&[]).unwrap();
 for repeat in 0..20 {for (case,path,expected) in [("allowed","/fixtures/alice",true),("operator_forbid","/fixtures/bob",false),("no_grant","/fixtures/other",false)]{
 let input=EvalInput::for_tool_call(Some("file".into()),Some("read".into()),"alice".into(),json!({"path":path}).as_object().unwrap().clone());let result=ev.evaluate(input).unwrap();assert_eq!(result.allow,expected);println!("{}",json!({"case_id":case,"repeat":repeat,"mode":"APF official Cedar evaluator","allow":result.allow,"deny_reason":result.deny_reason,"expected":expected,"scope":"decision only; OpenShell runtime unavailable; no native effect claim"}));}}
}
