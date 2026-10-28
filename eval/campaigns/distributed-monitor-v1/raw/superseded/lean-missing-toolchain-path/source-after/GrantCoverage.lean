import ReceiptCoverage

/-!
Grant-derived obligation inventory for the selected Linux profile. Raw identity
and exact typed conditions are checked; grant digest preimages, authorization,
lowering, signatures, freshness and Python/native correspondence are not proved.
-/
namespace GrantCoverage
open WorkerRoute

mutual
inductive Value where
  | null
  | bool (value : Bool)
  | int (value : Int)
  | text (value : String)
  | sequence (values : Values)
  | map (values : Entries)
  deriving DecidableEq, Repr
inductive Values where
  | nil
  | cons (head : Value) (tail : Values)
  deriving DecidableEq, Repr
inductive Entries where
  | nil
  | cons (key : String) (value : Value) (tail : Entries)
  deriving DecidableEq, Repr
end

inductive Domain where
  | filesystem | network | process | ipc | service | credential | runtime
  | delegation | resourceLimit
  deriving DecidableEq, Repr

inductive Requirement where
  | need | want
  deriving DecidableEq, Repr

inductive Kind where
  | operate | denyComplement | bypassPrevention | credentialCustody
  | authenticatedChannel | resourceLimit | evidence
  deriving DecidableEq, Repr

structure Rule where
  id : String
  domain : Domain
  operation : String
  selector : String
  conditions : Value
  requirement : Requirement
  provenance : List String
  baseline : Bool
  deriving DecidableEq, Repr

structure Grant where
  principal : String
  session : String
  tool : String
  artifact : String
  call : String
  intent : String
  policy : String
  deployment : String
  runtime : String
  digest : String
  rules : List Rule
  deriving DecidableEq, Repr

structure Obligation where
  id : String
  rule : String
  kind : Kind
  domain : Domain
  operation : String
  selector : String
  conditions : Value
  dependencies : List String
  waivable : Bool
  deriving DecidableEq, Repr

structure Certificate where
  grant : Grant
  obligations : List Obligation
  coverage : ReceiptCoverage.Certificate
  deriving DecidableEq, Repr

def domainName : Domain → String
  | .filesystem => "filesystem"
  | .network => "network"
  | .process => "process"
  | .ipc => "ipc"
  | .service => "service"
  | .credential => "credential"
  | .runtime => "runtime"
  | .delegation => "delegation"
  | .resourceLimit => "resource_limit"

def domains : List Domain :=
  [.filesystem, .network, .process, .ipc, .service, .credential, .runtime,
   .delegation, .resourceLimit]

def deriveRule (rule : Rule) : Obligation :=
  {id := "rule:" ++ rule.id ++ ":operate", rule := rule.id,
   kind := if rule.domain = .resourceLimit then .resourceLimit else .operate,
   domain := rule.domain, operation := rule.operation, selector := rule.selector,
   conditions := rule.conditions, dependencies := [],
   waivable := rule.requirement == .want && !rule.baseline}

def denyComplement (domain : Domain) : Obligation :=
  {id := "domain:" ++ domainName domain ++ ":deny_complement",
   rule := "domain:" ++ domainName domain, kind := .denyComplement,
   domain := domain, operation := "deny_unlisted", selector := "*",
   conditions := .map .nil, dependencies := [], waivable := false}

def generatedFromRules (rules : List Rule) : List Obligation :=
  rules.map deriveRule ++ domains.map denyComplement

def generated (grant : Grant) : List Obligation := generatedFromRules grant.rules

def isMap : Value → Bool
  | .map _ => true
  | _ => false

/-- The wire separately enforces canonical recursive map keys and bounds.
The model preserves all typed condition data without interpreting policy. -/
def RulesWellFormed (rules : List Rule) : Prop :=
  (rules.map Rule.id).Nodup ∧
  (∀ rule ∈ rules, rule.id ≠ "" ∧ rule.operation ≠ "" ∧ rule.selector ≠ "" ∧
    isMap rule.conditions = true) ∧
  ((generatedFromRules rules).map Obligation.id).Nodup

def ValidGrant (grant : Grant) : Prop :=
  grant.principal ≠ "" ∧ grant.session ≠ "" ∧ grant.tool ≠ "" ∧
  grant.artifact ≠ "" ∧ grant.call ≠ "" ∧ grant.intent ≠ "" ∧
  grant.policy ≠ "" ∧ grant.digest ≠ "" ∧ RulesWellFormed grant.rules

def GrantBound (binding : Binding) (grant : Grant) : Prop :=
  grant.principal = binding.principal ∧ grant.session = binding.session ∧
  grant.tool = binding.tool ∧ grant.artifact = binding.artifact ∧
  grant.call = binding.call ∧ grant.intent = binding.intent ∧
  grant.policy = binding.policy ∧ grant.deployment = binding.deployment ∧
  grant.runtime = binding.runtime ∧ grant.digest = binding.grant

/-- Full record equality, independent of inventory order; IDs alone do not suffice. -/
def ExactGenerated (grant : Grant) (obligations : List Obligation) : Prop :=
  (obligations.map Obligation.id).Nodup ∧
  (∀ row ∈ obligations, row ∈ generated grant) ∧
  (∀ row ∈ generated grant, row ∈ obligations)

instance (grant : Grant) (obligations : List Obligation) :
    Decidable (ValidGrant grant ∧ ExactGenerated grant obligations) := by
  unfold ValidGrant RulesWellFormed ExactGenerated
  infer_instance

def obligationsAccept (grant : Grant) (obligations : List Obligation) : Bool :=
  decide (ValidGrant grant ∧ ExactGenerated grant obligations)

def CompleteAssignments (certificate : Certificate) : Prop :=
  ReceiptCoverage.SameIDs
    (certificate.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation ++
      certificate.coverage.plan.waived)
    ((generated certificate.grant).map Obligation.id)

def Selected (certificate : Certificate) : Prop :=
  certificate.coverage.plan.waived = [] ∧
  certificate.coverage.plan.mode = .enforced ∧
  certificate.coverage.receipt.mode = .enforced

def ValidCertificate (binding : Binding) (certificate : Certificate) : Prop :=
  ValidGrant certificate.grant ∧ GrantBound binding certificate.grant ∧
  ExactGenerated certificate.grant certificate.obligations ∧
  CompleteAssignments certificate ∧ Selected certificate ∧
  ReceiptCoverage.BoundTo binding certificate.coverage ∧
  ReceiptCoverage.ValidCoverage certificate.coverage

instance (binding : Binding) (certificate : Certificate) :
    Decidable (ValidCertificate binding certificate) := by
  unfold ValidCertificate ValidGrant RulesWellFormed GrantBound ExactGenerated
    CompleteAssignments Selected
  infer_instance

def certificateValid (binding : Binding) (certificate : Certificate) : Bool :=
  decide (ValidCertificate binding certificate)

def runCertified (binding : Binding) (certificate : Certificate)
    (events : List Event) : State :=
  if certificateValid binding certificate then run binding events
  else ⟨binding, .refused⟩

def certifiedRoute (binding : Binding) (certificate : Certificate)
    (events : List Event) : Bool := allowsSuccess (runCertified binding certificate events)

theorem obligationsAccept_iff (grant : Grant) (obligations : List Obligation) :
    obligationsAccept grant obligations = true ↔
      ValidGrant grant ∧ ExactGenerated grant obligations := by
  simp [obligationsAccept]

theorem certificateValid_iff (binding : Binding) (certificate : Certificate) :
    certificateValid binding certificate = true ↔ ValidCertificate binding certificate := by
  simp [certificateValid]

theorem every_domain_present (domain : Domain) : domain ∈ domains := by
  cases domain <;> simp [domains]

theorem nine_distinct_complements :
    (domains.map denyComplement).length = 9 ∧
      ((domains.map denyComplement).map Obligation.id).Nodup := by
  decide

theorem generated_exact_origin (grant : Grant) (row : Obligation) :
    row ∈ generated grant ↔
      (∃ rule ∈ grant.rules, deriveRule rule = row) ∨
      (∃ domain : Domain, denyComplement domain = row) := by
  simp only [generated, generatedFromRules, List.mem_append, List.mem_map]
  constructor
  · intro h
    rcases h with h | ⟨domain, _, eq⟩
    · exact Or.inl h
    · exact Or.inr ⟨domain, eq⟩
  · intro h
    rcases h with h | ⟨domain, eq⟩
    · exact Or.inl h
    · exact Or.inr ⟨domain, every_domain_present domain, eq⟩

theorem generated_rule_present (grant : Grant) (rule : Rule)
    (present : rule ∈ grant.rules) : deriveRule rule ∈ generated grant :=
  (generated_exact_origin grant _).mpr (Or.inl ⟨rule, present, rfl⟩)

theorem generated_complement_present (grant : Grant) (domain : Domain) :
    denyComplement domain ∈ generated grant :=
  (generated_exact_origin grant _).mpr (Or.inr ⟨domain, rfl⟩)

theorem derived_rule_semantics (rule : Rule) :
    (deriveRule rule).id = "rule:" ++ rule.id ++ ":operate" ∧
    (deriveRule rule).rule = rule.id ∧
    (deriveRule rule).kind = (if rule.domain = .resourceLimit then .resourceLimit else .operate) ∧
    (deriveRule rule).domain = rule.domain ∧
    (deriveRule rule).operation = rule.operation ∧
    (deriveRule rule).selector = rule.selector ∧
    (deriveRule rule).conditions = rule.conditions ∧
    (deriveRule rule).dependencies = [] ∧
    (deriveRule rule).waivable = (rule.requirement == .want && !rule.baseline) := by
  simp [deriveRule]

private theorem unique_key {α : Type} {rows : List α} {key : α → String}
    (distinct : (rows.map key).Nodup) {left right : α}
    (leftMem : left ∈ rows) (rightMem : right ∈ rows)
    (same : key left = key right) : left = right := by
  induction rows generalizing left right with
  | nil => simp at leftMem
  | cons head tail ih =>
    have parts := List.nodup_cons.mp distinct
    rcases List.mem_cons.mp leftMem with leftEq | leftTail
    · rcases List.mem_cons.mp rightMem with rightEq | rightTail
      · exact leftEq.trans rightEq.symm
      · exact False.elim (parts.1 (List.mem_map.mpr
          ⟨right, rightTail, same.symm.trans (congrArg key leftEq)⟩))
    · rcases List.mem_cons.mp rightMem with rightEq | rightTail
      · exact False.elim (parts.1 (List.mem_map.mpr
          ⟨left, leftTail, same.trans (congrArg key rightEq)⟩))
      · exact ih parts.2 leftTail rightTail same

theorem no_missing_generated (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) (row : Obligation)
    (present : row ∈ generated grant) : row ∈ obligations :=
  ((obligationsAccept_iff grant obligations).mp accepted).2.2.2 row present

theorem no_extra_obligations (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) (row : Obligation)
    (present : row ∈ obligations) : row ∈ generated grant :=
  ((obligationsAccept_iff grant obligations).mp accepted).2.2.1 row present

theorem rule_covered_once (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) (rule : Rule)
    (present : rule ∈ grant.rules) :
    deriveRule rule ∈ obligations ∧
      ∀ other ∈ obligations, other.id = (deriveRule rule).id → other = deriveRule rule := by
  have member := no_missing_generated grant obligations accepted _
    (generated_rule_present grant rule present)
  exact ⟨member, fun other otherMem same =>
    unique_key ((obligationsAccept_iff _ _).mp accepted).2.1 otherMem member same⟩

theorem complement_covered_once (grant : Grant) (obligations : List Obligation)
    (accepted : obligationsAccept grant obligations = true) (domain : Domain) :
    denyComplement domain ∈ obligations ∧
      ∀ other ∈ obligations, other.id = (denyComplement domain).id →
        other = denyComplement domain := by
  have member := no_missing_generated grant obligations accepted _
    (generated_complement_present grant domain)
  exact ⟨member, fun other otherMem same =>
    unique_key ((obligationsAccept_iff _ _).mp accepted).2.1 otherMem member same⟩

theorem semantic_substitution_refuses (grant : Grant) (obligations : List Obligation)
    (original replacement : Obligation) (originalMem : original ∈ generated grant)
    (replacementMem : replacement ∈ obligations) (sameID : replacement.id = original.id)
    (changed : replacement ≠ original) : obligationsAccept grant obligations = false := by
  cases accepted : obligationsAccept grant obligations with
  | false => rfl
  | true =>
    have member := no_missing_generated grant obligations accepted original originalMem
    exact False.elim (changed (unique_key
      ((obligationsAccept_iff _ _).mp accepted).2.1 replacementMem member sameID))

theorem missing_generated_refuses (grant : Grant) (obligations : List Obligation)
    (row : Obligation) (present : row ∈ generated grant) (missing : row ∉ obligations) :
    obligationsAccept grant obligations = false := by
  cases accepted : obligationsAccept grant obligations with
  | false => rfl
  | true => exact False.elim (missing (no_missing_generated _ _ accepted row present))

theorem exact_generated_useful (grant : Grant) (valid : ValidGrant grant) :
    obligationsAccept grant (generated grant) = true := by
  apply (obligationsAccept_iff _ _).mpr
  exact ⟨valid, valid.2.2.2.2.2.2.2.2.2.2, fun _ h => h, fun _ h => h⟩

theorem certificate_inventory_accepted (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) :
    obligationsAccept certificate.grant certificate.obligations = true := by
  have valid := (certificateValid_iff _ _).mp accepted
  exact (obligationsAccept_iff _ _).mpr ⟨valid.1, valid.2.2.1⟩

theorem grant_binding_mismatch_refuses (binding : Binding) (certificate : Certificate)
    (mismatch : ¬ GrantBound binding certificate.grant) :
    certificateValid binding certificate = false := by
  simp [certificateValid, ValidCertificate, mismatch]

theorem assignment_inventory_exact (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) (id : String) :
    id ∈ certificate.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation ↔
      id ∈ (generated certificate.grant).map Obligation.id := by
  have valid := (certificateValid_iff _ _).mp accepted
  have complete := valid.2.2.2.1
  have selected := valid.2.2.2.2.1
  have exactIDs : ReceiptCoverage.SameIDs
      (certificate.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation)
      ((generated certificate.grant).map Obligation.id) := by
    simpa [CompleteAssignments, selected.1] using complete
  exact ⟨exactIDs.1 id, exactIDs.2 id⟩

theorem selected_no_waivers (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) :
    certificate.coverage.plan.waived = [] ∧
    certificate.coverage.plan.mode = .enforced ∧
    certificate.coverage.receipt.mode = .enforced :=
  ((certificateValid_iff _ _).mp accepted).2.2.2.2.1

theorem certificate_implies_receipt (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) :
    ReceiptCoverage.certificateValid binding certificate.coverage = true :=
  (ReceiptCoverage.certificateValid_iff _ _).mpr
    ((certificateValid_iff _ _).mp accepted).2.2.2.2.2

theorem certificate_preserves_grant_identity (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) :
    GrantBound binding certificate.grant :=
  ((certificateValid_iff _ _).mp accepted).2.1

theorem invalid_inventory_refuses (binding : Binding) (certificate : Certificate)
    (invalid : obligationsAccept certificate.grant certificate.obligations = false) :
    certificateValid binding certificate = false := by
  cases accepted : certificateValid binding certificate with
  | false => rfl
  | true =>
    have inventory := certificate_inventory_accepted binding certificate accepted
    simp [invalid] at inventory

/-- Activated IDs cover precisely the generated inventory, without trusting the
receipt's supplied activated array as an independent source of obligations. -/
theorem activated_inventory_exact (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) (id : String) :
    id ∈ certificate.coverage.receipt.activated ↔
      id ∈ (generated certificate.grant).map Obligation.id := by
  have receipt := (ReceiptCoverage.certificateValid_iff _ _).mp
    (certificate_implies_receipt binding certificate accepted)
  have coverage := (ReceiptCoverage.coverageAccept_iff _).mpr receipt.2
  constructor
  · intro present
    exact (assignment_inventory_exact binding certificate accepted id).mp
      (ReceiptCoverage.no_extra_activated_obligations _ coverage id present)
  · intro present
    have assigned := (assignment_inventory_exact binding certificate accepted id).mpr present
    rcases List.mem_map.mp assigned with ⟨assignment, member, identity⟩
    exact identity ▸ ReceiptCoverage.no_missing_activated_obligations _ coverage assignment member

theorem generated_evidence_owner_unique (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) (row : Obligation)
    (present : row ∈ generated certificate.grant) :
    ∃ assignment ∈ certificate.coverage.plan.assignments,
      assignment.obligation = row.id ∧
      ∃ evidence ∈ certificate.coverage.receipt.evidence,
        row.id ∈ evidence.obligations ∧ evidence.adapter = assignment.adapter ∧
        evidence.context = certificate.coverage.receipt.context ∧
        evidence.nonce = certificate.coverage.receipt.nonce ∧
        ∀ other ∈ certificate.coverage.receipt.evidence,
          row.id ∈ other.obligations → other = evidence := by
  have assigned := (assignment_inventory_exact binding certificate accepted row.id).mpr
    (List.mem_map.mpr ⟨row, present, rfl⟩)
  rcases List.mem_map.mp assigned with ⟨assignment, assignmentMem, identity⟩
  have receipt := (ReceiptCoverage.certificateValid_iff _ _).mp
    (certificate_implies_receipt binding certificate accepted)
  have coverage := (ReceiptCoverage.coverageAccept_iff _).mpr receipt.2
  refine ⟨assignment, assignmentMem, identity, ?_⟩
  simpa [identity] using ReceiptCoverage.assignment_evidence_unique
    certificate.coverage coverage assignment assignmentMem

theorem no_extra_generated_evidence (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true)
    (evidence : ReceiptCoverage.Evidence)
    (present : evidence ∈ certificate.coverage.receipt.evidence) (id : String)
    (covered : id ∈ evidence.obligations) :
    id ∈ (generated certificate.grant).map Obligation.id := by
  have receipt := (ReceiptCoverage.certificateValid_iff _ _).mp
    (certificate_implies_receipt binding certificate accepted)
  have coverage := (ReceiptCoverage.coverageAccept_iff _).mpr receipt.2
  exact (assignment_inventory_exact binding certificate accepted id).mp
    (ReceiptCoverage.no_extra_evidence_obligations _ coverage evidence present id covered)

def BindingIdentitiesValid (binding : Binding) : Prop :=
  binding.principal ≠ "" ∧ binding.session ≠ "" ∧ binding.tool ≠ "" ∧
  binding.artifact ≠ "" ∧ binding.call ≠ "" ∧ binding.intent ≠ "" ∧
  binding.policy ≠ "" ∧ binding.grant ≠ ""

def grantFor (binding : Binding) (rules : List Rule) : Grant :=
  {principal := binding.principal, session := binding.session, tool := binding.tool,
   artifact := binding.artifact, call := binding.call, intent := binding.intent,
   policy := binding.policy, deployment := binding.deployment, runtime := binding.runtime,
   digest := binding.grant, rules := rules}

def certificateFor (binding : Binding) (rules : List Rule)
    (plans : List ReceiptCoverage.NativePlan) : Certificate :=
  let grant := grantFor binding rules
  {grant := grant, obligations := generated grant,
   coverage := ReceiptCoverage.certificateFor binding plans [] []}

theorem constructed_grant_bound (binding : Binding) (rules : List Rule) :
    GrantBound binding (grantFor binding rules) := by
  simp [GrantBound, grantFor]

theorem constructed_grant_valid (binding : Binding) (rules : List Rule)
    (identities : BindingIdentitiesValid binding) (rulesValid : RulesWellFormed rules) :
    ValidGrant (grantFor binding rules) := by
  rcases identities with ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩
  exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, rulesValid⟩

/-- Arbitrary raw rules and an arbitrary matching multi-adapter partition produce
an accepted certificate. No hypothesis assumes the certificate or route passes. -/
theorem useful_grant_partition (binding : Binding) (rules : List Rule)
    (plans : List ReceiptCoverage.NativePlan)
    (identities : BindingIdentitiesValid binding) (rulesValid : RulesWellFormed rules)
    (partition : ReceiptCoverage.WellFormedPartition plans)
    (matching : ReceiptCoverage.SameIDs (ReceiptCoverage.allObligations plans)
      ((generatedFromRules rules).map Obligation.id)) :
    certificateValid binding (certificateFor binding rules plans) = true := by
  have grantValid := constructed_grant_valid binding rules identities rulesValid
  have inventory := (obligationsAccept_iff _ _).mp
    (exact_generated_useful (grantFor binding rules) grantValid)
  have receipt := (ReceiptCoverage.certificateValid_iff _ _).mp
    (ReceiptCoverage.useful_partition_certificate binding plans [] [] partition (by simp)
      (by simp))
  apply (certificateValid_iff _ _).mpr
  refine ⟨grantValid, constructed_grant_bound binding rules, inventory.2, ?_, ?_, receipt⟩
  · simpa [CompleteAssignments, certificateFor, ReceiptCoverage.certificateFor,
      ReceiptCoverage.partition_assignment_ids, generated, grantFor] using matching
  · simp [Selected, certificateFor, ReceiptCoverage.certificateFor]

theorem runCertified_running_iff (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    (runCertified binding certificate events).phase = .running ↔
      certificateValid binding certificate = true ∧
      events = [.authorize binding true, .activate binding true true, .go binding] := by
  by_cases accepted : certificateValid binding certificate = true
  · simp [runCertified, accepted, running_trace_exact]
  · simp [runCertified, accepted]

theorem certifiedRoute_iff (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    certifiedRoute binding certificate events = true ↔
      certificateValid binding certificate = true ∧ events = successfulEvents binding := by
  by_cases accepted : certificateValid binding certificate = true
  · simpa [certifiedRoute, runCertified, accepted, decideRoute] using
      (success_iff_exact_route binding events)
  · simp [certifiedRoute, runCertified, accepted, allowsSuccess]

theorem certifiedRoute_exact (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    certifiedRoute binding certificate events = true ↔
      ValidCertificate binding certificate ∧ events = successfulEvents binding := by
  rw [certifiedRoute_iff, certificateValid_iff]

theorem runCertified_running_exact (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    (runCertified binding certificate events).phase = .running ↔
      ValidCertificate binding certificate ∧
      events = [.authorize binding true, .activate binding true true, .go binding] := by
  rw [runCertified_running_iff, certificateValid_iff]

theorem useful_grant_partition_route (binding : Binding) (rules : List Rule)
    (plans : List ReceiptCoverage.NativePlan)
    (identities : BindingIdentitiesValid binding) (rulesValid : RulesWellFormed rules)
    (partition : ReceiptCoverage.WellFormedPartition plans)
    (matching : ReceiptCoverage.SameIDs (ReceiptCoverage.allObligations plans)
      ((generatedFromRules rules).map Obligation.id)) :
    certifiedRoute binding (certificateFor binding rules plans) (successfulEvents binding) = true :=
  (certifiedRoute_iff _ _ _).mpr
    ⟨useful_grant_partition binding rules plans identities rulesValid partition matching, rfl⟩

theorem runCertified_preserves_binding (binding : Binding) (certificate : Certificate)
    (events : List Event) : (runCertified binding certificate events).binding = binding := by
  unfold runCertified
  split <;> simp [run_preserves_binding]

theorem invalid_certificate_refuses_every_trace (binding : Binding)
    (certificate : Certificate) (invalid : certificateValid binding certificate = false)
    (events : List Event) : (runCertified binding certificate events).phase = .refused := by
  simp [runCertified, invalid]

end GrantCoverage
