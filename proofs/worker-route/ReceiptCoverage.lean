import WorkerRoute

/-!
Finite receipt composition for the actual assignment/native-plan/evidence
contract. Signatures, freshness, obligation generation, native activation and
faithful Python projection are separate premises, not facts inferred here.
-/
namespace ReceiptCoverage
open WorkerRoute

inductive Support where
  | exact | tightened
  deriving DecidableEq, Repr

inductive Mode where
  | enforced | degraded
  deriving DecidableEq, Repr

structure Assignment where
  obligation : String
  adapter : String
  support : Support
  deriving DecidableEq, Repr

structure NativePlan where
  adapter : String
  digest : String
  obligations : List String
  deriving DecidableEq, Repr

structure Evidence where
  adapter : String
  digest : String
  context : String
  nonce : String
  obligations : List String
  deriving DecidableEq, Repr

structure Plan where
  grant : String
  host : String
  digest : String
  mode : Mode
  assignments : List Assignment
  nativePlans : List NativePlan
  waived : List String
  removedWants : List String
  deriving DecidableEq, Repr

structure Receipt where
  grant : String
  plan : String
  host : String
  context : String
  nonce : String
  artifact : String
  deployment : String
  runtime : String
  mode : Mode
  activated : List String
  removedWants : List String
  evidence : List Evidence
  deriving DecidableEq, Repr

structure Certificate where
  plan : Plan
  receipt : Receipt
  deriving DecidableEq, Repr

/-- Order-independent membership equality. Uniqueness is checked separately. -/
def SameIDs (left right : List String) : Prop :=
  (∀ value ∈ left, value ∈ right) ∧ (∀ value ∈ right, value ∈ left)

instance (left right : List String) : Decidable (SameIDs left right) := by
  unfold SameIDs
  infer_instance

def assignedTo (assignments : List Assignment) (adapter : String) : List String :=
  (assignments.filter (fun row => row.adapter == adapter)).map Assignment.obligation

def ValidAssignments (rows : List Assignment) : Prop :=
  rows ≠ [] ∧ (rows.map Assignment.obligation).Nodup ∧
  ∀ row ∈ rows, row.obligation ≠ "" ∧ row.adapter ≠ ""

def ValidPlans (assignments : List Assignment) (plans : List NativePlan) : Prop :=
  plans ≠ [] ∧ (plans.map NativePlan.adapter).Nodup ∧
  SameIDs (plans.map NativePlan.adapter) (assignments.map Assignment.adapter) ∧
  ∀ row ∈ plans,
    row.adapter ≠ "" ∧ row.digest ≠ "" ∧ row.obligations ≠ [] ∧
    row.obligations.Nodup ∧ SameIDs row.obligations (assignedTo assignments row.adapter)

def EvidenceMatches (context nonce : String) (evidence : Evidence)
    (plan : NativePlan) : Prop :=
  evidence.adapter = plan.adapter ∧ evidence.digest = plan.digest ∧
  evidence.context = context ∧ evidence.nonce = nonce ∧
  SameIDs evidence.obligations plan.obligations

def ValidEvidence (plans : List NativePlan) (receipt : Receipt) : Prop :=
  (receipt.evidence.map Evidence.adapter).Nodup ∧
  SameIDs (receipt.evidence.map Evidence.adapter) (plans.map NativePlan.adapter) ∧
  ∀ row ∈ receipt.evidence,
    row.obligations ≠ [] ∧ row.obligations.Nodup ∧
    ∃ plan ∈ plans, EvidenceMatches receipt.context receipt.nonce row plan

def ValidReceipt (plan : Plan) (receipt : Receipt) : Prop :=
  receipt.activated.Nodup ∧
  SameIDs receipt.activated (plan.assignments.map Assignment.obligation) ∧
  SameIDs receipt.activated (receipt.evidence.flatMap Evidence.obligations) ∧
  receipt.mode = plan.mode ∧ receipt.removedWants = plan.removedWants

def ValidWaivers (plan : Plan) : Prop :=
  plan.waived.Nodup ∧
  (∀ value ∈ plan.waived, value ≠ "" ∧ value ∉ plan.assignments.map Assignment.obligation) ∧
  plan.mode = (if plan.waived = [] then .enforced else .degraded)

/-- Exact finite composition; waivers are recorded, never authorized here. -/
def ValidCoverage (certificate : Certificate) : Prop :=
  ValidAssignments certificate.plan.assignments ∧
  ValidPlans certificate.plan.assignments certificate.plan.nativePlans ∧
  ValidEvidence certificate.plan.nativePlans certificate.receipt ∧
  ValidReceipt certificate.plan certificate.receipt ∧
  ValidWaivers certificate.plan

instance (certificate : Certificate) : Decidable (ValidCoverage certificate) := by
  unfold ValidCoverage ValidAssignments ValidPlans ValidEvidence EvidenceMatches
    ValidReceipt ValidWaivers
  infer_instance

/-- Only actual receipt fields are compared. No digest preimage is inferred. -/
def BoundTo (binding : Binding) (certificate : Certificate) : Prop :=
  certificate.plan.grant = binding.grant ∧
  certificate.plan.host = binding.host ∧
  certificate.plan.digest = binding.plan ∧
  certificate.receipt.grant = binding.grant ∧
  certificate.receipt.plan = binding.plan ∧
  certificate.receipt.host = binding.host ∧
  certificate.receipt.context = binding.context ∧
  certificate.receipt.nonce = binding.nonce ∧
  certificate.receipt.artifact = binding.artifact ∧
  certificate.receipt.deployment = binding.deployment ∧
  certificate.receipt.runtime = binding.runtime

instance (binding : Binding) (certificate : Certificate) :
    Decidable (BoundTo binding certificate) := by
  unfold BoundTo
  infer_instance

def coverageAccept (certificate : Certificate) : Bool := decide (ValidCoverage certificate)

def certificateValid (binding : Binding) (certificate : Certificate) : Bool :=
  decide (BoundTo binding certificate ∧ ValidCoverage certificate)

def runCertified (binding : Binding) (certificate : Certificate)
    (events : List Event) : State :=
  if certificateValid binding certificate then run binding events
  else ⟨binding, .refused⟩

abbrev certifiedRun := runCertified

def certifiedRoute (binding : Binding) (certificate : Certificate)
    (events : List Event) : Bool := allowsSuccess (runCertified binding certificate events)

theorem coverageAccept_iff (certificate : Certificate) :
    coverageAccept certificate = true ↔ ValidCoverage certificate := by
  simp [coverageAccept]

theorem certificateValid_iff (binding : Binding) (certificate : Certificate) :
    certificateValid binding certificate = true ↔
      BoundTo binding certificate ∧ ValidCoverage certificate := by
  simp [certificateValid]

theorem certificate_rejects_binding_mismatch (binding : Binding)
    (certificate : Certificate) (mismatch : ¬ BoundTo binding certificate) :
    certificateValid binding certificate = false := by
  simp [certificateValid, mismatch]

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

theorem assignment_owner_unique (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (assignment : Assignment)
    (present : assignment ∈ certificate.plan.assignments) :
    ∃ plan ∈ certificate.plan.nativePlans,
      plan.adapter = assignment.adapter ∧ assignment.obligation ∈ plan.obligations ∧
      ∀ other ∈ certificate.plan.nativePlans,
        other.adapter = assignment.adapter → other = plan := by
  have valid := (coverageAccept_iff certificate).mp accepted
  have plans := valid.2.1
  have adapterMem := plans.2.2.1.2 assignment.adapter
    (List.mem_map.mpr ⟨assignment, present, rfl⟩)
  rcases List.mem_map.mp adapterMem with ⟨plan, planMem, owner⟩
  have assigned : assignment.obligation ∈ assignedTo certificate.plan.assignments plan.adapter := by
    apply List.mem_map.mpr
    refine ⟨assignment, List.mem_filter.mpr ⟨present, ?_⟩, rfl⟩
    simp [owner]
  have covered := (plans.2.2.2 plan planMem).2.2.2.2.2 assignment.obligation assigned
  refine ⟨plan, planMem, owner, covered, ?_⟩
  intro other otherMem otherOwner
  exact unique_key plans.2.1 otherMem planMem (otherOwner.trans owner.symm)

theorem plan_evidence_unique (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (plan : NativePlan)
    (present : plan ∈ certificate.plan.nativePlans) :
    ∃ evidence ∈ certificate.receipt.evidence,
      EvidenceMatches certificate.receipt.context certificate.receipt.nonce evidence plan ∧
      ∀ other ∈ certificate.receipt.evidence,
        other.adapter = plan.adapter → other = evidence := by
  have valid := (coverageAccept_iff certificate).mp accepted
  have plans := valid.2.1
  have evidences := valid.2.2.1
  have adapterMem := evidences.2.1.2 plan.adapter
    (List.mem_map.mpr ⟨plan, present, rfl⟩)
  rcases List.mem_map.mp adapterMem with ⟨evidence, evidenceMem, owner⟩
  rcases (evidences.2.2 evidence evidenceMem).2.2 with ⟨otherPlan, otherMem, correspondence⟩
  have samePlan := unique_key plans.2.1 otherMem present (correspondence.1.symm.trans owner)
  subst otherPlan
  refine ⟨evidence, evidenceMem, correspondence, ?_⟩
  intro other otherMem otherOwner
  exact unique_key evidences.1 otherMem evidenceMem (otherOwner.trans owner.symm)

/-- An evidence obligation comes from its adapter's actual assignment row. -/
theorem evidence_obligation_assignment (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (evidence : Evidence)
    (present : evidence ∈ certificate.receipt.evidence) (obligation : String)
    (covered : obligation ∈ evidence.obligations) :
    ∃ assignment ∈ certificate.plan.assignments,
      assignment.obligation = obligation ∧ assignment.adapter = evidence.adapter := by
  have valid := (coverageAccept_iff certificate).mp accepted
  rcases (valid.2.2.1.2.2 evidence present).2.2 with ⟨plan, planMem, correspondence⟩
  have planCovered := correspondence.2.2.2.2.1 obligation covered
  have assigned := (valid.2.1.2.2.2 plan planMem).2.2.2.2.1 obligation planCovered
  rcases List.mem_map.mp assigned with ⟨assignment, assignmentMem, identity⟩
  rcases List.mem_filter.mp assignmentMem with ⟨assignmentMem, owner⟩
  have ownerEq : assignment.adapter = plan.adapter := by simpa using owner
  exact ⟨assignment, assignmentMem, identity, ownerEq.trans correspondence.1.symm⟩

theorem no_extra_evidence_obligations (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (evidence : Evidence)
    (present : evidence ∈ certificate.receipt.evidence) (obligation : String)
    (covered : obligation ∈ evidence.obligations) :
    obligation ∈ certificate.plan.assignments.map Assignment.obligation := by
  rcases evidence_obligation_assignment certificate accepted evidence present obligation covered with
    ⟨assignment, assignmentMem, identity, _⟩
  exact List.mem_map.mpr ⟨assignment, assignmentMem, identity⟩

/-- Every assigned obligation has one evidence owner, even across adapters. -/
theorem assignment_evidence_unique (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (assignment : Assignment)
    (present : assignment ∈ certificate.plan.assignments) :
    ∃ evidence ∈ certificate.receipt.evidence,
      assignment.obligation ∈ evidence.obligations ∧
      evidence.adapter = assignment.adapter ∧
      evidence.context = certificate.receipt.context ∧
      evidence.nonce = certificate.receipt.nonce ∧
      ∀ other ∈ certificate.receipt.evidence,
        assignment.obligation ∈ other.obligations → other = evidence := by
  have valid := (coverageAccept_iff certificate).mp accepted
  rcases assignment_owner_unique certificate accepted assignment present with
    ⟨plan, planMem, owner, planCovered, _⟩
  rcases plan_evidence_unique certificate accepted plan planMem with
    ⟨evidence, evidenceMem, correspondence, uniqueEvidence⟩
  have evidenceCovered := correspondence.2.2.2.2.2 assignment.obligation planCovered
  refine ⟨evidence, evidenceMem, evidenceCovered, correspondence.1.trans owner,
    correspondence.2.2.1, correspondence.2.2.2.1, ?_⟩
  intro other otherMem otherCovered
  rcases evidence_obligation_assignment certificate accepted other otherMem
      assignment.obligation otherCovered with ⟨otherAssignment, assignmentMem, identity, otherOwner⟩
  have sameAssignment := unique_key valid.1.2.1 assignmentMem present identity
  subst otherAssignment
  exact uniqueEvidence other otherMem (otherOwner.symm.trans owner.symm)

theorem no_missing_activated_obligations (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (assignment : Assignment)
    (present : assignment ∈ certificate.plan.assignments) :
    assignment.obligation ∈ certificate.receipt.activated := by
  have valid := (coverageAccept_iff certificate).mp accepted
  exact valid.2.2.2.1.2.1.2 assignment.obligation
    (List.mem_map.mpr ⟨assignment, present, rfl⟩)

theorem no_extra_activated_obligations (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (obligation : String)
    (present : obligation ∈ certificate.receipt.activated) :
    obligation ∈ certificate.plan.assignments.map Assignment.obligation := by
  exact ((coverageAccept_iff certificate).mp accepted).2.2.2.1.2.1.1 obligation present

theorem waived_obligations_not_activated (certificate : Certificate)
    (accepted : coverageAccept certificate = true) (obligation : String)
    (waived : obligation ∈ certificate.plan.waived) :
    obligation ∉ certificate.receipt.activated := by
  have valid := (coverageAccept_iff certificate).mp accepted
  intro activated
  exact (valid.2.2.2.2.2.1 obligation waived).2
    (no_extra_activated_obligations certificate accepted obligation activated)

theorem receipt_preserves_mode_and_removed_wants (certificate : Certificate)
    (accepted : coverageAccept certificate = true) :
    certificate.receipt.mode = certificate.plan.mode ∧
      certificate.receipt.removedWants = certificate.plan.removedWants := by
  exact ((coverageAccept_iff certificate).mp accepted).2.2.2.1.2.2.2

theorem enforced_iff_no_waivers (certificate : Certificate)
    (accepted : coverageAccept certificate = true) :
    certificate.plan.mode = .enforced ↔ certificate.plan.waived = [] := by
  have mode := ((coverageAccept_iff certificate).mp accepted).2.2.2.2.2.2
  rw [mode]
  split <;> simp_all

theorem missing_evidence_refuses (certificate : Certificate) (assignment : Assignment)
    (present : assignment ∈ certificate.plan.assignments)
    (missing : ∀ evidence ∈ certificate.receipt.evidence,
      assignment.obligation ∉ evidence.obligations) :
    coverageAccept certificate = false := by
  cases accepted : coverageAccept certificate with
  | false => rfl
  | true =>
    rcases assignment_evidence_unique certificate accepted assignment present with
      ⟨evidence, evidenceMem, covered, _⟩
    exact False.elim (missing evidence evidenceMem covered)

def allObligations (plans : List NativePlan) : List String :=
  plans.flatMap NativePlan.obligations

def partitionAssignments (plans : List NativePlan) : List Assignment :=
  plans.flatMap fun plan => plan.obligations.map fun obligation =>
    {obligation := obligation, adapter := plan.adapter, support := .exact}

/-- Arbitrarily many adapters, each with its own nonempty disjoint partition. -/
def WellFormedPartition (plans : List NativePlan) : Prop :=
  plans ≠ [] ∧ (plans.map NativePlan.adapter).Nodup ∧ (allObligations plans).Nodup ∧
  ∀ plan ∈ plans,
    plan.adapter ≠ "" ∧ plan.digest ≠ "" ∧ plan.obligations ≠ [] ∧
    plan.obligations.Nodup ∧ ∀ obligation ∈ plan.obligations, obligation ≠ ""

def evidenceFor (binding : Binding) (plan : NativePlan) : Evidence :=
  {adapter := plan.adapter, digest := plan.digest, context := binding.context,
   nonce := binding.nonce, obligations := plan.obligations}

/-- Construct a real matching receipt, including explicit degraded dispositions. -/
def certificateFor (binding : Binding) (plans : List NativePlan)
    (waived removedWants : List String) : Certificate :=
  let mode := if waived = [] then Mode.enforced else Mode.degraded
  {plan := {
     grant := binding.grant, host := binding.host, digest := binding.plan, mode := mode,
     assignments := partitionAssignments plans, nativePlans := plans,
     waived := waived, removedWants := removedWants},
   receipt := {
     grant := binding.grant, plan := binding.plan, host := binding.host,
     context := binding.context, nonce := binding.nonce, artifact := binding.artifact,
     deployment := binding.deployment, runtime := binding.runtime, mode := mode,
     activated := allObligations plans, removedWants := removedWants,
     evidence := plans.map (evidenceFor binding)}}

theorem partition_assignment_ids (plans : List NativePlan) :
    (partitionAssignments plans).map Assignment.obligation = allObligations plans := by
  simp [partitionAssignments, allObligations, List.map_flatMap, List.map_map, Function.comp_def]

private theorem partition_assignments_valid (plans : List NativePlan)
    (wellFormed : WellFormedPartition plans) : ValidAssignments (partitionAssignments plans) := by
  rcases wellFormed with ⟨nonempty, adapters, obligations, rows⟩
  refine ⟨?_, ?_, ?_⟩
  · rcases List.exists_mem_of_ne_nil plans nonempty with ⟨plan, planMem⟩
    rcases List.exists_mem_of_ne_nil plan.obligations (rows plan planMem).2.2.1 with
      ⟨obligation, obligationMem⟩
    have member : Assignment.mk obligation plan.adapter .exact ∈ partitionAssignments plans :=
      List.mem_flatMap.mpr ⟨plan, planMem, List.mem_map.mpr ⟨obligation, obligationMem, rfl⟩⟩
    intro empty
    simp [empty] at member
  · simpa [partition_assignment_ids] using obligations
  · intro assignment assignmentMem
    rcases List.mem_flatMap.mp assignmentMem with ⟨plan, planMem, assignmentMem⟩
    rcases List.mem_map.mp assignmentMem with ⟨obligation, obligationMem, rfl⟩
    exact ⟨(rows plan planMem).2.2.2.2 obligation obligationMem, (rows plan planMem).1⟩

private theorem partition_plans_valid (plans : List NativePlan)
    (wellFormed : WellFormedPartition plans) : ValidPlans (partitionAssignments plans) plans := by
  rcases wellFormed with ⟨nonempty, adapters, obligations, rows⟩
  refine ⟨nonempty, adapters, ⟨?_, ?_⟩, ?_⟩
  · intro adapter adapterMem
    rcases List.mem_map.mp adapterMem with ⟨plan, planMem, rfl⟩
    rcases List.exists_mem_of_ne_nil plan.obligations (rows plan planMem).2.2.1 with
      ⟨obligation, obligationMem⟩
    exact List.mem_map.mpr ⟨Assignment.mk obligation plan.adapter .exact,
      List.mem_flatMap.mpr ⟨plan, planMem, List.mem_map.mpr ⟨obligation, obligationMem, rfl⟩⟩, rfl⟩
  · intro adapter adapterMem
    rcases List.mem_map.mp adapterMem with ⟨assignment, assignmentMem, rfl⟩
    rcases List.mem_flatMap.mp assignmentMem with ⟨plan, planMem, assignmentMem⟩
    rcases List.mem_map.mp assignmentMem with ⟨obligation, _, rfl⟩
    exact List.mem_map.mpr ⟨plan, planMem, rfl⟩
  · intro plan planMem
    have row := rows plan planMem
    refine ⟨row.1, row.2.1, row.2.2.1, row.2.2.2.1, ⟨?_, ?_⟩⟩
    · intro obligation obligationMem
      apply List.mem_map.mpr
      refine ⟨Assignment.mk obligation plan.adapter .exact, List.mem_filter.mpr ⟨?_, ?_⟩, rfl⟩
      · exact List.mem_flatMap.mpr
          ⟨plan, planMem, List.mem_map.mpr ⟨obligation, obligationMem, rfl⟩⟩
      · simp
    · intro obligation obligationMem
      rcases List.mem_map.mp obligationMem with ⟨assignment, assignmentMem, identity⟩
      rcases List.mem_filter.mp assignmentMem with ⟨assignmentMem, owner⟩
      rcases List.mem_flatMap.mp assignmentMem with ⟨other, otherMem, assignmentMem⟩
      rcases List.mem_map.mp assignmentMem with ⟨otherObligation, otherObligationMem, rfl⟩
      have sameOwner : other.adapter = plan.adapter := by simpa using owner
      have samePlan := unique_key adapters otherMem planMem sameOwner
      subst other
      simpa using identity ▸ otherObligationMem

/-- Constructive usefulness: exact receipts for any valid adapter partition pass.
The hypotheses describe the input partition and authorized waiver disposition;
none assumes receipt validity, successful activation or route acceptance. -/
theorem useful_partition_certificate (binding : Binding) (plans : List NativePlan)
    (waived removedWants : List String) (wellFormed : WellFormedPartition plans)
    (uniqueWaivers : waived.Nodup)
    (waiverBoundary : ∀ value ∈ waived, value ≠ "" ∧ value ∉ allObligations plans) :
    certificateValid binding (certificateFor binding plans waived removedWants) = true := by
  apply (certificateValid_iff _ _).mpr
  refine ⟨?_, ?_⟩
  · simp [BoundTo, certificateFor]
  · refine ⟨partition_assignments_valid plans wellFormed,
      partition_plans_valid plans wellFormed, ?_, ?_, ?_⟩
    · refine ⟨?_, ?_, ?_⟩
      · simpa [certificateFor, evidenceFor, List.map_map, Function.comp_def] using wellFormed.2.1
      · simp [certificateFor, evidenceFor, SameIDs, List.map_map]
      · intro evidence evidenceMem
        change evidence ∈ plans.map (evidenceFor binding) at evidenceMem
        rcases List.mem_map.mp evidenceMem with ⟨plan, planMem, rfl⟩
        have row := wellFormed.2.2.2 plan planMem
        refine ⟨row.2.2.1, row.2.2.2.1, plan, planMem, ?_⟩
        simp [EvidenceMatches, certificateFor, evidenceFor, SameIDs]
    · refine ⟨wellFormed.2.2.1, ?_, ?_, rfl, rfl⟩
      · simp [certificateFor, partition_assignment_ids, SameIDs]
      · simp [certificateFor, allObligations, List.flatMap_map, evidenceFor, SameIDs]
    · refine ⟨uniqueWaivers, ?_, rfl⟩
      simpa [certificateFor, partition_assignment_ids] using waiverBoundary

theorem useful_partition_route (binding : Binding) (plans : List NativePlan)
    (waived removedWants : List String) (wellFormed : WellFormedPartition plans)
    (uniqueWaivers : waived.Nodup)
    (waiverBoundary : ∀ value ∈ waived, value ≠ "" ∧ value ∉ allObligations plans) :
    certifiedRoute binding (certificateFor binding plans waived removedWants)
      (successfulEvents binding) = true := by
  have accepted := useful_partition_certificate binding plans waived removedWants
    wellFormed uniqueWaivers waiverBoundary
  simp [certifiedRoute, runCertified, accepted, allowsSuccess, run, runFrom,
    initial, successfulEvents, step, nextPhase]

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

theorem certifiedRoute_useful (binding : Binding) (certificate : Certificate)
    (accepted : certificateValid binding certificate = true) :
    certifiedRoute binding certificate (successfulEvents binding) = true :=
  (certifiedRoute_iff binding certificate _).mpr ⟨accepted, rfl⟩

theorem runCertified_preserves_binding (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    (runCertified binding certificate events).binding = binding := by
  unfold runCertified
  split <;> simp [run_preserves_binding]

theorem invalid_certificate_refuses_every_trace (binding : Binding)
    (certificate : Certificate) (invalid : certificateValid binding certificate = false)
    (events : List Event) :
    (runCertified binding certificate events).phase = .refused := by
  simp [runCertified, invalid]

theorem runCertified_running_exact (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    (runCertified binding certificate events).phase = .running ↔
      BoundTo binding certificate ∧ ValidCoverage certificate ∧
      events = [.authorize binding true, .activate binding true true, .go binding] := by
  rw [runCertified_running_iff, certificateValid_iff]
  simp only [and_assoc]

theorem certifiedRoute_exact (binding : Binding) (certificate : Certificate)
    (events : List Event) :
    certifiedRoute binding certificate events = true ↔
      BoundTo binding certificate ∧ ValidCoverage certificate ∧ events = successfulEvents binding := by
  rw [certifiedRoute_iff, certificateValid_iff]
  simp only [and_assoc]

end ReceiptCoverage
