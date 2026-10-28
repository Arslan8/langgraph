#!/usr/bin/env python3
"""Build and audit the finite Lean worker model into a new evidence directory.

This verifies the captured Lean model, not Python/OS/decoder refinement. Failed
runs retain their source snapshot, subprocess logs, and failure report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

PINNED_TOOLCHAIN = "leanprover/lean4:v4.34.1"
SOURCE_FILES = (
    "WorkerRoute.lean",
    "ReceiptCoverage.lean",
    "GrantCoverage.lean",
    "Main.lean",
    "lean-toolchain",
    "lakefile.toml",
    "lake-manifest.json",
    "check.py",
    "test_check.py",
)
ALLOWED_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})
# Fixed obligations: an empty discovery result cannot count as a proof.
WORKER_THEOREMS = (
    "success_iff_exact_route",
    "useful_route_succeeds",
    "step_preserves_binding",
    "run_preserves_binding",
    "go_requires_matching_authorized_activation",
    "authorization_denial_refuses",
    "unsupported_refuses",
    "unconfirmed_activation_refuses",
    "authorize_mismatch_refuses",
    "activation_mismatch_refuses",
    "go_mismatch_refuses",
    "result_mismatch_refuses",
    "result_failure_refuses",
    "cancellation_anywhere_refuses",
    "unknown_cleanup_anywhere_refuses",
    "success_requires_confirmed_cleanup",
    "success_excludes_cancellation",
)
RECEIPT_THEOREMS = (
    "coverageAccept_iff",
    "certificateValid_iff",
    "certificate_rejects_binding_mismatch",
    "assignment_owner_unique",
    "plan_evidence_unique",
    "evidence_obligation_assignment",
    "no_extra_evidence_obligations",
    "assignment_evidence_unique",
    "no_missing_activated_obligations",
    "no_extra_activated_obligations",
    "partition_assignment_ids",
    "useful_partition_certificate",
    "useful_partition_route",
    "runCertified_running_iff",
    "certifiedRoute_iff",
    "certifiedRoute_useful",
    "runCertified_preserves_binding",
    "invalid_certificate_refuses_every_trace",
    "runCertified_running_exact",
    "certifiedRoute_exact",
)
GRANT_THEOREMS = (
    "obligationsAccept_iff",
    "certificateValid_iff",
    "every_domain_present",
    "nine_distinct_complements",
    "generated_exact_origin",
    "generated_rule_present",
    "generated_complement_present",
    "derived_rule_semantics",
    "no_missing_generated",
    "no_extra_obligations",
    "rule_covered_once",
    "complement_covered_once",
    "semantic_substitution_refuses",
    "missing_generated_refuses",
    "exact_generated_useful",
    "certificate_inventory_accepted",
    "grant_binding_mismatch_refuses",
    "assignment_inventory_exact",
    "selected_no_waivers",
    "certificate_implies_receipt",
    "certificate_preserves_grant_identity",
    "invalid_inventory_refuses",
    "activated_inventory_exact",
    "generated_evidence_owner_unique",
    "no_extra_generated_evidence",
    "constructed_grant_bound",
    "constructed_grant_valid",
    "useful_grant_partition",
    "runCertified_running_iff",
    "certifiedRoute_iff",
    "certifiedRoute_exact",
    "runCertified_running_exact",
    "useful_grant_partition_route",
    "runCertified_preserves_binding",
    "invalid_certificate_refuses_every_trace",
)
REQUIRED_THEOREMS = (
    tuple("WorkerRoute." + name for name in WORKER_THEOREMS)
    + tuple("ReceiptCoverage." + name for name in RECEIPT_THEOREMS)
    + tuple("GrantCoverage." + name for name in GRANT_THEOREMS)
)
# This is a conservative source hygiene check, not a Lean parser or proof.
# The typed audit and dependency check below establish the theorem evidence.
FORBIDDEN_IDENTIFIERS = frozenset(
    {
        "sorry",
        "sorryAx",
        "admit",
        "axiom",
        "native_decide",
        "unsafe",
        "implemented_by",
        "extern",
        "elab",
        "macro",
        "run_tac",
        "initialize",
        "builtin_initialize",
        "set_option",
    }
)

AUDIT_SOURCE = r"""import WorkerRoute
import ReceiptCoverage
import GrantCoverage
open WorkerRoute

-- A complete, arbitrary identity record must exist and preserve its fields.
example (principal session call tool artifact grant plan nonce host context deployment runtime intent policy
    pid startTime bootId : String) :
    let b : Binding := {
      principal := principal, session := session, call := call, tool := tool,
      artifact := artifact, grant := grant, plan := plan, nonce := nonce,
      host := host, context := context, deployment := deployment, runtime := runtime,
      intent := intent, policy := policy,
      worker := {pid := pid, startTime := startTime, bootId := bootId}}
    [b.principal, b.session, b.call, b.tool, b.artifact, b.grant, b.plan,
      b.nonce, b.host, b.context, b.deployment, b.runtime, b.intent, b.policy,
      b.worker.pid, b.worker.startTime, b.worker.bootId] =
    [principal, session, call, tool, artifact, grant, plan, nonce, host, context, deployment, runtime, intent, policy,
      pid, startTime, bootId] := by rfl

-- Check fixed semantic statements, not just the existence of theorem names.
example (b : Binding) (events : List Event) :
    decideRoute b events = true ↔ events =
      [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] := by
  simpa only [successfulEvents] using success_iff_exact_route b events

example (b : Binding) :
    decideRoute b [.authorize b true, .activate b true true,
      .go b, .result b true, .cleanup true] = true := by
  simpa only [successfulEvents] using useful_route_succeeds b

example (s : State) (e : Event) : (step s e).binding = s.binding :=
  step_preserves_binding s e

example (b : Binding) (events : List Event) : (run b events).binding = b :=
  run_preserves_binding b events

example (b observed : Binding) (events : List Event) :
    (step (run b events) (.go observed)).phase = .running ↔
      events = [.authorize b true, .activate b true true] ∧ observed = b :=
  go_requires_matching_authorized_activation b observed events

example (s : State) (b : Binding) :
    (step s (.authorize b false)).phase = .refused := authorization_denial_refuses s b

example (s : State) (b : Binding) (confirmed : Bool) :
    (step s (.activate b false confirmed)).phase = .refused := unsupported_refuses s b confirmed

example (s : State) (b : Binding) (supported : Bool) :
    (step s (.activate b supported false)).phase = .refused :=
  unconfirmed_activation_refuses s b supported

example (s : State) (b : Binding) (a : Bool) (h : b ≠ s.binding) :
    (step s (.authorize b a)).phase = .refused := authorize_mismatch_refuses s b a h

example (s : State) (b : Binding) (a c : Bool) (h : b ≠ s.binding) :
    (step s (.activate b a c)).phase = .refused := activation_mismatch_refuses s b a c h

example (s : State) (b : Binding) (h : b ≠ s.binding) :
    (step s (.go b)).phase = .refused := go_mismatch_refuses s b h

example (s : State) (b : Binding) (a : Bool) (h : b ≠ s.binding) :
    (step s (.result b a)).phase = .refused := result_mismatch_refuses s b a h

example (s : State) (b : Binding) :
    (step s (.result b false)).phase = .refused := result_failure_refuses s b

example (b : Binding) (before after : List Event) :
    decideRoute b (before ++ .cancel :: after) = false :=
  cancellation_anywhere_refuses b before after

example (b : Binding) (before after : List Event) :
    decideRoute b (before ++ .cleanup false :: after) = false :=
  unknown_cleanup_anywhere_refuses b before after

example (b : Binding) (events : List Event) (h : decideRoute b events = true) :
    ∃ before, events = before ++ [.cleanup true] := success_requires_confirmed_cleanup b events h

example (b : Binding) (events : List Event) (h : decideRoute b events = true) :
    Event.cancel ∉ events := success_excludes_cancellation b events h

open ReceiptCoverage

example (support : Support) : support = .exact ∨ support = .tightened := by
  cases support <;> simp

example (mode : Mode) : mode = .enforced ∨ mode = .degraded := by
  cases mode <;> simp

-- Arbitrary values exercise every constructor field and its exact projection.
example (obligation adapter : String) (support : Support) :
    let row : Assignment := {obligation := obligation, adapter := adapter, support := support}
    (row.obligation, row.adapter, row.support) = (obligation, adapter, support) := by rfl

example (adapter digest : String) (obligations : List String) :
    let row : NativePlan := {adapter := adapter, digest := digest, obligations := obligations}
    (row.adapter, row.digest, row.obligations) = (adapter, digest, obligations) := by rfl

example (adapter digest context nonce : String) (obligations : List String) :
    let row : Evidence := {
      adapter := adapter, digest := digest, context := context,
      nonce := nonce, obligations := obligations}
    (row.adapter, row.digest, row.context, row.nonce, row.obligations) =
      (adapter, digest, context, nonce, obligations) := by rfl

example (grant host digest : String) (mode : Mode) (assignments : List Assignment)
    (nativePlans : List NativePlan) (waived removedWants : List String) :
    let row : Plan := {
      grant := grant, host := host, digest := digest, mode := mode,
      assignments := assignments, nativePlans := nativePlans, waived := waived,
      removedWants := removedWants}
    (row.grant, row.host, row.digest, row.mode, row.assignments, row.nativePlans,
      row.waived, row.removedWants) =
      (grant, host, digest, mode, assignments, nativePlans, waived, removedWants) := by rfl

example (grant plan host context nonce artifact deployment runtime : String)
    (mode : Mode) (activated removedWants : List String) (evidence : List Evidence) :
    let row : Receipt := {
      grant := grant, plan := plan, host := host, context := context,
      nonce := nonce, artifact := artifact, deployment := deployment, runtime := runtime,
      mode := mode, activated := activated, removedWants := removedWants, evidence := evidence}
    (row.grant, row.plan, row.host, row.context, row.nonce, row.artifact, row.deployment,
      row.runtime, row.mode, row.activated, row.removedWants, row.evidence) =
      (grant, plan, host, context, nonce, artifact, deployment, runtime, mode,
      activated, removedWants, evidence) := by rfl

example (plan : Plan) (receipt : Receipt) :
    let row : Certificate := {plan := plan, receipt := receipt}
    (row.plan, row.receipt) = (plan, receipt) := by rfl

-- Fixed semantic formulas: changing a model predicate to True must not audit.
def auditSameIDs (left right : List String) : Prop :=
  (∀ value ∈ left, value ∈ right) ∧ (∀ value ∈ right, value ∈ left)

def auditCoverage (c : Certificate) : Prop :=
  (c.plan.assignments ≠ [] ∧ (c.plan.assignments.map Assignment.obligation).Nodup ∧
    ∀ row ∈ c.plan.assignments, row.obligation ≠ "" ∧ row.adapter ≠ "") ∧
  (c.plan.nativePlans ≠ [] ∧ (c.plan.nativePlans.map NativePlan.adapter).Nodup ∧
    auditSameIDs (c.plan.nativePlans.map NativePlan.adapter) (c.plan.assignments.map Assignment.adapter) ∧
    ∀ row ∈ c.plan.nativePlans,
      row.adapter ≠ "" ∧ row.digest ≠ "" ∧ row.obligations ≠ [] ∧ row.obligations.Nodup ∧
      auditSameIDs row.obligations
        ((c.plan.assignments.filter (fun assignment => assignment.adapter == row.adapter)).map Assignment.obligation)) ∧
  ((c.receipt.evidence.map Evidence.adapter).Nodup ∧
    auditSameIDs (c.receipt.evidence.map Evidence.adapter) (c.plan.nativePlans.map NativePlan.adapter) ∧
    ∀ row ∈ c.receipt.evidence, row.obligations ≠ [] ∧ row.obligations.Nodup ∧
      ∃ plan ∈ c.plan.nativePlans,
        row.adapter = plan.adapter ∧ row.digest = plan.digest ∧
        row.context = c.receipt.context ∧ row.nonce = c.receipt.nonce ∧
        auditSameIDs row.obligations plan.obligations) ∧
  (c.receipt.activated.Nodup ∧
    auditSameIDs c.receipt.activated (c.plan.assignments.map Assignment.obligation) ∧
    auditSameIDs c.receipt.activated (c.receipt.evidence.flatMap Evidence.obligations) ∧
    c.receipt.mode = c.plan.mode ∧ c.receipt.removedWants = c.plan.removedWants) ∧
  (c.plan.waived.Nodup ∧
    (∀ value ∈ c.plan.waived, value ≠ "" ∧ value ∉ c.plan.assignments.map Assignment.obligation) ∧
    c.plan.mode = (if c.plan.waived = [] then .enforced else .degraded))

def auditBoundTo (b : Binding) (c : Certificate) : Prop :=
  c.plan.grant = b.grant ∧ c.plan.host = b.host ∧ c.plan.digest = b.plan ∧
  c.receipt.grant = b.grant ∧ c.receipt.plan = b.plan ∧ c.receipt.host = b.host ∧
  c.receipt.context = b.context ∧ c.receipt.nonce = b.nonce ∧
  c.receipt.artifact = b.artifact ∧ c.receipt.deployment = b.deployment ∧
  c.receipt.runtime = b.runtime

example (c : Certificate) : coverageAccept c = true ↔ auditCoverage c := by
  simpa only [auditCoverage, auditSameIDs, ValidCoverage, ValidAssignments, ValidPlans,
    ValidEvidence, EvidenceMatches, ValidReceipt, ValidWaivers, SameIDs, assignedTo]
    using coverageAccept_iff c

example (b : Binding) (c : Certificate) :
    certificateValid b c = true ↔ auditBoundTo b c ∧ auditCoverage c := by
  simpa only [auditCoverage, auditSameIDs, auditBoundTo, ValidCoverage, ValidAssignments,
    ValidPlans, ValidEvidence, EvidenceMatches, ValidReceipt, ValidWaivers, SameIDs,
    assignedTo, BoundTo] using certificateValid_iff b c

example (b : Binding) (c : Certificate) (h : ¬ auditBoundTo b c) :
    certificateValid b c = false := by
  apply certificate_rejects_binding_mismatch b c
  simpa only [auditBoundTo, BoundTo] using h

example (b : Binding) (c : Certificate) (events : List Event) :
    (runCertified b c events).phase = .running ↔ certificateValid b c = true ∧
      events = [.authorize b true, .activate b true true, .go b] :=
  runCertified_running_iff b c events

example (b : Binding) (c : Certificate) (events : List Event) :
    certifiedRoute b c events = true ↔ certificateValid b c = true ∧
      events = [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] := by
  simpa only [successfulEvents] using certifiedRoute_iff b c events

example (b : Binding) (c : Certificate) (h : certificateValid b c = true) :
    certifiedRoute b c [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] = true := by
  simpa only [successfulEvents] using certifiedRoute_useful b c h

example (c : Certificate) (accepted : coverageAccept c = true)
    (assignment : Assignment) (present : assignment ∈ c.plan.assignments) :
    ∃ plan ∈ c.plan.nativePlans,
      plan.adapter = assignment.adapter ∧ assignment.obligation ∈ plan.obligations ∧
      ∀ other ∈ c.plan.nativePlans, other.adapter = assignment.adapter → other = plan :=
  assignment_owner_unique c accepted assignment present

example (c : Certificate) (accepted : coverageAccept c = true)
    (plan : NativePlan) (present : plan ∈ c.plan.nativePlans) :
    ∃ evidence ∈ c.receipt.evidence,
      (evidence.adapter = plan.adapter ∧ evidence.digest = plan.digest ∧
        evidence.context = c.receipt.context ∧ evidence.nonce = c.receipt.nonce ∧
        auditSameIDs evidence.obligations plan.obligations) ∧
      ∀ other ∈ c.receipt.evidence, other.adapter = plan.adapter → other = evidence := by
  simpa only [EvidenceMatches, SameIDs, auditSameIDs] using plan_evidence_unique c accepted plan present

example (c : Certificate) (accepted : coverageAccept c = true)
    (evidence : Evidence) (present : evidence ∈ c.receipt.evidence)
    (obligation : String) (covered : obligation ∈ evidence.obligations) :
    ∃ assignment ∈ c.plan.assignments,
      assignment.obligation = obligation ∧ assignment.adapter = evidence.adapter :=
  evidence_obligation_assignment c accepted evidence present obligation covered

example (c : Certificate) (accepted : coverageAccept c = true)
    (evidence : Evidence) (present : evidence ∈ c.receipt.evidence)
    (obligation : String) (covered : obligation ∈ evidence.obligations) :
    obligation ∈ c.plan.assignments.map Assignment.obligation :=
  no_extra_evidence_obligations c accepted evidence present obligation covered

example (c : Certificate) (accepted : coverageAccept c = true)
    (assignment : Assignment) (present : assignment ∈ c.plan.assignments) :
    ∃ evidence ∈ c.receipt.evidence,
      assignment.obligation ∈ evidence.obligations ∧ evidence.adapter = assignment.adapter ∧
      evidence.context = c.receipt.context ∧ evidence.nonce = c.receipt.nonce ∧
      ∀ other ∈ c.receipt.evidence, assignment.obligation ∈ other.obligations → other = evidence :=
  assignment_evidence_unique c accepted assignment present

example (c : Certificate) (accepted : coverageAccept c = true)
    (assignment : Assignment) (present : assignment ∈ c.plan.assignments) :
    assignment.obligation ∈ c.receipt.activated :=
  no_missing_activated_obligations c accepted assignment present

example (c : Certificate) (accepted : coverageAccept c = true)
    (obligation : String) (present : obligation ∈ c.receipt.activated) :
    obligation ∈ c.plan.assignments.map Assignment.obligation :=
  no_extra_activated_obligations c accepted obligation present

def auditAssignments (plans : List NativePlan) : List Assignment :=
  plans.flatMap fun plan => plan.obligations.map fun obligation =>
    {obligation := obligation, adapter := plan.adapter, support := .exact}

def auditPartition (plans : List NativePlan) : Prop :=
  plans ≠ [] ∧ (plans.map NativePlan.adapter).Nodup ∧
  (plans.flatMap NativePlan.obligations).Nodup ∧
  ∀ plan ∈ plans, plan.adapter ≠ "" ∧ plan.digest ≠ "" ∧
    plan.obligations ≠ [] ∧ plan.obligations.Nodup ∧
    ∀ obligation ∈ plan.obligations, obligation ≠ ""

def auditCertificateFor (b : Binding) (plans : List NativePlan)
    (waived removedWants : List String) : Certificate :=
  let mode := if waived = [] then Mode.enforced else Mode.degraded
  {plan := {
     grant := b.grant, host := b.host, digest := b.plan, mode := mode,
     assignments := auditAssignments plans, nativePlans := plans,
     waived := waived, removedWants := removedWants},
   receipt := {
     grant := b.grant, plan := b.plan, host := b.host, context := b.context,
     nonce := b.nonce, artifact := b.artifact, deployment := b.deployment,
     runtime := b.runtime, mode := mode, activated := plans.flatMap NativePlan.obligations,
     removedWants := removedWants, evidence := plans.map fun plan =>
       {adapter := plan.adapter, digest := plan.digest, context := b.context,
        nonce := b.nonce, obligations := plan.obligations}}}

theorem auditEvidenceProjection (b : Binding) : evidenceFor b =
    (fun plan : NativePlan => {
      adapter := plan.adapter, digest := plan.digest,
      context := b.context, nonce := b.nonce, obligations := plan.obligations}) := by
  funext plan
  rfl

example (plans : List NativePlan) :
    (auditAssignments plans).map Assignment.obligation = plans.flatMap NativePlan.obligations := by
  simpa only [auditAssignments, partitionAssignments, allObligations] using partition_assignment_ids plans

example (b : Binding) (plans : List NativePlan) (waived removedWants : List String)
    (partition : auditPartition plans) (unique : waived.Nodup)
    (boundary : ∀ value ∈ waived, value ≠ "" ∧ value ∉ plans.flatMap NativePlan.obligations) :
    certificateValid b (auditCertificateFor b plans waived removedWants) = true := by
  have valid : WellFormedPartition plans := by
    simpa only [auditPartition, WellFormedPartition, allObligations] using partition
  simpa only [auditCertificateFor, auditAssignments, certificateFor, partitionAssignments,
    auditEvidenceProjection, allObligations] using useful_partition_certificate b plans waived removedWants valid unique boundary

example (b : Binding) (plans : List NativePlan) (waived removedWants : List String)
    (partition : auditPartition plans) (unique : waived.Nodup)
    (boundary : ∀ value ∈ waived, value ≠ "" ∧ value ∉ plans.flatMap NativePlan.obligations) :
    certifiedRoute b (auditCertificateFor b plans waived removedWants)
      [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] = true := by
  have valid : WellFormedPartition plans := by
    simpa only [auditPartition, WellFormedPartition, allObligations] using partition
  simpa only [auditCertificateFor, auditAssignments, certificateFor, partitionAssignments,
    auditEvidenceProjection, allObligations, successfulEvents] using useful_partition_route b plans waived removedWants valid unique boundary

-- Concrete useful multi-adapter acceptance, with arbitrary route identities.
def auditTwoPlans : List NativePlan :=
  [{adapter := "filesystem", digest := "filesystem-plan", obligations := ["read", "deny-complement"]},
   {adapter := "limits", digest := "limits-plan", obligations := ["cpu"]}]

example (b : Binding) :
    certifiedRoute b (auditCertificateFor b auditTwoPlans [] [])
      [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] = true := by
  have partition : WellFormedPartition auditTwoPlans := by
    unfold WellFormedPartition allObligations
    decide
  simpa only [auditCertificateFor, auditAssignments, certificateFor, partitionAssignments,
    auditEvidenceProjection, allObligations, successfulEvents] using
    useful_partition_route b auditTwoPlans [] [] partition (by simp) (by simp)

example (b : Binding) :
    certificateValid b (auditCertificateFor b auditTwoPlans ["optional-debug"] ["debug-rule"]) = true := by
  have partition : WellFormedPartition auditTwoPlans := by
    unfold WellFormedPartition allObligations
    decide
  have boundary : ∀ value ∈ ["optional-debug"], value ≠ "" ∧ value ∉ allObligations auditTwoPlans := by decide
  simpa only [auditCertificateFor, auditAssignments, certificateFor, partitionAssignments,
    auditEvidenceProjection, allObligations] using
    useful_partition_certificate b auditTwoPlans ["optional-debug"] ["debug-rule"] partition (by decide) boundary

example (b : Binding) (c : Certificate) (events : List Event) :
    (runCertified b c events).binding = b := runCertified_preserves_binding b c events

example (b : Binding) (c : Certificate) (h : certificateValid b c = false)
    (events : List Event) : (runCertified b c events).phase = .refused :=
  invalid_certificate_refuses_every_trace b c h events

example (b : Binding) (c : Certificate) (events : List Event) :
    (runCertified b c events).phase = .running ↔
      auditBoundTo b c ∧ auditCoverage c ∧
      events = [.authorize b true, .activate b true true, .go b] := by
  simpa only [auditCoverage, auditSameIDs, auditBoundTo, ValidCoverage, ValidAssignments,
    ValidPlans, ValidEvidence, EvidenceMatches, ValidReceipt, ValidWaivers, SameIDs,
    assignedTo, BoundTo] using runCertified_running_exact b c events

example (b : Binding) (c : Certificate) (events : List Event) :
    certifiedRoute b c events = true ↔ auditBoundTo b c ∧ auditCoverage c ∧
      events = [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] := by
  simpa only [auditCoverage, auditSameIDs, auditBoundTo, ValidCoverage, ValidAssignments,
    ValidPlans, ValidEvidence, EvidenceMatches, ValidReceipt, ValidWaivers, SameIDs,
    assignedTo, BoundTo, successfulEvents] using certifiedRoute_exact b c events
"""


GRANT_AUDIT_SOURCE = r"""
namespace GrantAudit
open GrantCoverage (Value Values Entries Domain Requirement Kind Rule Grant Obligation)

-- Arbitrary complete records, including fields not used by generation itself.
example (id operation selector : String) (domain : Domain) (conditions : Value)
    (requirement : Requirement) (provenance : List String) (baseline : Bool) :
    let r : Rule := Rule.mk id domain operation selector conditions requirement provenance baseline
    (r.id, r.domain, r.operation, r.selector, r.conditions, r.requirement,
      r.provenance, r.baseline) =
      (id, domain, operation, selector, conditions, requirement, provenance, baseline) := by rfl

example (principal session tool artifact call intent policy deployment runtime digest : String)
    (rules : List Rule) :
    let g : Grant := Grant.mk principal session tool artifact call intent policy deployment
      runtime digest rules
    (g.principal, g.session, g.tool, g.artifact, g.call, g.intent, g.policy,
      g.deployment, g.runtime, g.digest, g.rules) =
      (principal, session, tool, artifact, call, intent, policy, deployment, runtime,
       digest, rules) := by rfl

example (id rule operation selector : String) (kind : Kind) (domain : Domain)
    (conditions : Value) (dependencies : List String) (waivable : Bool) :
    let o : Obligation := Obligation.mk id rule kind domain operation selector conditions
      dependencies waivable
    (o.id, o.rule, o.kind, o.domain, o.operation, o.selector, o.conditions,
      o.dependencies, o.waivable) =
      (id, rule, kind, domain, operation, selector, conditions, dependencies, waivable) := by rfl

example (g : Grant) (rows : List Obligation) (coverage : ReceiptCoverage.Certificate) :
    let c : GrantCoverage.Certificate := {grant := g, obligations := rows, coverage := coverage}
    (c.grant, c.obligations, c.coverage) = (g, rows, coverage) := by rfl

-- All six tagged value forms remain distinct, preserving native bool/int separation.
example (b : Bool) (n : Int) : Value.bool b ≠ Value.int n := by intro h; cases h
example (s : String) : Value.text s ≠ Value.null := by intro h; cases h
example (xs : Values) (entries : Entries) : Value.sequence xs ≠ Value.map entries := by
  intro h; cases h
example (key : String) (value : Value) (rest : Entries) :
    Entries.cons key value rest = Entries.cons key value rest := by rfl
example (value : Value) (rest : Values) :
    Values.cons value rest = Values.cons value rest := by rfl

-- Independently spell the semantic generator, including each domain and field.
def auditDomainName : Domain → String
  | .filesystem => "filesystem"
  | .network => "network"
  | .process => "process"
  | .ipc => "ipc"
  | .service => "service"
  | .credential => "credential"
  | .runtime => "runtime"
  | .delegation => "delegation"
  | .resourceLimit => "resource_limit"

def auditDomains : List Domain :=
  [.filesystem, .network, .process, .ipc, .service, .credential, .runtime,
   .delegation, .resourceLimit]

def auditDerive (r : Rule) : Obligation :=
  {id := "rule:" ++ r.id ++ ":operate", rule := r.id,
   kind := if r.domain = .resourceLimit then .resourceLimit else .operate,
   domain := r.domain, operation := r.operation, selector := r.selector,
   conditions := r.conditions, dependencies := [],
   waivable := r.requirement == .want && !r.baseline}

def auditComplement (d : Domain) : Obligation :=
  {id := "domain:" ++ auditDomainName d ++ ":deny_complement",
   rule := "domain:" ++ auditDomainName d, kind := .denyComplement, domain := d,
   operation := "deny_unlisted", selector := "*", conditions := .map .nil,
   dependencies := [], waivable := false}

def auditGeneratedRules (rules : List Rule) : List Obligation :=
  rules.map auditDerive ++ auditDomains.map auditComplement

def auditGenerated (g : Grant) : List Obligation := auditGeneratedRules g.rules

example (r : Rule) : GrantCoverage.deriveRule r = auditDerive r := by rfl
example (d : Domain) : GrantCoverage.denyComplement d = auditComplement d := by rfl
example : GrantCoverage.domains = auditDomains := by rfl
example (g : Grant) : GrantCoverage.generated g = auditGenerated g := by rfl

-- Full-record matching and required inventory are independent of supplied receipts.
def auditValidGrant (g : Grant) : Prop :=
  g.principal ≠ "" ∧ g.session ≠ "" ∧ g.tool ≠ "" ∧ g.artifact ≠ "" ∧
  g.call ≠ "" ∧ g.intent ≠ "" ∧ g.policy ≠ "" ∧ g.digest ≠ "" ∧
  (g.rules.map Rule.id).Nodup ∧
  (∀ r ∈ g.rules, r.id ≠ "" ∧ r.operation ≠ "" ∧ r.selector ≠ "" ∧
    (match r.conditions with | .map _ => true | _ => false) = true) ∧
  ((auditGeneratedRules g.rules).map Obligation.id).Nodup

def auditExact (g : Grant) (rows : List Obligation) : Prop :=
  (rows.map Obligation.id).Nodup ∧
  (∀ row ∈ rows, row ∈ auditGenerated g) ∧
  (∀ row ∈ auditGenerated g, row ∈ rows)

def auditGrantBound (b : Binding) (g : Grant) : Prop :=
  g.principal = b.principal ∧ g.session = b.session ∧ g.tool = b.tool ∧
  g.artifact = b.artifact ∧ g.call = b.call ∧ g.intent = b.intent ∧
  g.policy = b.policy ∧ g.deployment = b.deployment ∧ g.runtime = b.runtime ∧
  g.digest = b.grant

def auditComplete (c : GrantCoverage.Certificate) : Prop :=
  auditSameIDs (c.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation ++
    c.coverage.plan.waived) ((auditGenerated c.grant).map Obligation.id)

def auditSelected (c : GrantCoverage.Certificate) : Prop :=
  c.coverage.plan.waived = [] ∧ c.coverage.plan.mode = .enforced ∧
  c.coverage.receipt.mode = .enforced

def auditValid (b : Binding) (c : GrantCoverage.Certificate) : Prop :=
  auditValidGrant c.grant ∧ auditGrantBound b c.grant ∧
  auditExact c.grant c.obligations ∧ auditComplete c ∧ auditSelected c ∧
  auditBoundTo b c.coverage ∧ auditCoverage c.coverage

example (g : Grant) (rows : List Obligation) :
    GrantCoverage.obligationsAccept g rows = true ↔ auditValidGrant g ∧ auditExact g rows :=
  GrantCoverage.obligationsAccept_iff g rows

example (b : Binding) (c : GrantCoverage.Certificate) :
    GrantCoverage.certificateValid b c = true ↔ auditValid b c :=
  GrantCoverage.certificateValid_iff b c

example (d : Domain) : d ∈ auditDomains := GrantCoverage.every_domain_present d
example : (auditDomains.map auditComplement).length = 9 ∧
    ((auditDomains.map auditComplement).map Obligation.id).Nodup :=
  GrantCoverage.nine_distinct_complements

example (g : Grant) (row : Obligation) : row ∈ auditGenerated g ↔
    (∃ r ∈ g.rules, auditDerive r = row) ∨ (∃ d : Domain, auditComplement d = row) :=
  GrantCoverage.generated_exact_origin g row
example (g : Grant) (r : Rule) (present : r ∈ g.rules) :
    auditDerive r ∈ auditGenerated g := GrantCoverage.generated_rule_present g r present
example (g : Grant) (d : Domain) : auditComplement d ∈ auditGenerated g :=
  GrantCoverage.generated_complement_present g d

example (r : Rule) :
    (GrantCoverage.deriveRule r).id = "rule:" ++ r.id ++ ":operate" ∧
    (GrantCoverage.deriveRule r).rule = r.id ∧
    (GrantCoverage.deriveRule r).kind = (if r.domain = .resourceLimit then .resourceLimit else .operate) ∧
    (GrantCoverage.deriveRule r).domain = r.domain ∧
    (GrantCoverage.deriveRule r).operation = r.operation ∧
    (GrantCoverage.deriveRule r).selector = r.selector ∧
    (GrantCoverage.deriveRule r).conditions = r.conditions ∧
    (GrantCoverage.deriveRule r).dependencies = [] ∧
    (GrantCoverage.deriveRule r).waivable = (r.requirement == .want && !r.baseline) :=
  GrantCoverage.derived_rule_semantics r

example (g : Grant) (rows : List Obligation)
    (accepted : GrantCoverage.obligationsAccept g rows = true) (row : Obligation)
    (present : row ∈ auditGenerated g) : row ∈ rows :=
  GrantCoverage.no_missing_generated g rows accepted row present
example (g : Grant) (rows : List Obligation)
    (accepted : GrantCoverage.obligationsAccept g rows = true) (row : Obligation)
    (present : row ∈ rows) : row ∈ auditGenerated g :=
  GrantCoverage.no_extra_obligations g rows accepted row present
example (g : Grant) (rows : List Obligation)
    (accepted : GrantCoverage.obligationsAccept g rows = true) (r : Rule)
    (present : r ∈ g.rules) : auditDerive r ∈ rows ∧
      ∀ other ∈ rows, other.id = (auditDerive r).id → other = auditDerive r :=
  GrantCoverage.rule_covered_once g rows accepted r present
example (g : Grant) (rows : List Obligation)
    (accepted : GrantCoverage.obligationsAccept g rows = true) (d : Domain) :
    auditComplement d ∈ rows ∧
      ∀ other ∈ rows, other.id = (auditComplement d).id → other = auditComplement d :=
  GrantCoverage.complement_covered_once g rows accepted d

example (g : Grant) (rows : List Obligation) (original replacement : Obligation)
    (originalMem : original ∈ auditGenerated g) (replacementMem : replacement ∈ rows)
    (sameID : replacement.id = original.id) (changed : replacement ≠ original) :
    GrantCoverage.obligationsAccept g rows = false :=
  GrantCoverage.semantic_substitution_refuses g rows original replacement
    originalMem replacementMem sameID changed
example (g : Grant) (rows : List Obligation) (row : Obligation)
    (present : row ∈ auditGenerated g) (missing : row ∉ rows) :
    GrantCoverage.obligationsAccept g rows = false :=
  GrantCoverage.missing_generated_refuses g rows row present missing
example (g : Grant) (valid : auditValidGrant g) :
    GrantCoverage.obligationsAccept g (auditGenerated g) = true :=
  GrantCoverage.exact_generated_useful g valid

example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) :
    GrantCoverage.obligationsAccept c.grant c.obligations = true :=
  GrantCoverage.certificate_inventory_accepted b c accepted
example (b : Binding) (c : GrantCoverage.Certificate)
    (mismatch : ¬ auditGrantBound b c.grant) :
    GrantCoverage.certificateValid b c = false :=
  GrantCoverage.grant_binding_mismatch_refuses b c mismatch
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) (id : String) :
    id ∈ c.coverage.plan.assignments.map ReceiptCoverage.Assignment.obligation ↔
      id ∈ (auditGenerated c.grant).map Obligation.id :=
  GrantCoverage.assignment_inventory_exact b c accepted id
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) :
    c.coverage.plan.waived = [] ∧ c.coverage.plan.mode = .enforced ∧
      c.coverage.receipt.mode = .enforced := GrantCoverage.selected_no_waivers b c accepted
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) :
    ReceiptCoverage.certificateValid b c.coverage = true :=
  GrantCoverage.certificate_implies_receipt b c accepted
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) : auditGrantBound b c.grant :=
  GrantCoverage.certificate_preserves_grant_identity b c accepted
example (b : Binding) (c : GrantCoverage.Certificate)
    (invalid : GrantCoverage.obligationsAccept c.grant c.obligations = false) :
    GrantCoverage.certificateValid b c = false := GrantCoverage.invalid_inventory_refuses b c invalid
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) (id : String) :
    id ∈ c.coverage.receipt.activated ↔ id ∈ (auditGenerated c.grant).map Obligation.id :=
  GrantCoverage.activated_inventory_exact b c accepted id
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) (row : Obligation)
    (present : row ∈ auditGenerated c.grant) :
    ∃ assignment ∈ c.coverage.plan.assignments, assignment.obligation = row.id ∧
      ∃ evidence ∈ c.coverage.receipt.evidence,
        row.id ∈ evidence.obligations ∧ evidence.adapter = assignment.adapter ∧
        evidence.context = c.coverage.receipt.context ∧ evidence.nonce = c.coverage.receipt.nonce ∧
        ∀ other ∈ c.coverage.receipt.evidence, row.id ∈ other.obligations → other = evidence :=
  GrantCoverage.generated_evidence_owner_unique b c accepted row present
example (b : Binding) (c : GrantCoverage.Certificate)
    (accepted : GrantCoverage.certificateValid b c = true) (evidence : ReceiptCoverage.Evidence)
    (present : evidence ∈ c.coverage.receipt.evidence) (id : String) (covered : id ∈ evidence.obligations) :
    id ∈ (auditGenerated c.grant).map Obligation.id :=
  GrantCoverage.no_extra_generated_evidence b c accepted evidence present id covered

-- Independently construct a grant and full receipt certificate from arbitrary raw rules.
def auditIdentities (b : Binding) : Prop :=
  b.principal ≠ "" ∧ b.session ≠ "" ∧ b.tool ≠ "" ∧ b.artifact ≠ "" ∧
  b.call ≠ "" ∧ b.intent ≠ "" ∧ b.policy ≠ "" ∧ b.grant ≠ ""
def auditRules (rules : List Rule) : Prop :=
  (rules.map Rule.id).Nodup ∧
  (∀ r ∈ rules, r.id ≠ "" ∧ r.operation ≠ "" ∧ r.selector ≠ "" ∧
    (match r.conditions with | .map _ => true | _ => false) = true) ∧
  ((auditGeneratedRules rules).map Obligation.id).Nodup
def auditGrantFor (b : Binding) (rules : List Rule) : Grant :=
  {principal := b.principal, session := b.session, tool := b.tool, artifact := b.artifact,
   call := b.call, intent := b.intent, policy := b.policy, deployment := b.deployment,
   runtime := b.runtime, digest := b.grant, rules := rules}
def auditGrantCertificate (b : Binding) (rules : List Rule)
    (plans : List ReceiptCoverage.NativePlan) : GrantCoverage.Certificate :=
  let grant := auditGrantFor b rules
  {grant := grant, obligations := auditGenerated grant,
   coverage := auditCertificateFor b plans [] []}

theorem auditGrantCertificateProjection (b : Binding) (rules : List Rule)
    (plans : List ReceiptCoverage.NativePlan) :
    GrantCoverage.certificateFor b rules plans = auditGrantCertificate b rules plans := by rfl

example (b : Binding) (rules : List Rule) : auditGrantBound b (auditGrantFor b rules) :=
  GrantCoverage.constructed_grant_bound b rules
example (b : Binding) (rules : List Rule) (identities : auditIdentities b)
    (valid : auditRules rules) : auditValidGrant (auditGrantFor b rules) :=
  GrantCoverage.constructed_grant_valid b rules identities valid
example (b : Binding) (rules : List Rule) (plans : List ReceiptCoverage.NativePlan)
    (identities : auditIdentities b) (valid : auditRules rules)
    (partition : auditPartition plans)
    (matching : auditSameIDs (plans.flatMap ReceiptCoverage.NativePlan.obligations)
      ((auditGeneratedRules rules).map Obligation.id)) :
    GrantCoverage.certificateValid b (auditGrantCertificate b rules plans) = true := by
  exact GrantCoverage.useful_grant_partition b rules plans identities valid partition matching
example (b : Binding) (rules : List Rule) (plans : List ReceiptCoverage.NativePlan)
    (identities : auditIdentities b) (valid : auditRules rules)
    (partition : auditPartition plans)
    (matching : auditSameIDs (plans.flatMap ReceiptCoverage.NativePlan.obligations)
      ((auditGeneratedRules rules).map Obligation.id)) :
    GrantCoverage.certifiedRoute b (auditGrantCertificate b rules plans)
      [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] = true :=
  GrantCoverage.useful_grant_partition_route b rules plans identities valid partition matching

example (b : Binding) (c : GrantCoverage.Certificate) (events : List Event) :
    (GrantCoverage.runCertified b c events).phase = .running ↔
      GrantCoverage.certificateValid b c = true ∧
      events = [.authorize b true, .activate b true true, .go b] :=
  GrantCoverage.runCertified_running_iff b c events
example (b : Binding) (c : GrantCoverage.Certificate) (events : List Event) :
    (GrantCoverage.runCertified b c events).phase = .running ↔ auditValid b c ∧
      events = [.authorize b true, .activate b true true, .go b] :=
  GrantCoverage.runCertified_running_exact b c events
example (b : Binding) (c : GrantCoverage.Certificate) (events : List Event) :
    GrantCoverage.certifiedRoute b c events = true ↔
      GrantCoverage.certificateValid b c = true ∧
      events = [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] :=
  GrantCoverage.certifiedRoute_iff b c events
example (b : Binding) (c : GrantCoverage.Certificate) (events : List Event) :
    GrantCoverage.certifiedRoute b c events = true ↔ auditValid b c ∧
      events = [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] :=
  GrantCoverage.certifiedRoute_exact b c events
example (b : Binding) (c : GrantCoverage.Certificate) (events : List Event) :
    (GrantCoverage.runCertified b c events).binding = b :=
  GrantCoverage.runCertified_preserves_binding b c events
example (b : Binding) (c : GrantCoverage.Certificate)
    (invalid : GrantCoverage.certificateValid b c = false) (events : List Event) :
    (GrantCoverage.runCertified b c events).phase = .refused :=
  GrantCoverage.invalid_certificate_refuses_every_trace b c invalid events

-- A concrete nonempty two-rule, two-adapter example discharges every structural
-- premise. Only arbitrary nonempty caller identity fields remain parameters.
def usefulRules : List Rule :=
  [{id := "file", domain := .filesystem, operation := "read", selector := "/data/report",
    conditions := .map (.cons "subtree" (.bool false) .nil), requirement := .need,
    provenance := ["policy:1"], baseline := false},
   {id := "limit", domain := .resourceLimit, operation := "limit", selector := "cpu_ms",
    conditions := .map (.cons "maximum" (.int 1000) .nil), requirement := .need,
    provenance := ["policy:2"], baseline := true}]
def usefulPlans : List ReceiptCoverage.NativePlan :=
  [{adapter := "filesystem", digest := "native-filesystem", obligations := ["rule:file:operate"]},
   {adapter := "limits-and-complements", digest := "native-limits",
    obligations := ["rule:limit:operate"] ++
      auditDomains.map (fun domain => "domain:" ++ auditDomainName domain ++ ":deny_complement")}]
example (b : Binding) (identities : auditIdentities b) :
    GrantCoverage.certifiedRoute b (auditGrantCertificate b usefulRules usefulPlans)
      [.authorize b true, .activate b true true, .go b, .result b true, .cleanup true] = true := by
  apply GrantCoverage.useful_grant_partition_route b usefulRules usefulPlans identities
  · unfold GrantCoverage.RulesWellFormed GrantCoverage.generatedFromRules
      GrantCoverage.deriveRule GrantCoverage.denyComplement GrantCoverage.domains
      GrantCoverage.domainName GrantCoverage.isMap usefulRules
    decide
  · unfold ReceiptCoverage.WellFormedPartition ReceiptCoverage.allObligations
    decide
  · unfold ReceiptCoverage.SameIDs ReceiptCoverage.allObligations
    decide
end GrantAudit
"""

NEGATIVE_AUDITS = {
    "WrongBindingField": r"""import WorkerRoute
open WorkerRoute
example (b : Binding) : (run b []).binding.runtime = b.deployment := by
  simpa only [run, runFrom, initial] using (rfl : b.runtime = b.runtime)
""",
    "MissingReceiptField": r"""import ReceiptCoverage
open ReceiptCoverage
def incompleteReceipt : Receipt := {
  grant := "grant", plan := "plan", host := "host", context := "context",
  nonce := "nonce", artifact := "artifact", deployment := "",
  mode := .enforced, activated := ["obligation"], removedWants := [], evidence := []}
""",
    "WrongGeneratedSelector": r"""import GrantCoverage
open GrantCoverage
example (rule : Rule) : (deriveRule rule).selector = rule.operation := by
  exact (rfl : rule.selector = rule.selector)
""",
    "WrongTypedCondition": r"""import GrantCoverage
open GrantCoverage
example : Value.bool true = Value.int 1 := by
  exact (rfl : Value.bool true = Value.bool true)
""",
    "MissingGrantDigest": r"""import GrantCoverage
open GrantCoverage
def incompleteGrant : Grant := {
  principal := "principal", session := "session", tool := "tool", artifact := "artifact",
  call := "call", intent := "intent", policy := "policy", deployment := "",
  runtime := "", rules := []}
""",
}


class AuditFailure(Exception):
    """A captured audit/build condition failed."""


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def metadata(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": digest(data), "bytes": len(data)}


def lean_code_without_comments_or_strings(text: str) -> str:
    """Blank comments/string/character literals without hiding following code."""
    result: list[str] = []
    index = 0
    nesting = 0
    string = False
    while index < len(text):
        pair = text[index : index + 2]
        char = text[index]
        if nesting:
            if pair == "/-":
                nesting += 1
                index += 2
            elif pair == "-/":
                nesting -= 1
                index += 2
            else:
                result.append("\n" if char == "\n" else " ")
                index += 1
        elif string:
            if char == "\\":
                result.extend("  ")
                index += 2
            elif char == '"':
                result.append(" ")
                string = False
                index += 1
            else:
                result.append("\n" if char == "\n" else " ")
                index += 1
        elif pair == "/-":
            result.extend("  ")
            nesting = 1
            index += 2
        elif pair == "--":
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            result.extend(" " * (end - index))
            index = end
        elif char == "'" and (
            index == 0 or not (text[index - 1].isalnum() or text[index - 1] in "_'")
        ):
            # Lean identifiers may end in apostrophes. Blank only a complete,
            # finite character literal; never scan to an arbitrary later quote.
            literal = re.match(
                r"'(?:\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[^\r\n])|[^\\'\r\n])'",
                text[index:],
            )
            if literal:
                result.extend(" " * len(literal.group()))
                index += len(literal.group())
            else:
                result.append(char)
                index += 1
        elif char == '"':
            result.append(" ")
            string = True
            index += 1
        else:
            result.append(char)
            index += 1
    if nesting or string:
        raise AuditFailure("unterminated Lean comment/string")
    return "".join(result)


def source_hygiene(source: str, name: str) -> None:
    code = lean_code_without_comments_or_strings(source)
    identifiers = set(re.findall(r"[A-Za-z_][A-Za-z_0-9']*", code))
    bad = sorted(identifiers & FORBIDDEN_IDENTIFIERS)
    if bad:
        raise AuditFailure(f"{name}: prohibited proof bypass/declaration tokens: {bad}")
    if re.search(r"#\s*eval\b", code):
        raise AuditFailure(f"{name}: native/evaluator commands are not admitted")


def parse_axioms(output: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    pattern = re.compile(
        r"^'([A-Za-z_][A-Za-z_0-9'.]*)' "
        r"(?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)\s*$",
        re.MULTILINE,
    )
    for line in output.splitlines():
        if (
            "depends on axioms:" in line or "does not depend on any axioms" in line
        ) and not pattern.fullmatch(line):
            raise AuditFailure("malformed axiom query result")
    for match in pattern.finditer(output):
        name = match.group(1)
        if name not in REQUIRED_THEOREMS:
            raise AuditFailure(f"unexpected axiom query result: {name}")
        if name in found:
            raise AuditFailure(f"duplicate axiom query result: {name}")
        raw = match.group(2) or ""
        dependencies = [item.strip() for item in raw.split(",")] if raw.strip() else []
        if any(not item for item in dependencies) or len(set(dependencies)) != len(
            dependencies
        ):
            raise AuditFailure(f"{name}: malformed or repeated axiom dependencies")
        disallowed = sorted(set(dependencies) - ALLOWED_AXIOMS)
        if disallowed:
            raise AuditFailure(f"{name}: disallowed axiom dependencies: {disallowed}")
        found[name] = dependencies
    missing = sorted(set(REQUIRED_THEOREMS) - set(found))
    if missing:
        raise AuditFailure(f"missing required axiom results: {missing}")
    return found


def run_command(
    argv: list[str], cwd: Path, log: Path, report: dict, timeout: int
) -> subprocess.CompletedProcess:
    start = timestamp()
    clock = time.monotonic()
    command = {"argv": argv, "cwd": str(cwd), "started_at": start, "log": str(log)}
    report["commands"].append(command)
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        log.write_text(completed.stdout, encoding="utf-8")
        command["exit_code"] = completed.returncode
        command["finished_at"] = timestamp()
        command["elapsed_seconds"] = round(time.monotonic() - clock, 6)
        if completed.returncode != 0:
            raise AuditFailure(
                f"command failed ({completed.returncode}); see {log.name}"
            )
        return completed
    except subprocess.TimeoutExpired as exc:
        data = exc.stdout or b""
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        log.write_text(data, encoding="utf-8")
        command.update(
            {
                "timed_out": True,
                "finished_at": timestamp(),
                "elapsed_seconds": round(time.monotonic() - clock, 6),
            }
        )
        raise AuditFailure(f"command timed out; see {log.name}") from exc


def require_kernel_replay(
    lake: str,
    toolchain_root: Path,
    snapshot: Path,
    log: Path,
    report: dict,
    timeout: int,
) -> None:
    checker = toolchain_root / "bin" / "leanchecker"
    report["kernel_replay"] = {
        "available": checker.is_file(),
        "is_independent_implementation": False,
        "scope": "Lean's own kernel replay; not an external independent verifier.",
    }
    if not checker.is_file():
        raise AuditFailure(
            "required pinned-toolchain leanchecker executable is missing"
        )
    report["kernel_replay"].update({"path": str(checker), **metadata(checker)})
    run_command(
        [lake, "env", str(checker), "--fresh", "KernelAudit"],
        snapshot,
        log,
        report,
        timeout,
    )
    report["kernel_replay_checked"] = True


def check_negative_audits(
    lake: str, snapshot: Path, logs: Path, report: dict, timeout: int
) -> None:
    """Require the kernel front end to reject fixed malformed semantic witnesses.

    These are controls for the audit harness, not additional security proofs.
    Timeout, missing tool or infrastructure failure cannot count as rejection.
    """
    report["negative_audit_controls"] = []
    for name, source in NEGATIVE_AUDITS.items():
        path = snapshot / f"{name}.lean"
        path.write_text(source)
        log = logs / f"negative-{name}.log"
        try:
            run_command(
                [lake, "env", "lean", path.name], snapshot, log, report, timeout
            )
        except AuditFailure:
            command = report["commands"][-1]
            output = log.read_text() if log.is_file() else ""
            if command.get("exit_code") != 1 or not any(
                marker in output.lower()
                for marker in ("type mismatch", "unsolved goals", "fields missing")
            ):
                raise AuditFailure(
                    f"negative control did not reach its expected type error: {name}"
                ) from None
            report["negative_audit_controls"].append(
                {
                    "name": name,
                    "source": metadata(path),
                    "rejected": True,
                    "log": str(log),
                }
            )
        else:
            raise AuditFailure(
                f"invalid semantic audit unexpectedly typechecked: {name}"
            )


def capture_before(project: Path, snapshot: Path) -> dict:
    result = {}
    for name in SOURCE_FILES:
        original = project / name
        data = original.read_bytes()
        (snapshot / name).write_bytes(data)
        result[name] = {"sha256": digest(data), "bytes": len(data)}
    return result


def capture_after(project: Path, after: Path) -> dict:
    result = {}
    for name in SOURCE_FILES:
        path = project / name
        try:
            data = path.read_bytes()
            (after / name).write_bytes(data)
            result[name] = {"sha256": digest(data), "bytes": len(data)}
        except OSError as exc:
            result[name] = {"error": str(exc)}
    return result


def audit(args: argparse.Namespace) -> int:
    project = Path(__file__).resolve().parent
    output = Path(args.output).absolute()
    # No files/logs from an earlier observation may be replaced.
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(f"refusing existing output directory: {output}", file=sys.stderr)
        return 2
    snapshot = output / "snapshot"
    after = output / "source-after"
    logs = output / "logs"
    artifacts = output / "artifacts"
    for directory in (snapshot, after, logs, artifacts):
        directory.mkdir()
    report = {
        "schema_version": 3,
        "kind": "worker-route-grant-lean-model-audit",
        "protocol": "worker-route-grant-v3",
        "started_at": timestamp(),
        "source_project": str(project),
        "output": str(output),
        "passed": False,
        "model_proved": False,
        "kernel_typecheck_passed": False,
        "kernel_replay_checked": False,
        "independent_checker_verified": False,
        "source_refinement_proved": False,
        "runtime_refinement_proved": False,
        "compiler_refinement_proved": False,
        "decoder_refinement_proved": False,
        "os_refinement_proved": False,
        "system_complete": False,
        "source_stable": False,
        "required_theorems": list(REQUIRED_THEOREMS),
        "allowed_standard_axioms": sorted(ALLOWED_AXIOMS),
        "commands": [],
        "issues": [],
        "scope": "Kernel-checked captured finite model only; positive runtime fact provenance and deployment correspondence are separate obligations.",
        "unproved_obligations": [
            "Python source call placement and all native effect paths correspond to the model.",
            "Grant, obligation, plan and receipt fields faithfully project the actual admitted Python records; authorized grant provenance, digest preimages, adapter signatures, freshness, expiry, support claims and waiver authorization remain outside this finite composition model.",
            "The selected Linux obligation generator corresponds to the checked full-record rule expansion and nine fixed complements; custom additional-obligation profiles are not covered.",
            "Every authorization, identity, support, activation, result, cleanup and cancellation fact is truthful, complete and ordered.",
            "JSON encoding/decoding preserves the model inputs and rejects ambiguous or unsupported inputs.",
            "The Lean compiler, C toolchain, binary loader and deployed executable preserve the checked definitions.",
            "The operating system, namespace, seccomp, LSM and lifetime mechanisms enforce the claimed native properties.",
        ],
    }
    complete = False
    try:
        report["source_before"] = capture_before(project, snapshot)
        toolchain = (snapshot / "lean-toolchain").read_text().strip()
        report["pinned_toolchain"] = toolchain
        if toolchain != PINNED_TOOLCHAIN:
            raise AuditFailure(f"unexpected toolchain pin: {toolchain}")
        for name in ("WorkerRoute.lean", "ReceiptCoverage.lean", "GrantCoverage.lean", "Main.lean"):
            source_hygiene((snapshot / name).read_text(), name)
        report["source_hygiene_passed"] = True
        run_command(
            [sys.executable, "-m", "unittest", "-v", "test_check"],
            snapshot,
            logs / "driver-tests.log",
            report,
            args.timeout,
        )
        report["driver_tests_passed"] = True
        lake = shutil.which(args.lake)
        if lake is None:
            raise AuditFailure(f"lake executable unavailable: {args.lake}")
        lake = str(Path(lake).absolute())
        report["lake_executable"] = {"path": lake, **metadata(Path(lake))}
        report["lake_version"] = run_command(
            [lake, "--version"],
            snapshot,
            logs / "lake-version.log",
            report,
            args.timeout,
        ).stdout.strip()
        version = run_command(
            [lake, "env", "lean", "--version"],
            snapshot,
            logs / "lean-version.log",
            report,
            args.timeout,
        ).stdout.strip()
        report["lean_version"] = version
        if not re.search(r"\bversion 4\.34\.1\b", version):
            raise AuditFailure(
                "active Lean version does not match the pinned toolchain"
            )
        prefix = run_command(
            [lake, "env", "lean", "--print-prefix"],
            snapshot,
            logs / "lean-prefix.log",
            report,
            args.timeout,
        ).stdout.strip()
        toolchain_root = Path(prefix)
        report["lean_executable"] = {
            "path": str(toolchain_root / "bin" / "lean"),
            **metadata(toolchain_root / "bin" / "lean"),
        }
        run_command(
            [lake, "-v", "build", "WorkerRoute", "ReceiptCoverage", "GrantCoverage", "workerRoute"],
            snapshot,
            logs / "build.log",
            report,
            args.timeout,
        )
        audit_source = (
            AUDIT_SOURCE
            + GRANT_AUDIT_SOURCE
            + "\n"
            + "\n".join(f"#print axioms {name}" for name in REQUIRED_THEOREMS)
            + "\n"
        )
        source_hygiene(audit_source, "KernelAudit.lean")
        (snapshot / "KernelAudit.lean").write_text(audit_source)
        report["generated_audit"] = metadata(snapshot / "KernelAudit.lean")
        audit_result = run_command(
            [
                lake,
                "env",
                "lean",
                "KernelAudit.lean",
                "-o",
                ".lake/build/lib/lean/KernelAudit.olean",
            ],
            snapshot,
            logs / "kernel-audit.log",
            report,
            args.timeout,
        )
        report["axiom_dependencies"] = parse_axioms(audit_result.stdout)
        report["kernel_typecheck_passed"] = True
        check_negative_audits(lake, snapshot, logs, report, args.timeout)
        require_kernel_replay(
            lake,
            toolchain_root,
            snapshot,
            logs / "kernel-replay.log",
            report,
            args.timeout,
        )
        binary = snapshot / ".lake" / "build" / "bin" / "workerRoute"
        shutil.copy2(binary, artifacts / "workerRoute")
        report["binary"] = {"path": str(artifacts / "workerRoute"), **metadata(binary)}
        report["ci_environment"] = {
            "LANGGRAPH_LEAN_WORKER_BINARY": str(artifacts / "workerRoute"),
        }
        report["ci_requirements"] = [
            "Run the Lean bridge and selected native lifecycle test files against ci_environment's captured binary.",
            "Required CI must fail on missing binary or skipped selected-route tests; an optional local skip is not CI evidence.",
            "Runtime test results remain separate from this model proof report.",
        ]
        if metadata(artifacts / "workerRoute") != metadata(binary):
            raise AuditFailure("copied executable bytes differ from build output")
        for name in ("WorkerRoute", "ReceiptCoverage", "GrantCoverage", "Main", "KernelAudit"):
            compiled = snapshot / ".lake" / "build" / "lib" / "lean" / f"{name}.olean"
            if not compiled.is_file():
                raise AuditFailure(f"required compiled module is missing: {name}")
            shutil.copy2(compiled, artifacts / compiled.name)
        complete = True
    except (AuditFailure, OSError, ValueError) as exc:
        report["issues"].append(str(exc))
    finally:
        report["source_after"] = capture_after(project, after)
        report["snapshot_after"] = {
            name: metadata(snapshot / name)
            if (snapshot / name).is_file()
            else {"error": "missing"}
            for name in SOURCE_FILES
        }
        report["source_stable"] = (
            report.get("source_before") == report["source_after"]
            and report.get("source_before") == report["snapshot_after"]
        )
        if not report["source_stable"]:
            report["issues"].append(
                "project source bytes changed or became unavailable during audit"
            )
        report["model_proved"] = complete and report["source_stable"]
        report["passed"] = report["model_proved"]
        report["finished_at"] = timestamp()
        (output / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "model_proved": report["model_proved"],
                "report": str(output / "report.json"),
                "issues": report["issues"],
            }
        )
    )
    return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        required=True,
        help="new evidence directory; existing paths are refused",
    )
    parser.add_argument(
        "--lake",
        default=os.environ.get("LAKE", "lake"),
        help="Lake executable (default: LAKE or PATH)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="maximum seconds per build/audit subprocess",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return audit(args)


if __name__ == "__main__":
    raise SystemExit(main())
