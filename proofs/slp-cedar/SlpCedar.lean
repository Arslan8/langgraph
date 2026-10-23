import Std

/-!
A model of the v2 object-policy query boundary, after successful SLP expansion.
This is not a verification of the Python implementation or the Cedar interpreter.
Policy predicates below denote successful, error-free policy evaluation.
-/
namespace SlpCedar

structure Line where
  identity : Nat
  classId : Nat
  operation : Nat
  resource : Nat
  need : Bool
  deriving DecidableEq, Repr

structure Request where
  principal : Nat
  tool : Nat
  classId : Nat
  operation : Nat
  resource : Nat
  need : Bool
  deriving DecidableEq, Repr

/-- Typed analogue of `object_policy._request`; wire encoding is outside the model. -/
def query (principal tool : Nat) (line : Line) : Request :=
  ⟨principal, tool, line.classId, line.operation, line.resource, line.need⟩

/-- The generated candidate permit constrains principal and action, not resource. -/
def candidatePermit (principal : Nat) (line : Line) (q : Request) : Bool :=
  q.principal == principal && q.classId == line.classId && q.operation == line.operation

theorem candidate_permits_generated_query (p t : Nat) (l : Line) :
    candidatePermit p l (query p t l) = true := by
  simp [candidatePermit, query]

/-- Cedar's permit-exists / forbid-overrides combination rule. -/
def cedarAllows (permit forbid : Bool) : Bool := permit && !forbid

structure Policies where
  owner : Request → Bool
  principal : Request → Bool
  share : Request → Bool
  forbid : Request → Bool

/-- Independent source-side decision on a normalized SLP line. -/
def sourceAllows (s : Policies) (p t : Nat) (l : Line) : Bool :=
  s.owner (query p t l) &&
    (s.principal (query p t l) || s.share (query p t l)) &&
    !s.forbid (query p t l)

/-- Three separate Cedar queries, as in `CedarObjectAuthorizer.authorize`. -/
def targetAllows (s : Policies) (p t : Nat) (l : Line) : Bool :=
  cedarAllows (s.owner (query p t l)) false &&
    cedarAllows (s.principal (query p t l) || s.share (query p t l)) false &&
    cedarAllows (candidatePermit p l (query p t l)) (s.forbid (query p t l))

theorem query_sound_complete (s : Policies) (p t : Nat) (l : Line) :
    targetAllows s p t l = sourceAllows s p t l := by
  simp [targetAllows, sourceAllows, cedarAllows, candidate_permits_generated_query]

/-- Recursive model of the Python loop: denied NEED aborts, denied WANT skips. -/
def collect (allow : Line → Bool) : List Line → Option (List Line)
  | [] => some []
  | l :: ls =>
    if allow l then (collect allow ls).map (l :: ·)
    else if l.need then none else collect allow ls

def needsSatisfied (allow : Line → Bool) (ls : List Line) : Prop :=
  ∀ l ∈ ls, l.need = true → allow l = true

theorem collect_formula (allow : Line → Bool) (ls : List Line) :
    collect allow ls =
      if ls.all (fun l => !l.need || allow l) then some (ls.filter allow) else none := by
  induction ls with
  | nil => rfl
  | cons l ls ih =>
    cases ha : allow l <;> cases hn : l.need <;>
      cases ht : ls.all (fun l => !l.need || allow l) <;>
      simp [collect, ih, ha, hn, ht]

theorem collect_exact (allow : Line → Bool) (ls out : List Line) :
    collect allow ls = some out ↔
      needsSatisfied allow ls ∧ out = ls.filter allow := by
  rw [collect_formula]
  have hneeds : ls.all (fun l => !l.need || allow l) = true ↔
      needsSatisfied allow ls := by
    simp only [List.all_eq_true, Bool.or_eq_true]
    constructor
    · intro h l hl hn
      rcases h l hl with hfalse | hallow
      · simp [hn] at hfalse
      · exact hallow
    · intro h l hl
      cases hn : l.need
      · exact Or.inl rfl
      · exact Or.inr (h l hl hn)
  split
  · rename_i h
    simp only [Option.some.injEq, hneeds.mp h, true_and]
    exact eq_comm
  · rename_i h
    simp only [reduceCtorEq, false_iff, not_and]
    intro hn
    exact False.elim (h (hneeds.mpr hn))

/-- Call gates include owner/MAC call checks and, only for empty manifests,
the principal call check. `operational` covers validation and CLI success. -/
structure Gates where
  operational : Bool
  ownerCall : Bool
  principalCall : Bool
  macCall : Bool

def callGate (g : Gates) (ls : List Line) : Bool :=
  g.operational && g.ownerCall && g.macCall &&
    (if ls.isEmpty then g.principalCall else true)

/-- `supported` includes explicitly accepted enforcement waivers. -/
def authorize (g : Gates) (allow supported : Line → Bool)
    (ls : List Line) : Option (List Line) :=
  if callGate g ls then
    match collect allow ls with
    | none => none
    | some out =>
      if (!ls.isEmpty && out.isEmpty) || !(out.all supported) then none else some out
  else none

/-- Declarative contract: exact authorized subset, all NEEDs, nonempty resource
access, call eligibility, and support for every returned line. -/
def ValidGrant (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) : Prop :=
  callGate g ls = true ∧ needsSatisfied allow ls ∧
    out = ls.filter allow ∧
    (!ls.isEmpty && out.isEmpty) = false ∧ out.all supported = true

theorem authorize_sound_complete (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) :
    authorize g allow supported ls = some out ↔ ValidGrant g allow supported ls out := by
  unfold authorize ValidGrant
  by_cases hg : callGate g ls = true
  · simp only [hg, ↓reduceIte, true_and]
    cases hc : collect allow ls with
    | none =>
      simp only [reduceCtorEq, false_iff]
      intro ⟨hn, heq, _⟩
      have h := (collect_exact allow ls out).mpr ⟨hn, heq⟩
      rw [hc] at h
      contradiction
    | some result =>
      have h := collect_exact allow ls out
      simp only [hc, Option.some.injEq] at h
      rw [← @and_assoc (needsSatisfied allow ls) (out = ls.filter allow), ← h]
      by_cases hb : ((!ls.isEmpty && result.isEmpty) || !(result.all supported)) = true
      · simp only [hb, ↓reduceIte, reduceCtorEq, false_iff]
        intro ⟨heq, hn, hs⟩
        subst out
        simp [hn, hs] at hb
      · simp only [hb, Bool.false_eq_true, ↓reduceIte, Option.some.injEq]
        have good : (!ls.isEmpty && result.isEmpty) = false ∧ result.all supported = true := by
          cases hn : (!ls.isEmpty && result.isEmpty) <;>
            cases hs : result.all supported <;> simp_all
        constructor
        · intro heq; subst out; exact ⟨rfl, good⟩
        · exact fun heq => heq.1
  · simp only [hg, ↓reduceIte, reduceCtorEq, false_and]

theorem slp_to_cedar_sound_complete (g : Gates) (s : Policies) (p t : Nat)
    (supported : Line → Bool) (ls out : List Line) :
    authorize g (targetAllows s p t) supported ls = some out ↔
      ValidGrant g (sourceAllows s p t) supported ls out := by
  have heq : targetAllows s p t = sourceAllows s p t :=
    funext (query_sound_complete s p t)
  rw [heq]
  exact authorize_sound_complete g _ supported ls out

/-- No authority can be introduced by the collector. -/
theorem no_amplification (g : Gates) (allow supported : Line → Bool)
    (ls out : List Line) (h : authorize g allow supported ls = some out) :
    ∀ l ∈ out, l ∈ ls ∧ allow l = true := by
  have hv := (authorize_sound_complete g allow supported ls out).mp h
  rw [hv.2.2.1]
  intro l hl
  simpa using hl

/-- An unrestricted policy-equivalence claim is false: candidate permits are
ephemeral and must only be evaluated on their corresponding generated query. -/
example :
    let l : Line := ⟨0, 1, 2, 3, true⟩
    let other : Request := ⟨0, 0, 1, 2, 999, true⟩
    candidatePermit 0 l other = true ∧ other.resource ≠ l.resource := by
  decide

#print axioms query_sound_complete
#print axioms collect_exact
#print axioms slp_to_cedar_sound_complete
#print axioms no_amplification

end SlpCedar
