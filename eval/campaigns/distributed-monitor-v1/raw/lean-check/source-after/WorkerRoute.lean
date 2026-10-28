import Std

/-!
A finite decision model for one synchronous worker computation. The Python/OS
bridge must establish the truth and provenance of each supplied fact. This file
does not prove that Python follows the model or that the OS enforces a plan.
-/
namespace WorkerRoute

/-- PID alone is insufficient: capture the process start identity as well. -/
structure WorkerIdentity where
  pid : String
  startTime : String
  bootId : String
  deriving DecidableEq, Repr

/-- Canonical identities, captured once and compared without omission. -/
structure Binding where
  principal : String
  session : String
  call : String
  intent : String
  policy : String
  tool : String
  artifact : String
  deployment : String
  runtime : String
  grant : String
  plan : String
  nonce : String
  host : String
  context : String
  worker : WorkerIdentity
  deriving DecidableEq, Repr

inductive Phase where
  | prepared | authorized | activated | running | resultReady | ready | refused
  deriving DecidableEq, Repr

structure State where
  binding : Binding
  phase : Phase
  deriving DecidableEq, Repr

/-- Facts must be supplied in observed order. Cancellation is never a success. -/
inductive Event where
  | authorize (observed : Binding) (authorized : Bool)
  | activate (observed : Binding) (supported activationConfirmed : Bool)
  | go (observed : Binding)
  | result (observed : Binding) (resultAccepted : Bool)
  | cleanup (confirmed : Bool)
  | cancel
  deriving DecidableEq, Repr

def initial (binding : Binding) : State := ⟨binding, .prepared⟩

/-- Every unexpected transition refuses, including events after readiness. -/
def nextPhase (binding : Binding) : Phase → Event → Phase
  | .prepared, .authorize observed authorized =>
      if observed = binding ∧ authorized = true then .authorized else .refused
  | .authorized, .activate observed supported confirmed =>
      if observed = binding ∧ supported = true ∧ confirmed = true
      then .activated else .refused
  | .activated, .go observed =>
      if observed = binding then .running else .refused
  | .running, .result observed accepted =>
      if observed = binding ∧ accepted = true then .resultReady else .refused
  | .resultReady, .cleanup confirmed =>
      if confirmed then .ready else .refused
  | _, _ => .refused

def step (state : State) (event : Event) : State :=
  ⟨state.binding, nextPhase state.binding state.phase event⟩

def runFrom (state : State) : List Event → State
  | [] => state
  | event :: events => runFrom (step state event) events

def run (binding : Binding) (events : List Event) : State :=
  runFrom (initial binding) events

def allowsSuccess (state : State) : Bool := decide (state.phase = .ready)

def decideRoute (binding : Binding) (events : List Event) : Bool :=
  allowsSuccess (run binding events)

/-- The concrete nonempty useful route, parameterized by the entire binding. -/
def successfulEvents (binding : Binding) : List Event :=
  [.authorize binding true, .activate binding true true, .go binding,
    .result binding true, .cleanup true]

/-- Remaining legal events for each state; refusal has no successful suffix. -/
def completion (binding : Binding) : Phase → Option (List Event)
  | .prepared => some (successfulEvents binding)
  | .authorized =>
      some [.activate binding true true, .go binding, .result binding true, .cleanup true]
  | .activated => some [.go binding, .result binding true, .cleanup true]
  | .running => some [.result binding true, .cleanup true]
  | .resultReady => some [.cleanup true]
  | .ready => some []
  | .refused => none

theorem step_preserves_binding (state : State) (event : Event) :
    (step state event).binding = state.binding := rfl

theorem runFrom_preserves_binding (state : State) (events : List Event) :
    (runFrom state events).binding = state.binding := by
  induction events generalizing state with
  | nil => rfl
  | cons event events ih => exact ih (step state event)

theorem go_requires_activation (state : State) (observed : Binding) :
    (step state (.go observed)).phase = .running ↔
      state.phase = .activated ∧ observed = state.binding := by
  cases state with
  | mk binding phase =>
    cases phase <;> simp [step, nextPhase]

theorem cancel_refuses (state : State) :
    (step state .cancel).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem unknown_cleanup_refuses (state : State) :
    (step state (.cleanup false)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem unsupported_refuses (state : State) (observed : Binding) (confirmed : Bool) :
    (step state (.activate observed false confirmed)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem unconfirmed_activation_refuses (state : State) (observed : Binding)
    (supported : Bool) :
    (step state (.activate observed supported false)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem refused_is_sticky (binding : Binding) (events : List Event) :
    (runFrom ⟨binding, .refused⟩ events).phase = .refused := by
  induction events with
  | nil => rfl
  | cons event events ih =>
    cases event <;> simpa [runFrom, step, nextPhase] using ih

/-- Exact characterization, not merely a necessary condition or deny-all proof. -/
theorem completion_exact (state : State) (events : List Event) :
    (runFrom state events).phase = .ready ↔
      some events = completion state.binding state.phase := by
  induction events generalizing state with
  | nil =>
    cases state with
    | mk binding phase => cases phase <;> simp [runFrom, completion, successfulEvents]
  | cons event events ih =>
    cases state with
    | mk binding phase =>
      cases event with
      | authorize observed authorized =>
        by_cases h : observed = binding
        · subst observed
          cases phase <;> cases authorized <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents]
        · cases phase <;> cases authorized <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents, h]
      | activate observed supported confirmed =>
        by_cases h : observed = binding
        · subst observed
          cases phase <;> cases supported <;> cases confirmed <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents]
        · cases phase <;> cases supported <;> cases confirmed <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents, h]
      | go observed =>
        by_cases h : observed = binding
        · subst observed
          cases phase <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents]
        · cases phase <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents, h]
      | result observed accepted =>
        by_cases h : observed = binding
        · subst observed
          cases phase <;> cases accepted <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents]
        · cases phase <;> cases accepted <;>
            simp [runFrom, ih, step, nextPhase, completion, successfulEvents, h]
      | cleanup confirmed =>
        cases phase <;> cases confirmed <;>
          simp [runFrom, ih, step, nextPhase, completion, successfulEvents]
      | cancel =>
        cases phase <;>
          simp [runFrom, ih, step, nextPhase, completion, successfulEvents]

theorem success_iff_exact_route (binding : Binding) (events : List Event) :
    decideRoute binding events = true ↔ events = successfulEvents binding := by
  simp [decideRoute, allowsSuccess, run, completion_exact, initial, completion]

theorem useful_route_succeeds (binding : Binding) :
    decideRoute binding (successfulEvents binding) = true :=
  (success_iff_exact_route binding _).mpr rfl

theorem runFrom_append (state : State) (first second : List Event) :
    runFrom state (first ++ second) = runFrom (runFrom state first) second := by
  induction first generalizing state with
  | nil => rfl
  | cons event events ih => exact ih (step state event)

theorem run_preserves_binding (binding : Binding) (events : List Event) :
    (run binding events).binding = binding :=
  runFrom_preserves_binding (initial binding) events

theorem authorization_denial_refuses (state : State) (observed : Binding) :
    (step state (.authorize observed false)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem activation_requires_authorization (state : State) (observed : Binding)
    (supported confirmed : Bool) :
    (step state (.activate observed supported confirmed)).phase = .activated ↔
      state.phase = .authorized ∧ observed = state.binding ∧
        supported = true ∧ confirmed = true := by
  cases state with
  | mk binding phase => cases phase <;> simp [step, nextPhase]

theorem authorize_mismatch_refuses (state : State) (observed : Binding)
    (authorized : Bool) (mismatch : observed ≠ state.binding) :
    (step state (.authorize observed authorized)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h, mismatch]

theorem activation_mismatch_refuses (state : State) (observed : Binding)
    (supported confirmed : Bool) (mismatch : observed ≠ state.binding) :
    (step state (.activate observed supported confirmed)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h, mismatch]

theorem go_mismatch_refuses (state : State) (observed : Binding)
    (mismatch : observed ≠ state.binding) :
    (step state (.go observed)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h, mismatch]

theorem result_mismatch_refuses (state : State) (observed : Binding)
    (accepted : Bool) (mismatch : observed ≠ state.binding) :
    (step state (.result observed accepted)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h, mismatch]

theorem result_failure_refuses (state : State) (observed : Binding) :
    (step state (.result observed false)).phase = .refused := by
  cases h : state.phase <;> simp [step, nextPhase, h]

theorem refused_cannot_recover (state : State) (events : List Event)
    (refusal : state.phase = .refused) :
    allowsSuccess (runFrom state events) = false := by
  cases state with
  | mk binding phase =>
    simp only at refusal
    subst phase
    simp [allowsSuccess, refused_is_sticky]

theorem cancellation_cannot_succeed (state : State) (events : List Event) :
    allowsSuccess (runFrom (step state .cancel) events) = false :=
  refused_cannot_recover _ _ (cancel_refuses state)

theorem unknown_cleanup_cannot_succeed (state : State) (events : List Event) :
    allowsSuccess (runFrom (step state (.cleanup false)) events) = false :=
  refused_cannot_recover _ _ (unknown_cleanup_refuses state)

/-- A reached activation state has exactly the matching authorization prefix. -/
theorem activated_trace_exact (binding : Binding) (events : List Event) :
    (run binding events).phase = .activated ↔
      events = [.authorize binding true, .activate binding true true] := by
  constructor
  · intro reached
    let suffix := [Event.go binding, .result binding true, .cleanup true]
    have ready : (runFrom (run binding events) suffix).phase = .ready := by
      apply (completion_exact _ _).mpr
      rw [reached, run_preserves_binding]
      rfl
    have whole : (run binding (events ++ suffix)).phase = .ready := by
      simpa [run, runFrom_append] using ready
    have exactRoute : events ++ suffix = successfulEvents binding := by
      apply (success_iff_exact_route _ _).mp
      simpa [decideRoute, allowsSuccess] using whole
    have appendEq : events ++ suffix =
        [.authorize binding true, .activate binding true true] ++ suffix := by
      simpa [successfulEvents, suffix] using exactRoute
    exact List.append_cancel_right appendEq
  · intro exactRoute
    subst events
    simp [run, runFrom, initial, step, nextPhase]

/-- GO can be accepted only after matching authorization and activation. -/
theorem go_requires_matching_authorized_activation (binding observed : Binding)
    (events : List Event) :
    (step (run binding events) (.go observed)).phase = .running ↔
      events = [.authorize binding true, .activate binding true true] ∧
        observed = binding := by
  rw [go_requires_activation, activated_trace_exact, run_preserves_binding]

/-- A running state has exactly the nonempty authorize/activate/GO prefix. -/
theorem running_trace_exact (binding : Binding) (events : List Event) :
    (run binding events).phase = .running ↔
      events = [.authorize binding true, .activate binding true true, .go binding] := by
  constructor
  · intro reached
    let suffix := [Event.result binding true, .cleanup true]
    have ready : (runFrom (run binding events) suffix).phase = .ready := by
      apply (completion_exact _ _).mpr
      rw [reached, run_preserves_binding]
      rfl
    have whole : (run binding (events ++ suffix)).phase = .ready := by
      simpa [run, runFrom_append] using ready
    have exactRoute : events ++ suffix = successfulEvents binding := by
      apply (success_iff_exact_route _ _).mp
      simpa [decideRoute, allowsSuccess] using whole
    have appendEq : events ++ suffix =
        [.authorize binding true, .activate binding true true, .go binding] ++ suffix := by
      simpa [successfulEvents, suffix] using exactRoute
    exact List.append_cancel_right appendEq
  · intro exactRoute
    subst events
    simp [run, runFrom, initial, step, nextPhase]

theorem success_requires_confirmed_cleanup (binding : Binding) (events : List Event)
    (success : decideRoute binding events = true) :
    ∃ before, events = before ++ [.cleanup true] := by
  rw [(success_iff_exact_route _ _).mp success]
  exact ⟨[.authorize binding true, .activate binding true true,
    .go binding, .result binding true], rfl⟩

theorem success_excludes_cancellation (binding : Binding) (events : List Event)
    (success : decideRoute binding events = true) :
    Event.cancel ∉ events := by
  rw [(success_iff_exact_route _ _).mp success]
  simp [successfulEvents]

theorem cancellation_anywhere_refuses (binding : Binding) (before after : List Event) :
    decideRoute binding (before ++ .cancel :: after) = false := by
  simpa [decideRoute, run, runFrom_append, runFrom] using
    cancellation_cannot_succeed (run binding before) after

theorem unknown_cleanup_anywhere_refuses (binding : Binding) (before after : List Event) :
    decideRoute binding (before ++ .cleanup false :: after) = false := by
  simpa [decideRoute, run, runFrom_append, runFrom] using
    unknown_cleanup_cannot_succeed (run binding before) after

end WorkerRoute

#print axioms WorkerRoute.success_iff_exact_route
#print axioms WorkerRoute.useful_route_succeeds
#print axioms WorkerRoute.go_requires_matching_authorized_activation
#print axioms WorkerRoute.cancellation_anywhere_refuses
#print axioms WorkerRoute.unknown_cleanup_anywhere_refuses
