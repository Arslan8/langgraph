import TranslationFailure
namespace ProductionCapture
def emitted : List Char := [Char.ofNat 106, Char.ofNat 111, Char.ofNat 115, Char.ofNat 92, Char.ofNat 117, Char.ofNat 48, Char.ofNat 48, Char.ofNat 101, Char.ofNat 57]
theorem emitted_is_counterexample : emitted = "jos\\u00e9".toList := by rfl
theorem production_output_not_cedar_body : ¬ TranslationFailure.Body emitted := by
  rw [emitted_is_counterexample]
  exact TranslationFailure.json_escape_not_cedar
#print axioms production_output_not_cedar_body
end ProductionCapture
