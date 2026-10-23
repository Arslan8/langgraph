import Std

/-!
Cedar string-body grammar, restricted only by *removing* checks: unicode digits,
hex digits and raw control characters are left unchecked. This overapproximation
is sufficient to refute JSON's unbraced unicode escapes. The constructors follow
https://docs.cedarpolicy.com/syntax-grammar.html (STR).
This does not formalize the full Cedar parser or Python execution.
-/
namespace TranslationFailure

inductive Body : List Char → Prop where
  | empty : Body []
  | raw (c : Char) (rest : List Char) :
      c ≠ '\\' → c ≠ '"' → Body rest → Body (c :: rest)
  | short (c : Char) (rest : List Char) :
      c ∈ ['"', '\\', 'n', 'r', 't', '0'] → Body rest → Body ('\\' :: c :: rest)
  | hex (a b : Char) (rest : List Char) :
      Body rest → Body ('\\' :: 'x' :: a :: b :: rest)
  | unicode (digits rest : List Char) :
      Body rest → Body ('\\' :: 'u' :: '{' :: (digits ++ '}' :: rest))

theorem raw_tail {c : Char} {rest : List Char} (hc : c ≠ '\\')
    (h : Body (c :: rest)) : Body rest := by
  cases h with
  | raw _ _ _ _ tail => exact tail
  | short _ _ _ _ => exact False.elim (hc rfl)
  | hex _ _ _ _ => exact False.elim (hc rfl)
  | unicode _ _ _ => exact False.elim (hc rfl)

theorem unbraced_unicode_rejected (rest : List Char) :
    ¬ Body ('\\' :: 'u' :: '0' :: rest) := by
  intro h
  cases h with
  | raw _ _ hslash _ _ => exact hslash rfl
  | short _ _ hshort _ => simp at hshort

theorem json_escape_not_cedar : ¬ Body "jos\\u00e9".toList := by
  intro h
  have hj := raw_tail (by decide : 'j' ≠ '\\') h
  have ho := raw_tail (by decide : 'o' ≠ '\\') hj
  have hs := raw_tail (by decide : 's' ≠ '\\') ho
  exact unbraced_unicode_rejected _ hs

/-- Unescaped Unicode is a valid string body in this grammar. -/
theorem raw_unicode_valid : Body "josé".toList := by
  apply Body.raw <;> try decide
  apply Body.raw <;> try decide
  apply Body.raw <;> try decide
  apply Body.raw <;> try decide
  exact Body.empty

#print axioms json_escape_not_cedar
#print axioms raw_unicode_valid
end TranslationFailure
