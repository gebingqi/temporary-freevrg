/**
 * @name Missing upper-bound check before array or descriptor use
 * @description Detects externally controlled integer values used as array indexes or descriptor counts without an upper-bound guard.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/missing-array-bounds-check-on-network-controlled-index
 * @tags security
 */

import cpp

predicate sameFunction(Expr a, Expr b) {
  exists(Function f |
    a.getEnclosingFunction() = f and
    b.getEnclosingFunction() = f
  )
}

predicate beforeUse(Element guard, Expr use) {
  guard.getLocation().getFile() = use.getLocation().getFile() and
  guard.getLocation().getStartLine() <= use.getLocation().getStartLine()
}

predicate textMentions(Element e, Expr v) {
  e.toString().matches("%" + v.toString() + "%")
}

predicate isKnownDescriptorSource(Expr e) {
  exists(FunctionCall fc |
    fc = e and
    fc.getTarget().hasName("vq_getchain")
  )
}

predicate isExternalIntegerLike(Expr e) {
  e.toString().matches("%->%") or
  e.toString().matches("%.%") or
  e.toString().regexpMatch("(?i).*(idx|index|epid|htype|count|cnt|num|len|iov|n).*") or
  isKnownDescriptorSource(e)
}

predicate isArrayIndexUse(Expr idx, Expr use) {
  exists(ArrayExpr ae |
    use = ae and
    idx = ae.getArrayOffset()
  )
}

predicate isDescriptorSensitiveCall(Expr idx, Expr use) {
  exists(FunctionCall fc, int i |
    use = fc and
    idx = fc.getArgument(i) and
    (
      fc.getTarget().getName().regexpMatch("(?i).*(iov|desc|chain|vq).*") or
      fc.toString().regexpMatch("(?i).*(iov|desc|chain|vq).*")
    )
  )
}

predicate isDangerousUse(Expr idx, Expr use) {
  isArrayIndexUse(idx, use) or
  isDescriptorSensitiveCall(idx, use)
}

predicate isRangeCheckFor(Expr cond, Expr idx) {
  textMentions(cond, idx) and
  (
    cond.toString().matches("%>=%") or
    cond.toString().matches("%>%") or
    cond.toString().matches("%<=%") or
    cond.toString().matches("%<%")
  )
}

predicate hasUpperBoundGuard(Expr idx, Expr use) {
  exists(IfStmt ifs |
    sameFunction(idx, use) and
    beforeUse(ifs, use) and
    isRangeCheckFor(ifs.getCondition(), idx)
  )
  or
  exists(FunctionCall assertCall |
    sameFunction(idx, use) and
    beforeUse(assertCall, use) and
    assertCall.getTarget().hasName("assert") and
    textMentions(assertCall, idx) and
    (
      assertCall.toString().matches("%>=%") or
      assertCall.toString().matches("%>%") or
      assertCall.toString().matches("%<=%") or
      assertCall.toString().matches("%<%")
    )
  )
}

from Expr idx, Expr use
where
  isExternalIntegerLike(idx) and
  isDangerousUse(idx, use) and
  sameFunction(idx, use) and
  not hasUpperBoundGuard(idx, use)
select use,
  "Externally controlled integer '" + idx.toString() +
  "' is used in an array or descriptor-sensitive operation without an apparent upper-bound guard."
