/**
 * @name Missing upper-bound check before array or descriptor use
 * @description Detects externally controlled integer values used as array indexes or descriptor counts without an apparent upper-bound or valid-range guard in the same function.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/missing-array-bounds-check-on-network-controlled-index
 * @tags security
 */

import cpp

predicate sameFunction(Expr source, Element useSite) {
  exists(Expr e |
    useSite = e and
    source.getEnclosingFunction() = e.getEnclosingFunction()
  )
  or
  exists(Stmt s |
    useSite = s and
    source.getEnclosingFunction() = s.getEnclosingFunction()
  )
}

predicate beforeUse(Element guard, Element useSite) {
  guard.getLocation().getFile() = useSite.getLocation().getFile() and
  guard.getLocation().getStartLine() <= useSite.getLocation().getStartLine()
}

predicate textMentions(Element e, Expr value) {
  e.toString().matches("%" + value.toString() + "%")
}

predicate nameLooksLikeExternalIndexOrCount(Expr e) {
  e.toString().regexpMatch("(?i).*(idx|index|epid|htype|count|cnt|num|len|iov).*")
}

predicate isPacketOrGuestField(Expr e) {
  e.toString().matches("%->%") or
  e.toString().matches("%.%" )
}

predicate isAssignedFromDescriptorChain(Expr e) {
  exists(AssignExpr assign, FunctionCall call |
    assign.getLValue().toString() = e.toString() and
    assign.getRValue() = call and
    call.getTarget().hasName("vq_getchain") and
    assign.getEnclosingFunction() = e.getEnclosingFunction()
  )
}

predicate isExternalInteger(Expr e) {
  isPacketOrGuestField(e) or
  nameLooksLikeExternalIndexOrCount(e) or
  isAssignedFromDescriptorChain(e)
}

predicate isArrayIndexUse(Expr idx, Element useSite) {
  exists(ArrayExpr access |
    useSite = access and
    idx = access.getArrayOffset()
  )
}

predicate isDescriptorSensitiveCall(Expr idx, Element useSite) {
  exists(FunctionCall call, int i |
    useSite = call and
    idx = call.getArgument(i) and
    (
      call.getTarget().getName().regexpMatch("(?i).*(iov|desc|chain|vq|virtqueue).*") or
      call.toString().regexpMatch("(?i).*(iov|desc|chain|vq|virtqueue).*")
    )
  )
}

predicate isDescriptorLoopUse(Expr idx, Element useSite) {
  exists(Loop loop |
    useSite = loop and
    textMentions(loop, idx) and
    loop.toString().regexpMatch("(?i).*(iov|desc|chain|vq|eps).*")
  )
}

predicate isDescriptorAssignmentUse(Expr idx, Element useSite) {
  exists(AssignExpr assign |
    useSite = assign and
    textMentions(assign, idx) and
    assign.toString().regexpMatch("(?i).*(iov|desc|chain|vq|eps).*")
  )
}

predicate isDangerousUse(Expr idx, Element useSite) {
  isArrayIndexUse(idx, useSite) or
  isDescriptorSensitiveCall(idx, useSite) or
  isDescriptorLoopUse(idx, useSite) or
  isDescriptorAssignmentUse(idx, useSite)
}

predicate isRangeCheckFor(Expr cond, Expr idx) {
  textMentions(cond, idx) and
  (
    cond.toString().matches("%>=%") or
    cond.toString().matches("%>%") or
    cond.toString().matches("%<=%") or
    cond.toString().matches("%<%") or
    cond.toString().matches("%== 0%") or
    cond.toString().matches("%==0%")
  )
}

predicate hasRelevantGuard(Expr idx, Element useSite) {
  exists(IfStmt ifs |
    sameFunction(idx, ifs) and
    beforeUse(ifs, useSite) and
    isRangeCheckFor(ifs.getCondition(), idx)
  )
  or
  exists(FunctionCall assertCall |
    sameFunction(idx, assertCall) and
    beforeUse(assertCall, useSite) and
    assertCall.getTarget().hasName("assert") and
    isRangeCheckFor(assertCall, idx)
  )
}

from Expr idx, Element useSite
where
  isExternalInteger(idx) and
  isDangerousUse(idx, useSite) and
  sameFunction(idx, useSite) and
  not hasRelevantGuard(idx, useSite)
select useSite,
  "Externally controlled index or descriptor count '" + idx.toString() +
  "' is used without an apparent upper-bound or valid-range guard."
