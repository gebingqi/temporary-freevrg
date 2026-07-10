/**
 * @name Missing minimum-length or nonnegative check before protocol parser use
 * @description Detects packet length or offset values used in protocol parsing without an apparent minimum-length or nonnegative guard in the same function.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/missing-minimum-length-check-on-network-protocol-packet
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

predicate hasProtocolLengthName(Expr e) {
  e.toString().regexpMatch("(?i).*(len|length|alen|offset|off|pos|ptr|pointed_len).*")
}

predicate isKnownProtocolAnchor(Expr e) {
  e.toString().matches("%POS_LENGTH%") or
  e.toString().matches("%POS_ATTRS%") or
  e.toString().matches("%MD5_DIGEST_LENGTH%")
}

predicate isPacketLengthLike(Expr e) {
  hasProtocolLengthName(e) or
  isKnownProtocolAnchor(e)
}

predicate controlsLoopBoundary(Expr len, Element useSite) {
  exists(Loop loop |
    useSite = loop and
    textMentions(loop.getCondition(), len)
  )
}

predicate controlsPointerOrIndexUse(Expr len, Element useSite) {
  exists(ArrayExpr access |
    useSite = access and
    textMentions(access, len)
  )
  or
  exists(AssignExpr assign |
    useSite = assign and
    textMentions(assign, len) and
    (
      assign.toString().matches("%+=%") or
      assign.toString().matches("%-=%") or
      assign.toString().matches("%+%") or
      assign.toString().matches("%-%")
    )
  )
}

predicate controlsProtocolCall(Expr len, Element useSite) {
  exists(FunctionCall call, int i |
    useSite = call and
    len = call.getArgument(i) and
    (
      call.getTarget().getName().regexpMatch("(?i).*(attr|parse|read|get|copy|memcpy|memcmp|digest).*") or
      call.toString().matches("%POS_ATTRS%") or
      call.toString().matches("%MD5_DIGEST_LENGTH%")
    )
  )
}

predicate controlsProtocolPosition(Expr len, Element useSite) {
  exists(AssignExpr assign |
    useSite = assign and
    textMentions(assign, len) and
    assign.toString().regexpMatch("(?i).*(pos|ptr|offset|off|cp|cursor|data).*")
  )
}

predicate isParserUse(Expr len, Element useSite) {
  controlsLoopBoundary(len, useSite) or
  controlsPointerOrIndexUse(len, useSite) or
  controlsProtocolCall(len, useSite) or
  controlsProtocolPosition(len, useSite)
}

predicate isMinimumOrNonnegativeCheckFor(Expr cond, Expr len) {
  textMentions(cond, len) and
  (
    cond.toString().matches("%< 0%") or
    cond.toString().matches("%<0%") or
    cond.toString().matches("%< 1%") or
    cond.toString().matches("%<1%") or
    cond.toString().matches("%< 2%") or
    cond.toString().matches("%<2%") or
    cond.toString().matches("%< POS_%") or
    cond.toString().matches("%< MIN%") or
    cond.toString().matches("%< sizeof%") or
    cond.toString().matches("%<= 0%") or
    cond.toString().matches("%<=0%")
  )
}

predicate hasRelevantGuard(Expr len, Element useSite) {
  exists(IfStmt ifs |
    sameFunction(len, ifs) and
    beforeUse(ifs, useSite) and
    isMinimumOrNonnegativeCheckFor(ifs.getCondition(), len)
  )
  or
  exists(FunctionCall assertCall |
    sameFunction(len, assertCall) and
    beforeUse(assertCall, useSite) and
    assertCall.getTarget().hasName("assert") and
    isMinimumOrNonnegativeCheckFor(assertCall, len)
  )
}

from Expr len, Element useSite
where
  isPacketLengthLike(len) and
  isParserUse(len, useSite) and
  sameFunction(len, useSite) and
  not hasRelevantGuard(len, useSite)
select useSite,
  "Packet length or offset '" + len.toString() +
  "' is used in protocol parsing without an apparent minimum-length or nonnegative guard."
