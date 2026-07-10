/**
 * @name Missing minimum-length check before protocol parser use
 * @description Detects packet length or offset values used in protocol parsing without a minimum-length or nonnegative guard.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/missing-minimum-length-check-on-network-protocol-packet
 * @tags security
 */

import cpp

predicate sameFunction(Expr a, Element b) {
  exists(Function f |
    a.getEnclosingFunction() = f and
    b.getEnclosingFunction() = f
  )
}

predicate beforeUse(Element guard, Element use) {
  guard.getLocation().getFile() = use.getLocation().getFile() and
  guard.getLocation().getStartLine() <= use.getLocation().getStartLine()
}

predicate textMentions(Element e, Expr v) {
  e.toString().matches("%" + v.toString() + "%")
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

predicate controlsLoopBoundary(Expr len, Element use) {
  exists(LoopStmt loop |
    use = loop and
    textMentions(loop, len)
  )
}

predicate controlsPointerOrIndexUse(Expr len, Element use) {
  exists(ArrayExpr ae |
    use = ae and
    textMentions(ae, len)
  )
  or
  exists(AssignExpr assign |
    use = assign and
    textMentions(assign, len) and
    (
      assign.toString().matches("%+=%") or
      assign.toString().matches("%+%") or
      assign.toString().matches("%-%")
    )
  )
}

predicate controlsProtocolCall(Expr len, Element use) {
  exists(FunctionCall fc, int i |
    use = fc and
    fc.getArgument(i) = len and
    (
      fc.getTarget().getName().regexpMatch("(?i).*(attr|parse|read|get|copy|memcpy|memcmp).*") or
      fc.toString().matches("%POS_ATTRS%") or
      fc.toString().matches("%MD5_DIGEST_LENGTH%")
    )
  )
}

predicate isParserUse(Expr len, Element use) {
  controlsLoopBoundary(len, use) or
  controlsPointerOrIndexUse(len, use) or
  controlsProtocolCall(len, use)
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
    cond.toString().matches("%< sizeof%")
  )
}

predicate hasMinimumOrNonnegativeGuard(Expr len, Element use) {
  exists(IfStmt ifs |
    sameFunction(len, use) and
    beforeUse(ifs, use) and
    isMinimumOrNonnegativeCheckFor(ifs.getCondition(), len)
  )
}

from Expr len, Element use
where
  isPacketLengthLike(len) and
  isParserUse(len, use) and
  sameFunction(len, use) and
  not hasMinimumOrNonnegativeGuard(len, use)
select use,
  "Packet length or offset '" + len.toString() +
  "' is used in protocol parsing without an apparent minimum-length or nonnegative guard."
