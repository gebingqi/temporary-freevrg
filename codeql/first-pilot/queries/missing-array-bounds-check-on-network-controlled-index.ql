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
import semmle.code.cpp.commons.Assertions

Function enclosingFunction(Element e) {
  exists(Expr expr | e = expr and result = expr.getEnclosingFunction())
  or
  exists(Stmt stmt | e = stmt and result = stmt.getEnclosingFunction())
}

predicate beforeUse(Locatable guard, Element useSite) {
  guard.getLocation().getFile() = useSite.getLocation().getFile() and
  guard.getLocation().getStartLine() <= useSite.getLocation().getStartLine()
}

predicate accessesVariable(Expr tree, Variable value) {
  exists(VariableAccess access |
    tree.getAChild*() = access and
    access.getTarget() = value
  )
}

predicate isIntegralVariable(Variable value) {
  value.getType().getUnspecifiedType() instanceof IntegralType
}

predicate nameLooksLikeExternalIndexOrCount(Variable value) {
  value.getName().regexpMatch("(?i).*(idx|index|epid|htype|count|cnt|num|len|iov).*")
}

predicate isAssignedFromDescriptorChain(Variable value, Function function) {
  exists(AssignExpr assign, VariableAccess lhs, FunctionCall call |
    assign.getEnclosingFunction() = function and
    assign.getLValue() = lhs and
    lhs.getTarget() = value and
    assign.getRValue().getAChild*() = call and
    call.getTarget().getName().regexpMatch("(?i).*(vq_getchain|virtqueue.*chain).*")
  )
}

predicate isExternalInteger(Variable value, Function function) {
  isIntegralVariable(value) and
  (
    nameLooksLikeExternalIndexOrCount(value) or
    isAssignedFromDescriptorChain(value, function)
  )
}

predicate isArrayIndexUse(Variable value, Element useSite) {
  exists(ArrayExpr access |
    useSite = access and
    accessesVariable(access.getArrayOffset(), value)
  )
}

predicate loopContainsArrayOrDescriptorUse(Loop loop) {
  exists(ArrayExpr access |
    access.getEnclosingStmt() = loop.getStmt() or
    access.getEnclosingStmt().getEnclosingBlock() = loop.getStmt()
  )
  or
  exists(FunctionCall call |
    (
      call.getEnclosingStmt() = loop.getStmt() or
      call.getEnclosingStmt().getEnclosingBlock() = loop.getStmt()
    ) and
    call.getTarget().getName().regexpMatch("(?i).*(iov|desc|chain|virtqueue|readv|writev|buf_to|to_buf).*")
  )
}

predicate isDescriptorLoopUse(Variable value, Element useSite) {
  exists(Loop loop |
    useSite = loop and
    accessesVariable(loop.getCondition(), value) and
    loopContainsArrayOrDescriptorUse(loop)
  )
}

predicate isDescriptorSensitiveCall(Variable value, Element useSite) {
  exists(FunctionCall call, Expr argument |
    useSite = call and
    argument = call.getAnArgument() and
    accessesVariable(argument, value) and
    call.getTarget().getName().regexpMatch("(?i).*(iov|desc|readv|writev|buf_to|to_buf).*") and
    not call.getTarget().getName().regexpMatch("(?i).*(vq_getchain|virtqueue.*chain).*")
  )
}

predicate isDangerousUse(Variable value, Element useSite) {
  isArrayIndexUse(value, useSite) or
  isDescriptorLoopUse(value, useSite) or
  isDescriptorSensitiveCall(value, useSite)
}

predicate isUpperBoundViolation(RelationalOperation comparison, Variable value) {
  (
    accessesVariable(comparison.getLeftOperand(), value) and
    not accessesVariable(comparison.getRightOperand(), value) and
    comparison.getOperator() = [">=", ">"]
  )
  or
  (
    accessesVariable(comparison.getRightOperand(), value) and
    not accessesVariable(comparison.getLeftOperand(), value) and
    comparison.getOperator() = ["<=", "<"]
  )
}

predicate isValidUpperBound(RelationalOperation comparison, Variable value) {
  (
    accessesVariable(comparison.getLeftOperand(), value) and
    not accessesVariable(comparison.getRightOperand(), value) and
    comparison.getOperator() = ["<=", "<"]
  )
  or
  (
    accessesVariable(comparison.getRightOperand(), value) and
    not accessesVariable(comparison.getLeftOperand(), value) and
    comparison.getOperator() = [">=", ">"]
  )
}

predicate containsUpperBoundViolation(Expr condition, Variable value) {
  exists(RelationalOperation comparison |
    condition.getAChild*() = comparison and
    isUpperBoundViolation(comparison, value)
  )
}

predicate containsValidUpperBound(Expr condition, Variable value) {
  exists(RelationalOperation comparison |
    condition.getAChild*() = comparison and
    isValidUpperBound(comparison, value)
  )
}

predicate branchReturns(Stmt branch) {
  branch instanceof ReturnStmt or
  exists(ReturnStmt ret | branch.getAChild*() = ret)
}

predicate isInside(Stmt branch, Element useSite) {
  useSite = branch or branch.getAChild*() = useSite
}

predicate hasRelevantGuard(Variable value, Element useSite) {
  exists(IfStmt guard |
    guard.getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(guard, useSite) and
    containsUpperBoundViolation(guard.getCondition(), value) and
    branchReturns(guard.getThen())
  )
  or
  exists(IfStmt guard |
    guard.getEnclosingFunction() = enclosingFunction(useSite) and
    containsValidUpperBound(guard.getCondition(), value) and
    isInside(guard.getThen(), useSite)
  )
  or
  exists(Assertion assertion |
    assertion.getAsserted().getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(assertion, useSite) and
    containsValidUpperBound(assertion.getAsserted(), value)
  )
  or
  exists(FunctionCall assertCall |
    assertCall.getEnclosingFunction() = enclosingFunction(useSite) and
    beforeUse(assertCall, useSite) and
    assertCall.getTarget().hasName("assert") and
    containsValidUpperBound(assertCall.getArgument(0), value)
  )
}

from Variable value, Element useSite
where
  isExternalInteger(value, enclosingFunction(useSite)) and
  isDangerousUse(value, useSite) and
  not hasRelevantGuard(value, useSite)
select useSite,
  "Externally controlled index or descriptor count '" + value.getName() +
  "' is used without an apparent upper-bound or valid-range guard."
