/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
      // TODO: replace <class> and <var>
      exists(MacroInvocation mi |
          mi.getMacroName() in ["ntohl", "ntohll", "ntohs"] and
          mi.getExpr() = this
      )
    }
  }

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
      source.asExpr() instanceof NetworkByteSwap
    // TODO
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc | fc.getArgument(0) = sink.asExpr() and 
    fc.getTarget().getName() = "memcpy")
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
