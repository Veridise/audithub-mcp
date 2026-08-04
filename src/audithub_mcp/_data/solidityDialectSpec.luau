-- Solidity PAQL Dialect


-- Define expr, stmts helpers
local ALL_EXPRSTMTS = {}
local ALL_EXPRS = {}
local ALL_STMTS = {}
function exprstmt_class(name)
  local c = class(name)
  ALL_EXPRSTMTS[c] = {}
  return c
end
function expr_class(name)
  local c = exprstmt_class(name)
  ALL_EXPRS[c] = {}
  return c
end
function stmt_class(name)
  local c = exprstmt_class(name)
  ALL_STMTS[c] = {}
  return c
end
function iterator_exprstmt(cls, options)
  for ecls in ALL_EXPRSTMTS do
    cls:iterator(ecls, options)
  end
end

local universe = class("Universe")

local contract = class("Contract")
local super_classes_provider = class("SuperClassesProvider")

local func = class("Function")
local reachable_functions_provider = class("ReachableFunctionsProvider")

local local_variable = class("MemoryAllocation")
local storage_read_effect = class("StorageRead")
local storage_write_effect = class("StorageWrite")
local storage_var = class("StorageVar")

local memory_read_effect = class("MemoryRead")
local memory_write_effect = class("MemoryWrite")

local optionalExpression = class("OptionalExpression")
local optionalValue = class("OptionalValue")

local expression = expr_class("Expression")
local ext_call = expr_class("ExternalCall")
local int_call = expr_class("InternalCall")
local address_this = expr_class("AddressThis")
local msg_sender = expr_class("MsgSender")
local precompile_call = expr_class("PrecompileCall")
local divExpr = expr_class("DivideExpression")
local mulExpr = expr_class("MultiplyExpression")

local hashOp = expr_class("HashOp")
local keccak256 = expr_class("Keccak256")
local sha256 = expr_class("Sha256")
local ripemd160 = expr_class("Ripemd160")

local statement = stmt_class("Statement")
local require_like = stmt_class("RequireLike")
local condition = class("Condition")
local conditionClause = class("ConditionClause")
local revert = stmt_class("Revert")

local value = class("Value")
local paramValue = class("Parameter")
local resultValue = class("Result")

local slices = class("Slices")
local slice = class("Slice")
local exprResults = class("ExprResults")
local use = class("Use")
local callArgument = class("CallArgument")
local sliceElement = class("SliceElement")
local path = class("Path")
local paths = class("Paths")


local reachableStatements = class("ReachableStatements")

-- Common properties

function common_op_iterators(cls, options)
  iterator_exprstmt(cls, options)
  cls:iterator(storage_read_effect, options)
  cls:iterator(storage_write_effect, options)
  cls:iterator(local_variable, options)

  cls:iterator(memory_read_effect, options)
  cls:iterator(memory_write_effect, options)
end

optionalExpression:iterator(expression)
optionalValue:iterator(value)

function slice_properties(cls)
  cls:property("forwardSlices", slices)
  cls:property("backwardSlices", slices)
  cls:property("interprocForwardSlices", slices)
  cls:property("interprocBackwardSlices", slices)
end

-- Contract
universe:iterator(contract, { implicit = true })
universe:iterator(func, { implicit = true })
common_op_iterators(universe, { implicit = true })

contract:property("name", string)
contract:property("superClasses", super_classes_provider)
contract:property("kind", string)
contract:property("isLibrary", bool)
contract:property("isInterface", bool)
contract:property("isContract", bool)
contract:property("filepath", string)  -- The Solidity virtual file path
contract:property("isAbstract", bool)
contract:property("isConcrete", bool)
contract:iterator(func)
contract:iterator(storage_var)
common_op_iterators(contract)

super_classes_provider:iterator(contract)

storage_var:property("name", string)
storage_var:property("contract", contract)
storage_var:property("declaringContract", contract)
storage_var:property("getterSignature", string)
storage_var:property("visibility", string)
storage_var:property("slot", string)
storage_var:property("offset", string)

-- Function

func:property("visibility", string)
func:property("name", string)
func:property("signature", string)
func:property("selector", string)
func:property("contract", contract)
-- TODO: FIXME: see corresponding comments for definingContractName in implementation
func:property("definingContractName", string)
func:property("reachable", reachable_functions_provider)
func:property("isExternallyCallable", bool)
func:property("isConstructor", bool)
func:property("isEntrypoint", bool)
func:property("mutability", string)

func:iterator(paramValue)
common_op_iterators(func)

reachable_functions_provider:iterator(func)
common_op_iterators(reachable_functions_provider)

-- Expressions

for cls in ALL_EXPRSTMTS do
  cls:property("after", reachableStatements)
  cls:property("before", reachableStatements)
  slice_properties(cls)
  cls:property("incomingPaths", paths)
  cls:property("outgoingPaths", paths)
  path:iterator(cls)

  cls:iterator(storage_read_effect)
  cls:iterator(storage_write_effect)
end

path:iterator(optionalExpression)

for cls in ALL_EXPRS do
  cls:property("results", exprResults)
end

ext_call:property("signature", string)
ext_call:property("name", string)
ext_call:property("selector", string)
ext_call:property("callees", ext_call)
ext_call:property("isLowLevelCall", bool)
ext_call:property("isSend", bool)
ext_call:property("kind", string)
ext_call:property("isCall", bool)
ext_call:property("isStaticcall", bool)
ext_call:property("isDelegatecall", bool)
ext_call:property("address", value)
ext_call:property("calldata", optionalValue)
ext_call:iterator(func) -- allow iterating through the callees
ext_call:iterator(callArgument)

int_call:property("callee", func)
int_call:property("contract", contract)
int_call:iterator(callArgument)

precompile_call:property("address", string)
precompile_call:property("name", string)

-- Statements

for cls in ALL_STMTS do
  -- No properties right now, but leaving this here for the future.
end

require_like:property("condition", value)
require_like:property("clauses", condition)
condition:iterator(conditionClause)
conditionClause:property("value", value)
conditionClause:property("kind", string)


common_op_iterators(reachableStatements)

for _, storage_effect in pairs({storage_read_effect, storage_write_effect}) do
  storage_effect:property("location", string)
  storage_effect:iterator(storage_var)
  storage_effect:property("after", reachableStatements)
  storage_effect:property("before", reachableStatements)
  storage_effect:property("incomingPaths", paths)
  storage_effect:property("outgoingPaths", paths)
end

custom_op("regexMatch", {string, string}, bool)

resultValue:property("interprocForwardSlices", slices)
resultValue:property("forwardSlices", slices)

value:property("source", optionalExpression)

slice_properties(value)
value:iterator(use)

paramValue:property("paramIndex", int)
-- keep this for backward compatibility
paramValue:property("argIndex", int)
paramValue:property("function", func)
slice_properties(paramValue)

resultValue:property("resultIndex", int)
resultValue:property("definingExpression", expression)

slices:iterator(slice)
slices:iterator(sliceElement)
slices:iterator(value)
slices:iterator(paramValue)
slices:iterator(storage_read_effect)
slices:iterator(storage_write_effect)
slices:iterator(memory_read_effect)
slices:iterator(memory_write_effect)
iterator_exprstmt(slices)

slice:iterator(sliceElement)

sliceElement:iterator(storage_write_effect)
sliceElement:iterator(storage_read_effect)

exprResults:iterator(resultValue)

use:property("argIndex", int)
use:property("user", expression)

paths:iterator(path)

callArgument:property("argIndex", int)
callArgument:property("value", value)
slice_properties(callArgument)

-- Aliases
-- allow using Argument in place of Parameter for backward compatibility
local alias = class_alias("Argument", paramValue, { deprecated = true })

-- % paql --type dialect-spec solidityDialectSpec.luau
