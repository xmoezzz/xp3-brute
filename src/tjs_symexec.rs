//! Bounded symbolic execution for compiled TJS2 bootstrap scripts.
//!
//! This deliberately runs above raw VM opcodes: tjs2dec already lowers each
//! object through CFG -> SSA -> ExprProgram.  The executor interprets that IR,
//! tracks concrete strings/integers through SSA and φ nodes, forks bounded
//! unknown branches, and records selected native method calls as sinks.

use crate::{Error, Result};
use std::collections::{HashMap, VecDeque};
use tjs2dec::decompile::cfg::Cfg;
use tjs2dec::decompile::expr::{BinOp, Expr, UnOp};
use tjs2dec::decompile::expr_build::{ExprProgram, Stmt, Terminator};
use tjs2dec::decompile::ssa::{SsaProgram, Var, VarId};
use tjs2dec::{load_tjs2_bytecode, Tjs2File, Tjs2Object};

const MAX_STATES: usize = 256;
const MAX_STEPS_PER_STATE: usize = 20_000;
const MAX_BLOCK_VISITS: usize = 32;
const MAX_CALL_DEPTH: usize = 8;
const MAX_STRING_UNITS: usize = 64 * 1024 / 2;

#[derive(Clone, Debug, PartialEq)]
enum SymValue {
    Unknown,
    Void,
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(String),
    Octet(Vec<u8>),
    Array(Vec<SymValue>),
    Dictionary(Vec<(SymValue, SymValue)>),
    RegExp(String),
    Path(String),
    Function(usize),
    Symbolic(String),
}

impl SymValue {
    fn concrete_string(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    fn truthy(&self) -> Option<bool> {
        match self {
            Self::Void | Self::Null => Some(false),
            Self::Bool(v) => Some(*v),
            Self::Int(v) => Some(*v != 0),
            Self::Real(v) => Some(*v != 0.0 && !v.is_nan()),
            Self::Str(v) => Some(!v.is_empty()),
            Self::Octet(v) => Some(!v.is_empty()),
            Self::Array(_)
            | Self::Dictionary(_)
            | Self::RegExp(_)
            | Self::Path(_)
            | Self::Function(_) => Some(true),
            Self::Unknown | Self::Symbolic(_) => None,
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Unknown => "?".into(),
            Self::Void => "void".into(),
            Self::Null => "null".into(),
            Self::Bool(v) => v.to_string(),
            Self::Int(v) => v.to_string(),
            Self::Real(v) => v.to_string(),
            Self::Str(v) => format!("{:?}", v),
            Self::Octet(v) => format!("octet[{}]", v.len()),
            Self::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(SymValue::display)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Dictionary(entries) => format!(
                "%[{}]",
                entries
                    .iter()
                    .map(|(key, value)| format!("{}=>{}", key.display(), value.display()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::RegExp(token) => token.clone(),
            Self::Path(v) => v.clone(),
            Self::Function(index) => format!("function#{index}"),
            Self::Symbolic(v) => v.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TjsSymbolicCall {
    pub object_index: usize,
    pub object_name: Option<String>,
    pub block_id: usize,
    pub pc: usize,
    pub target: String,
    pub argument: Option<String>,
    pub argument_repr: String,
}

#[derive(Clone, Debug, Default)]
pub struct TjsSymbolicReport {
    pub setup_archive_data_calls: Vec<TjsSymbolicCall>,
    pub script_load_calls: Vec<TjsSymbolicCall>,
    pub unresolved_setup_calls: usize,
    pub unresolved_script_load_calls: usize,
    pub states_explored: usize,
    pub steps_executed: usize,
    pub objects_executed: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
struct ExecState {
    block: usize,
    predecessor: Option<usize>,
    vars: HashMap<VarId, SymValue>,
    memory: HashMap<String, SymValue>,
    call_args: Vec<SymValue>,
    visits: HashMap<usize, usize>,
    steps: usize,
    return_value: SymValue,
}

impl ExecState {
    fn new(entry: usize) -> Self {
        Self {
            block: entry,
            predecessor: None,
            vars: HashMap::new(),
            memory: HashMap::new(),
            call_args: Vec::new(),
            visits: HashMap::new(),
            steps: 0,
            return_value: SymValue::Void,
        }
    }
}

struct Executor<'a> {
    file: &'a Tjs2File,
    programs: HashMap<usize, ExprProgram>,
    report: TjsSymbolicReport,
}

impl<'a> Executor<'a> {
    fn new(file: &'a Tjs2File) -> Self {
        Self {
            file,
            programs: HashMap::new(),
            report: TjsSymbolicReport::default(),
        }
    }

    fn object(&self, object_index: usize) -> Result<&Tjs2Object> {
        self.file
            .objects
            .iter()
            .find(|object| object.index == object_index)
            .ok_or_else(|| Error::invalid(format!("TJS2 object index {object_index} is out of range")))
    }

    fn program(&mut self, object_index: usize) -> Result<ExprProgram> {
        if let Some(program) = self.programs.get(&object_index) {
            return Ok(program.clone());
        }
        let object = self.object(object_index)?;
        let cfg = Cfg::build(object).map_err(|e| Error::invalid(format!("TJS2 CFG build failed: {e}")))?;
        let ssa = SsaProgram::from_cfg(&cfg)
            .map_err(|e| Error::invalid(format!("TJS2 SSA build failed: {e}")))?;
        let program = ExprProgram::from_ssa(self.file, object, &ssa)
            .map_err(|e| Error::invalid(format!("TJS2 ExprProgram build failed: {e}")))?;
        self.programs.insert(object_index, program.clone());
        Ok(program)
    }

    fn scope_is_class(&self, object: &Tjs2Object) -> bool {
        // tTJSContextType::ctClass is 6.  Check the object itself first:
        // class bodies have a this-proxy scope even when their parent is the
        // top-level object.  The old implementation only inspected parents,
        // so a class object was incorrectly seeded as global scope.
        if object.context_type == 6 {
            return true;
        }
        let mut parent = object.parent;
        while parent >= 0 {
            let Some(candidate) = self
                .file
                .objects
                .iter()
                .find(|candidate| candidate.index == parent as usize)
            else {
                break;
            };
            match candidate.context_type {
                0 => return false,
                6 => return true,
                _ => parent = candidate.parent,
            }
        }
        false
    }

    fn seed_static_properties(&self, object: &Tjs2Object, memory: &mut HashMap<String, SymValue>) {
        let scope = if self.scope_is_class(object) { "this" } else { "global" };
        for (name_index, object_index) in &object.properties {
            if *name_index < 0 || *object_index < 0 {
                continue;
            }
            let Some(name) = self.file.const_pools.strings.get(*name_index as usize) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            memory
                .entry(format!("{scope}.{name}"))
                .or_insert(SymValue::Function(*object_index as usize));
            // A member reached through `this` should resolve the same static
            // declaration when the object is the active execution context.
            memory
                .entry(format!("this.{name}"))
                .or_insert(SymValue::Function(*object_index as usize));
        }
    }

    fn execute_object(
        &mut self,
        object_index: usize,
        args: &[SymValue],
        inherited_memory: &HashMap<String, SymValue>,
        depth: usize,
    ) -> Result<(SymValue, HashMap<String, SymValue>)> {
        if depth > MAX_CALL_DEPTH {
            self.report.truncated = true;
            return Ok((SymValue::Unknown, inherited_memory.clone()));
        }
        let object = self.object(object_index)?.clone();
        if object.code.is_empty() {
            return Ok((SymValue::Void, inherited_memory.clone()));
        }
        let program = self.program(object_index)?;
        self.report.objects_executed += 1;

        let mut initial = ExecState::new(program.entry_block);
        initial.memory = inherited_memory.clone();
        initial.call_args = args.to_vec();
        // TJS2 VM calling convention: %-1=this, %-2=this-proxy, arguments
        // begin at %-3 and continue downward.
        initial.vars.insert(
            VarId {
                var: Var::Reg(-1),
                ver: 0,
            },
            SymValue::Path("this".into()),
        );
        // %-2 is TJS2's scope/this-proxy register.  At global scope it
        // resolves to global; inside class scope it resolves through this.
        // This matches tjs2dec's own high-level emitter and is much more
        // useful than treating it as an unrelated opaque object.
        let scope_path = if self.scope_is_class(&object) { "this" } else { "global" };
        initial.vars.insert(
            VarId {
                var: Var::Reg(-2),
                ver: 0,
            },
            SymValue::Path(scope_path.into()),
        );
        self.seed_static_properties(&object, &mut initial.memory);
        for (index, value) in args.iter().enumerate() {
            initial.vars.insert(
                VarId {
                    var: Var::Reg(-3 - index as i32),
                    ver: 0,
                },
                value.clone(),
            );
        }

        let mut queue = VecDeque::from([initial]);
        let mut terminal = Vec::<ExecState>::new();
        let mut spawned = 1usize;

        while let Some(mut state) = queue.pop_front() {
            if state.steps >= MAX_STEPS_PER_STATE {
                self.report.truncated = true;
                terminal.push(state);
                continue;
            }
            if spawned > MAX_STATES {
                self.report.truncated = true;
                terminal.push(state);
                continue;
            }
            let Some(block) = program.blocks.iter().find(|block| block.id == state.block) else {
                terminal.push(state);
                continue;
            };
            let visits = state.visits.entry(block.id).or_insert(0);
            *visits += 1;
            if *visits > MAX_BLOCK_VISITS {
                self.report.truncated = true;
                terminal.push(state);
                continue;
            }

            self.apply_phi(block, &mut state);
            for stmt in &block.stmts {
                state.steps += 1;
                self.report.steps_executed += 1;
                self.execute_stmt(&object, block.id, block.start_pc, stmt, &mut state, depth)?;
                if state.steps >= MAX_STEPS_PER_STATE {
                    break;
                }
            }
            self.report.states_explored += 1;

            if state.steps >= MAX_STEPS_PER_STATE {
                self.report.truncated = true;
                terminal.push(state);
                continue;
            }

            match &block.term {
                Terminator::Jmp(next) => {
                    state.predecessor = Some(block.id);
                    state.block = *next;
                    queue.push_back(state);
                }
                Terminator::Br {
                    cond,
                    if_true,
                    if_false,
                } => match self.eval_expr(&object, block.id, block.start_pc, cond, &mut state, depth)?.truthy() {
                    Some(true) => {
                        state.predecessor = Some(block.id);
                        state.block = *if_true;
                        queue.push_back(state);
                    }
                    Some(false) => {
                        state.predecessor = Some(block.id);
                        state.block = *if_false;
                        queue.push_back(state);
                    }
                    None => {
                        let mut other = state.clone();
                        state.predecessor = Some(block.id);
                        state.block = *if_true;
                        other.predecessor = Some(block.id);
                        other.block = *if_false;
                        spawned += 1;
                        queue.push_back(state);
                        queue.push_back(other);
                    }
                },
                Terminator::Ret(expr) => {
                    state.return_value = self.eval_expr(
                        &object,
                        block.id,
                        block.start_pc,
                        expr,
                        &mut state,
                        depth,
                    )?;
                    terminal.push(state);
                }
                Terminator::Throw(expr) => {
                    let _ = self.eval_expr(
                        &object,
                        block.id,
                        block.start_pc,
                        expr,
                        &mut state,
                        depth,
                    )?;
                    terminal.push(state);
                }
                Terminator::Exit => {
                    // tjs2dec currently maps VM_EXTRY to Terminator::Exit even
                    // though its CFG keeps the VM's normal fallthrough edge.
                    // VM_EXTRY only leaves the active try region; it does not
                    // return from the TJS function.  Treat the first successor
                    // as the normal edge (the optional later successor is the
                    // conservative exception-handler edge added by Cfg::build).
                    if let Some(next) = block.succ.first().copied() {
                        state.predecessor = Some(block.id);
                        state.block = next;
                        queue.push_back(state);
                    } else {
                        terminal.push(state);
                    }
                }
                Terminator::Fallthrough => {
                    if let Some(next) = block.succ.first().copied() {
                        state.predecessor = Some(block.id);
                        state.block = next;
                        queue.push_back(state);
                    } else {
                        terminal.push(state);
                    }
                }
            }
        }

        if terminal.is_empty() {
            return Ok((SymValue::Unknown, inherited_memory.clone()));
        }
        let return_value = merge_values(terminal.iter().map(|state| &state.return_value));
        let memory = merge_memories(terminal.iter().map(|state| &state.memory));
        Ok((return_value, memory))
    }

    fn apply_phi(&self, block: &tjs2dec::decompile::expr_build::ExprBlock, state: &mut ExecState) {
        for phi in &block.phi {
            let value = if let Some(pred) = state.predecessor {
                phi.args
                    .iter()
                    .find(|(candidate, _)| *candidate == pred)
                    .and_then(|(_, var)| state.vars.get(var))
                    .cloned()
                    .unwrap_or(SymValue::Unknown)
            } else {
                merge_values(phi.args.iter().filter_map(|(_, var)| state.vars.get(var)))
            };
            state.vars.insert(phi.result, value);
        }
    }

    fn execute_stmt(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        stmt: &Stmt,
        state: &mut ExecState,
        depth: usize,
    ) -> Result<()> {
        match stmt {
            Stmt::Assign { dst, expr } => {
                let value = self.eval_expr(object, block_id, pc, expr, state, depth)?;
                state.vars.insert(*dst, value);
            }
            Stmt::Store { target, value } => {
                let value = self.eval_expr(object, block_id, pc, value, state, depth)?;
                if let Some(path) = self.lvalue_path(object, block_id, pc, target, state, depth)? {
                    state.memory.insert(path, value);
                }
            }
            Stmt::MemberDecl { name, value } => {
                // tjs2dec 0.5 lowers class-body SPDS into an explicit member
                // declaration.  In the VM this writes through objthis (`this`).
                let value = self.eval_expr(object, block_id, pc, value, state, depth)?;
                state.memory.insert(format!("this.{name}"), value);
            }
            Stmt::Update {
                dst,
                target,
                op,
                rhs,
            } => {
                let left = self.eval_expr(object, block_id, pc, target, state, depth)?;
                let right = self.eval_expr(object, block_id, pc, rhs, state, depth)?;
                let value = eval_binary(*op, left, right);
                if let Some(path) = self.lvalue_path(object, block_id, pc, target, state, depth)? {
                    state.memory.insert(path, value.clone());
                }
                if let Some(dst) = dst {
                    state.vars.insert(*dst, value);
                }
            }
            Stmt::IncDec {
                dst,
                target,
                increment,
            } => {
                let old = self.eval_expr(object, block_id, pc, target, state, depth)?;
                let op = if *increment { BinOp::Add } else { BinOp::Sub };
                let value = eval_binary(op, old, SymValue::Int(1));
                if let Some(path) = self.lvalue_path(object, block_id, pc, target, state, depth)? {
                    state.memory.insert(path, value.clone());
                }
                if let Some(dst) = dst {
                    state.vars.insert(*dst, value);
                }
            }
            Stmt::Expr(expr) => {
                let _ = self.eval_expr(object, block_id, pc, expr, state, depth)?;
            }
            Stmt::Opaque { op, args, defs } => {
                // ExprProgram deliberately keeps several VM operations opaque.
                // Evaluate their SSA inputs here instead of throwing away the
                // exact data-flow that the emit layer retained.
                let values = self.eval_args(object, block_id, pc, args, state, depth)?;
                if op.eq_ignore_ascii_case("srv") || op.eq_ignore_ascii_case("VM_SRV") {
                    if let Some(value) = values.first() {
                        state.return_value = value.clone();
                    }
                    for def in defs {
                        state.vars.insert(*def, SymValue::Unknown);
                    }
                    return Ok(());
                }

                if defs.len() == 1 {
                    if let Some(value) = eval_opaque_vm_op(op, &values) {
                        state.vars.insert(defs[0], value);
                        return Ok(());
                    }
                }
                for def in defs {
                    state.vars.insert(*def, SymValue::Unknown);
                }
            }
        }
        Ok(())
    }

    fn eval_expr(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        expr: &Expr,
        state: &mut ExecState,
        depth: usize,
    ) -> Result<SymValue> {
        Ok(match expr {
            Expr::Reg(reg) => state
                .vars
                .get(&VarId {
                    var: Var::Reg(*reg),
                    ver: 0,
                })
                .cloned()
                .unwrap_or(SymValue::Unknown),
            Expr::Flag => state
                .vars
                .get(&VarId {
                    var: Var::Flag,
                    ver: 0,
                })
                .cloned()
                .unwrap_or(SymValue::Unknown),
            Expr::ConstData(index) => SymValue::Symbolic(format!("const[{index}]")),
            Expr::SsaVar(var) => state.vars.get(var).cloned().unwrap_or(SymValue::Unknown),
            Expr::Void => SymValue::Void,
            Expr::Null => SymValue::Null,
            Expr::Bool(v) => SymValue::Bool(*v),
            Expr::Int(v) => SymValue::Int(*v),
            Expr::Real(v) => SymValue::Real(*v),
            Expr::Str(v) => SymValue::Str(v.clone()),
            Expr::Octet(v) => SymValue::Octet(v.clone()),
            Expr::ObjectRef(index) | Expr::GeneratorRef(index) if *index >= 0 => {
                SymValue::Function(*index as usize)
            }
            Expr::ObjectRef(_) | Expr::GeneratorRef(_) => SymValue::Unknown,
            Expr::ScopeProxy => SymValue::Path(
                if self.scope_is_class(object) { "this" } else { "global" }.into(),
            ),
            Expr::Unary(op, inner) => {
                let value = self.eval_expr(object, block_id, pc, inner, state, depth)?;
                eval_unary(*op, value)
            }
            Expr::Deref(inner) => self.eval_expr(object, block_id, pc, inner, state, depth)?,
            Expr::Binary(op, left, right) => {
                let left = self.eval_expr(object, block_id, pc, left, state, depth)?;
                let right = self.eval_expr(object, block_id, pc, right, state, depth)?;
                eval_binary(*op, left, right)
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond = self.eval_expr(object, block_id, pc, cond, state, depth)?;
                match cond.truthy() {
                    Some(true) => {
                        self.eval_expr(object, block_id, pc, then_expr, state, depth)?
                    }
                    Some(false) => {
                        self.eval_expr(object, block_id, pc, else_expr, state, depth)?
                    }
                    None => {
                        // Conditional expressions can contain calls/property
                        // reads. Evaluate each possible branch in an isolated
                        // state, retain sinks from both, then keep only state
                        // facts that agree across both outcomes.
                        let mut then_state = state.clone();
                        let then_value = self.eval_expr(
                            object,
                            block_id,
                            pc,
                            then_expr,
                            &mut then_state,
                            depth,
                        )?;
                        let mut else_state = state.clone();
                        let else_value = self.eval_expr(
                            object,
                            block_id,
                            pc,
                            else_expr,
                            &mut else_state,
                            depth,
                        )?;
                        state.vars = merge_vars([&then_state.vars, &else_state.vars]);
                        state.memory = merge_memories([&then_state.memory, &else_state.memory]);
                        merge_values([&then_value, &else_value])
                    }
                }
            }
            Expr::ArrayLiteral(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.eval_expr(object, block_id, pc, item, state, depth)?);
                }
                SymValue::Array(values)
            }
            Expr::DictionaryLiteral(items) => {
                let mut values = Vec::with_capacity(items.len());
                for (key, value) in items {
                    let key = self.eval_expr(object, block_id, pc, key, state, depth)?;
                    let value = self.eval_expr(object, block_id, pc, value, state, depth)?;
                    values.push((key, value));
                }
                SymValue::Dictionary(values)
            }
            Expr::RegExpLiteral(token) => SymValue::RegExp(token.clone()),
            // These nodes are meaningful primarily inside call argument lists.
            // Keep direct evaluation conservative; eval_args below performs the
            // actual expansion semantics.
            Expr::ArgExpand(inner) => {
                self.eval_expr(object, block_id, pc, inner, state, depth)?
            }
            Expr::ArgUnnamedExpand | Expr::ArgForwardAll => SymValue::Unknown,
            Expr::Member(base, member) => {
                let base = self.eval_expr(object, block_id, pc, base, state, depth)?;
                self.read_member(base, member, state)
            }
            Expr::Index(base, key) => {
                let base = self.eval_expr(object, block_id, pc, base, state, depth)?;
                let key = self.eval_expr(object, block_id, pc, key, state, depth)?;
                self.read_index(base, key, state)
            }
            Expr::Call(callee, args) => {
                let callee = self.eval_expr(object, block_id, pc, callee, state, depth)?;
                let args = self.eval_args(object, block_id, pc, args, state, depth)?;
                self.record_path_sink(object, block_id, pc, &callee, &args);
                self.call_value(callee, &args, state, depth)?
            }
            Expr::New(ctor, args) => {
                // Constructors are executable TJS objects too.  Even when we
                // cannot model the allocated instance precisely, entering the
                // constructor is required for bootstrap side effects (script
                // loads and setupArchiveData calls) to remain reachable.
                let ctor = self.eval_expr(object, block_id, pc, ctor, state, depth)?;
                let args = self.eval_args(object, block_id, pc, args, state, depth)?;
                let _ = self.call_value(ctor, &args, state, depth)?;
                SymValue::Unknown
            }
            Expr::MethodCall { base, member, args } => {
                let base_value = self.eval_expr(object, block_id, pc, base, state, depth)?;
                let args = self.eval_args(object, block_id, pc, args, state, depth)?;
                self.record_sink(object, block_id, pc, &base_value, member, &args);
                self.call_method(base_value, member, &args, state, depth)?
            }
            Expr::Opaque(name, args) => {
                if name == "global" {
                    SymValue::Path("global".into())
                } else if let Some(index) = parse_inter_callable(name) {
                    SymValue::Function(index)
                } else {
                    let values = self.eval_args(object, block_id, pc, args, state, depth)?;
                    SymValue::Symbolic(format!(
                        "{}({})",
                        name,
                        values
                            .iter()
                            .map(SymValue::display)
                            .collect::<Vec<_>>()
                            .join(",")
                    ))
                }
            }
        })
    }

    fn eval_args(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        args: &[Expr],
        state: &mut ExecState,
        depth: usize,
    ) -> Result<Vec<SymValue>> {
        let mut out = Vec::new();
        for arg in args {
            match arg {
                Expr::ArgExpand(inner) => {
                    match self.eval_expr(object, block_id, pc, inner, state, depth)? {
                        SymValue::Array(values) => out.extend(values),
                        // The exact cardinality of an unknown expanded value is
                        // unavailable. Preserve one unknown slot so a following
                        // sink does not incorrectly appear argument-less.
                        _ => out.push(SymValue::Unknown),
                    }
                }
                Expr::ArgUnnamedExpand => {
                    // tjs2dec preserves FuncDeclUnnamedArgArrayBase from the
                    // TJS2 object header. It is the first incoming argument
                    // belonging to the unnamed/rest portion of this function.
                    if let Ok(start) = usize::try_from(object.func_decl_unnamed_arg_array_base) {
                        out.extend(state.call_args.iter().skip(start).cloned());
                    } else {
                        out.push(SymValue::Unknown);
                    }
                }
                Expr::ArgForwardAll => {
                    out.extend(state.call_args.iter().cloned());
                }
                _ => out.push(self.eval_expr(object, block_id, pc, arg, state, depth)?),
            }
        }
        Ok(out)
    }

    fn read_member(&self, base: SymValue, member: &str, state: &ExecState) -> SymValue {
        if member == "length" {
            if let SymValue::Str(value) = &base {
                return SymValue::Int(value.encode_utf16().count() as i64);
            }
            if let SymValue::Octet(value) = &base {
                return SymValue::Int(value.len() as i64);
            }
            if let SymValue::Array(value) = &base {
                return SymValue::Int(value.len() as i64);
            }
        }
        if let SymValue::Path(base) = base {
            let path = format!("{base}.{member}");
            return state
                .memory
                .get(&path)
                .cloned()
                .unwrap_or(SymValue::Path(path));
        }
        SymValue::Unknown
    }

    fn read_index(&self, base: SymValue, key: SymValue, state: &ExecState) -> SymValue {
        match (base, key) {
            (SymValue::Path(base), SymValue::Str(key)) => {
                let path = format!("{base}.{key}");
                state
                    .memory
                    .get(&path)
                    .cloned()
                    .unwrap_or(SymValue::Path(path))
            }
            (SymValue::Str(value), SymValue::Int(index)) if index >= 0 => value
                .encode_utf16()
                .nth(index as usize)
                .and_then(|unit| char::from_u32(unit as u32))
                .map(|ch| SymValue::Str(ch.to_string()))
                .unwrap_or(SymValue::Void),
            (SymValue::Array(values), SymValue::Int(index)) if index >= 0 => values
                .get(index as usize)
                .cloned()
                .unwrap_or(SymValue::Void),
            (SymValue::Dictionary(entries), key) => entries
                .into_iter()
                .find_map(|(entry_key, value)| (entry_key == key).then_some(value))
                .unwrap_or(SymValue::Void),
            _ => SymValue::Unknown,
        }
    }

    fn lvalue_path(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        expr: &Expr,
        state: &mut ExecState,
        depth: usize,
    ) -> Result<Option<String>> {
        let expr = match expr {
            Expr::Deref(inner) => inner.as_ref(),
            other => other,
        };
        Ok(match expr {
            Expr::Member(base, member) => {
                let base = self.eval_expr(object, block_id, pc, base, state, depth)?;
                match base {
                    SymValue::Path(path) => Some(format!("{path}.{member}")),
                    _ => None,
                }
            }
            Expr::Index(base, key) => {
                let base = self.eval_expr(object, block_id, pc, base, state, depth)?;
                let key = self.eval_expr(object, block_id, pc, key, state, depth)?;
                match (base, key) {
                    (SymValue::Path(path), SymValue::Str(key)) => Some(format!("{path}.{key}")),
                    _ => None,
                }
            }
            Expr::SsaVar(var) => match state.vars.get(var) {
                Some(SymValue::Path(path)) => Some(path.clone()),
                _ => None,
            },
            _ => None,
        })
    }

    fn call_value(
        &mut self,
        callee: SymValue,
        args: &[SymValue],
        state: &mut ExecState,
        depth: usize,
    ) -> Result<SymValue> {
        match callee {
            SymValue::Function(index) => {
                let (ret, memory) = self.execute_object(index, args, &state.memory, depth + 1)?;
                state.memory = memory;
                Ok(ret)
            }
            SymValue::Path(path) if path.ends_with(".String") || path == "String" => Ok(args
                .first()
                .map(value_to_string)
                .unwrap_or_else(|| SymValue::Str(String::new()))),
            SymValue::Path(path) if path.ends_with(".Integer") || path == "Integer" => Ok(args
                .first()
                .and_then(value_to_int)
                .map(SymValue::Int)
                .unwrap_or(SymValue::Unknown)),
            _ => Ok(SymValue::Unknown),
        }
    }

    fn call_method(
        &mut self,
        base: SymValue,
        member: &str,
        args: &[SymValue],
        state: &mut ExecState,
        depth: usize,
    ) -> Result<SymValue> {
        // CALLD is not only a native/builtin method call.  tjs2dec lowers a
        // normal TJS member invocation such as `bootstrap()` or
        // `obj.bootstrap()` to Expr::MethodCall as well.  The old executor
        // handled only String builtins here, which meant that a function
        // registered in the TJS object's property table was never entered.
        // In real startup bytecode that made execution stop after the tiny
        // top-level registration stub (typically only a handful of steps).
        match (&base, member) {
            (SymValue::Str(value), "toString") => return Ok(SymValue::Str(value.clone())),
            (SymValue::Str(value), "toLowerCase") => {
                return Ok(SymValue::Str(value.to_lowercase()))
            }
            (SymValue::Str(value), "toUpperCase") => {
                return Ok(SymValue::Str(value.to_uppercase()))
            }
            (SymValue::Str(value), "substr") => return Ok(string_substr(value, args)),
            (SymValue::Str(value), "substring") => return Ok(string_substring(value, args)),
            (SymValue::Str(value), "charAt") => return Ok(string_char_at(value, args)),
            _ => {}
        }

        if let SymValue::Path(base_path) = &base {
            let path = format!("{base_path}.{member}");
            if let Some(callee) = state.memory.get(&path).cloned() {
                return self.call_value(callee, args, state, depth);
            }
        }

        Ok(SymValue::Unknown)
    }

    fn record_path_sink(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        callee: &SymValue,
        args: &[SymValue],
    ) {
        let SymValue::Path(path) = callee else {
            return;
        };
        let Some(member) = path.rsplit('.').next() else {
            return;
        };
        if member == "setupArchiveData"
            || matches!(member, "execStorage" | "evalStorage" | "loadStorage")
        {
            let base = path
                .rsplit_once('.')
                .map(|(base, _)| SymValue::Path(base.to_string()))
                .unwrap_or_else(|| SymValue::Path(String::new()));
            self.record_sink(object, block_id, pc, &base, member, args);
        }
    }

    fn record_sink(
        &mut self,
        object: &Tjs2Object,
        block_id: usize,
        pc: usize,
        base: &SymValue,
        member: &str,
        args: &[SymValue],
    ) {
        let base_name = base.display();
        let target = format!("{base_name}.{member}");
        let argument = args.first().and_then(SymValue::concrete_string).and_then(|value| {
            (value.encode_utf16().count() <= MAX_STRING_UNITS).then(|| value.to_string())
        });
        let call = TjsSymbolicCall {
            object_index: object.index,
            object_name: object.name.clone(),
            block_id,
            pc,
            target,
            argument: argument.clone(),
            argument_repr: args
                .first()
                .map(SymValue::display)
                .unwrap_or_else(|| "<missing>".into()),
        };

        if member == "setupArchiveData" {
            if argument.is_none() {
                self.report.unresolved_setup_calls += 1;
            }
            self.report.setup_archive_data_calls.push(call);
        } else if matches!(member, "execStorage" | "evalStorage" | "loadStorage") {
            if argument.is_none() {
                self.report.unresolved_script_load_calls += 1;
            }
            self.report.script_load_calls.push(call);
        }
    }
}

fn parse_inter_callable(name: &str) -> Option<usize> {
    for prefix in ["#InterObject(", "#InterGenerator("] {
        if let Some(value) = name.strip_prefix(prefix).and_then(|s| s.strip_suffix(')')) {
            if let Ok(index) = value.parse::<usize>() {
                return Some(index);
            }
        }
    }
    None
}

fn merge_values<'a>(values: impl IntoIterator<Item = &'a SymValue>) -> SymValue {
    let mut iter = values.into_iter();
    let Some(first) = iter.next() else {
        return SymValue::Unknown;
    };
    if iter.all(|value| value == first) {
        first.clone()
    } else {
        SymValue::Unknown
    }
}

fn merge_vars<'a>(
    vars: impl IntoIterator<Item = &'a HashMap<VarId, SymValue>>,
) -> HashMap<VarId, SymValue> {
    let vars = vars.into_iter().collect::<Vec<_>>();
    let Some(first) = vars.first() else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (key, value) in first.iter() {
        if vars.iter().skip(1).all(|other| other.get(key) == Some(value)) {
            out.insert(*key, value.clone());
        }
    }
    out
}

fn merge_memories<'a>(
    memories: impl IntoIterator<Item = &'a HashMap<String, SymValue>>,
) -> HashMap<String, SymValue> {
    let memories = memories.into_iter().collect::<Vec<_>>();
    let Some(first) = memories.first() else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (key, value) in first.iter() {
        if memories.iter().skip(1).all(|memory| memory.get(key) == Some(value)) {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

fn normalized_vm_op(op: &str) -> String {
    let upper = op.trim().to_ascii_uppercase();
    upper
        .strip_prefix("VM_")
        .unwrap_or(&upper)
        .to_string()
}

fn eval_opaque_vm_op(op: &str, args: &[SymValue]) -> Option<SymValue> {
    let op = normalized_vm_op(op);
    let first = || args.first().cloned().unwrap_or(SymValue::Unknown);
    let second = || args.get(1).cloned().unwrap_or(SymValue::Unknown);

    let binary = match op.as_str() {
        "ADD" => Some(BinOp::Add),
        "SUB" => Some(BinOp::Sub),
        "MUL" => Some(BinOp::Mul),
        "DIV" | "IDIV" => Some(BinOp::Div),
        "MOD" => Some(BinOp::Mod),
        "SAL" | "SHL" => Some(BinOp::Shl),
        "SAR" | "SHR" => Some(BinOp::Shr),
        "SR" | "USHR" => Some(BinOp::UShr),
        "BAND" => Some(BinOp::BitAnd),
        "BOR" => Some(BinOp::BitOr),
        "BXOR" => Some(BinOp::BitXor),
        "LAND" => Some(BinOp::LogAnd),
        "LOR" => Some(BinOp::LogOr),
        "EQ" | "CEQ" => Some(BinOp::Eq),
        "NE" => Some(BinOp::Ne),
        "DEQ" | "CDEQ" => Some(BinOp::StrictEq),
        "DNE" => Some(BinOp::StrictNe),
        "LT" | "CLT" => Some(BinOp::Lt),
        "LE" => Some(BinOp::Le),
        "GT" | "CGT" => Some(BinOp::Gt),
        "GE" => Some(BinOp::Ge),
        _ => None,
    };
    if let Some(op) = binary {
        return Some(eval_binary(op, first(), second()));
    }

    Some(match op.as_str() {
        "CHS" => eval_unary(UnOp::Neg, first()),
        "LNOT" => eval_unary(UnOp::Not, first()),
        "BNOT" => eval_unary(UnOp::BitNot, first()),
        // chgthis mutates only the closure's bound-this object.  The callable
        // identity itself is unchanged, which is the part needed by this
        // executor to follow the subsequent SPDE/CALLD chain.  addci likewise
        // augments class-instance metadata without replacing the object.
        "CHGTHIS" | "ADDCI" => first(),
        "STR" | "STRING" => value_to_string(&first()),
        "INT" => value_to_int(&first())
            .map(SymValue::Int)
            .unwrap_or(SymValue::Unknown),
        "NUM" => value_to_number(&first()),
        "REAL" => match first() {
            SymValue::Real(value) => SymValue::Real(value),
            SymValue::Int(value) => SymValue::Real(value as f64),
            SymValue::Bool(value) => SymValue::Real(if value { 1.0 } else { 0.0 }),
            SymValue::Str(value) => value
                .trim()
                .parse::<f64>()
                .map(SymValue::Real)
                .unwrap_or(SymValue::Unknown),
            _ => SymValue::Unknown,
        },
        "CHR" => {
            let Some(value) = value_to_int(&first()) else {
                return Some(SymValue::Unknown);
            };
            let unit = value as u16;
            SymValue::Str(String::from_utf16_lossy(&[unit]))
        }
        "ASC" => match first() {
            SymValue::Str(value) => SymValue::Int(
                value.encode_utf16().next().map(i64::from).unwrap_or(0),
            ),
            _ => SymValue::Int(0),
        },
        "TYPEOF" => eval_unary(UnOp::Typeof, first()),
        _ => return None,
    })
}

fn eval_unary(op: UnOp, value: SymValue) -> SymValue {
    match op {
        UnOp::Neg => match value {
            SymValue::Int(v) => SymValue::Int(v.wrapping_neg()),
            SymValue::Real(v) => SymValue::Real(-v),
            _ => SymValue::Unknown,
        },
        UnOp::Not => value
            .truthy()
            .map(|value| SymValue::Bool(!value))
            .unwrap_or(SymValue::Unknown),
        UnOp::BitNot => value_to_int(&value)
            .map(|value| SymValue::Int(!value))
            .unwrap_or(SymValue::Unknown),
        UnOp::Num => value_to_number(&value),
        UnOp::CharCode => match value_to_string(&value) {
            SymValue::Str(value) => SymValue::Int(
                value.encode_utf16().next().map(i64::from).unwrap_or(0),
            ),
            _ => SymValue::Unknown,
        },
        UnOp::CharFromCode => {
            let Some(value) = value_to_int(&value) else {
                return SymValue::Unknown;
            };
            let unit = value as u16;
            // TJS strings can contain an isolated UTF-16 surrogate; Rust String
            // cannot, so do not silently normalize it to U+FFFD.
            if (0xd800..=0xdfff).contains(&unit) {
                SymValue::Unknown
            } else {
                char::from_u32(unit as u32)
                    .map(|ch| SymValue::Str(ch.to_string()))
                    .unwrap_or(SymValue::Unknown)
            }
        }
        // TJS2 typeof is not JavaScript typeof.  The VM returns these exact
        // type names/casing.
        UnOp::Typeof => SymValue::Str(
            match value {
                SymValue::Void => "void",
                SymValue::Null
                | SymValue::Array(_)
                | SymValue::Dictionary(_)
                | SymValue::RegExp(_)
                | SymValue::Path(_)
                | SymValue::Function(_) => "Object",
                SymValue::Bool(_) | SymValue::Int(_) => "Integer",
                SymValue::Real(_) => "Real",
                SymValue::Str(_) => "String",
                SymValue::Octet(_) => "Octet",
                SymValue::Unknown | SymValue::Symbolic(_) => return SymValue::Unknown,
            }
            .into(),
        ),
        UnOp::Delete => SymValue::Unknown,
        UnOp::Int => value_to_int(&value)
            .map(SymValue::Int)
            .unwrap_or(SymValue::Unknown),
        UnOp::Real => value_to_real(&value),
        UnOp::String => value_to_string(&value),
        UnOp::Octet => match value {
            SymValue::Octet(bytes) => SymValue::Octet(bytes),
            _ => SymValue::Unknown,
        },
        UnOp::Invalidate => match value {
            SymValue::Void
            | SymValue::Null
            | SymValue::Bool(_)
            | SymValue::Int(_)
            | SymValue::Real(_)
            | SymValue::Str(_)
            | SymValue::Octet(_) => SymValue::Bool(false),
            SymValue::Array(_)
            | SymValue::Dictionary(_)
            | SymValue::RegExp(_)
            | SymValue::Path(_)
            | SymValue::Function(_)
            | SymValue::Unknown
            | SymValue::Symbolic(_) => SymValue::Unknown,
        },
        UnOp::IsValid => match value {
            SymValue::Void
            | SymValue::Null
            | SymValue::Bool(_)
            | SymValue::Int(_)
            | SymValue::Real(_)
            | SymValue::Str(_)
            | SymValue::Octet(_) => SymValue::Bool(true),
            SymValue::Array(_)
            | SymValue::Dictionary(_)
            | SymValue::RegExp(_)
            | SymValue::Path(_)
            | SymValue::Function(_)
            | SymValue::Unknown
            | SymValue::Symbolic(_) => SymValue::Unknown,
        },
        // IgnoreProp changes getter/setter dispatch, not the materialized value.
        // This executor does not model the dispatch distinction separately.
        UnOp::IgnoreProp => value,
    }
}

fn eval_binary(op: BinOp, left: SymValue, right: SymValue) -> SymValue {
    match op {
        BinOp::Add => {
            if matches!(left, SymValue::Str(_)) || matches!(right, SymValue::Str(_)) {
                match (value_to_string(&left), value_to_string(&right)) {
                    (SymValue::Str(mut a), SymValue::Str(b)) => {
                        a.push_str(&b);
                        if a.encode_utf16().count() <= MAX_STRING_UNITS {
                            SymValue::Str(a)
                        } else {
                            SymValue::Unknown
                        }
                    }
                    _ => SymValue::Unknown,
                }
            } else {
                numeric_binary(op, left, right)
            }
        }
        BinOp::Sub
        | BinOp::Mul
        | BinOp::Div
        | BinOp::IDiv
        | BinOp::Mod
        | BinOp::Shl
        | BinOp::Shr
        | BinOp::UShr
        | BinOp::BitAnd
        | BinOp::BitOr
        | BinOp::BitXor => numeric_binary(op, left, right),
        BinOp::Eq | BinOp::StrictEq => {
            if matches!(
                (&left, &right),
                (SymValue::Array(_), _)
                    | (_, SymValue::Array(_))
                    | (SymValue::Dictionary(_), _)
                    | (_, SymValue::Dictionary(_))
                    | (SymValue::RegExp(_), _)
                    | (_, SymValue::RegExp(_))
            ) {
                SymValue::Unknown
            } else {
                SymValue::Bool(left == right)
            }
        }
        BinOp::Ne | BinOp::StrictNe => {
            if matches!(
                (&left, &right),
                (SymValue::Array(_), _)
                    | (_, SymValue::Array(_))
                    | (SymValue::Dictionary(_), _)
                    | (_, SymValue::Dictionary(_))
                    | (SymValue::RegExp(_), _)
                    | (_, SymValue::RegExp(_))
            ) {
                SymValue::Unknown
            } else {
                SymValue::Bool(left != right)
            }
        }
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => compare_binary(op, left, right),
        BinOp::LogAnd => match left.truthy() {
            Some(false) => left,
            Some(true) => right,
            None => SymValue::Unknown,
        },
        BinOp::LogOr => match left.truthy() {
            Some(true) => left,
            Some(false) => right,
            None => SymValue::Unknown,
        },
        BinOp::Assign => right,
        BinOp::AddAssign => eval_binary(BinOp::Add, left, right),
        BinOp::SubAssign => eval_binary(BinOp::Sub, left, right),
        BinOp::MulAssign => eval_binary(BinOp::Mul, left, right),
        BinOp::DivAssign => eval_binary(BinOp::Div, left, right),
        BinOp::IDivAssign => eval_binary(BinOp::IDiv, left, right),
        BinOp::ModAssign => eval_binary(BinOp::Mod, left, right),
        BinOp::ShlAssign => eval_binary(BinOp::Shl, left, right),
        BinOp::ShrAssign => eval_binary(BinOp::Shr, left, right),
        BinOp::UShrAssign => eval_binary(BinOp::UShr, left, right),
        BinOp::AndAssign => eval_binary(BinOp::BitAnd, left, right),
        BinOp::OrAssign => eval_binary(BinOp::BitOr, left, right),
        BinOp::XorAssign => eval_binary(BinOp::BitXor, left, right),
        BinOp::LogAndAssign => eval_binary(BinOp::LogAnd, left, right),
        BinOp::LogOrAssign => eval_binary(BinOp::LogOr, left, right),
        BinOp::In | BinOp::InstanceOf => SymValue::Unknown,
        // `incontextof` changes the bound `this`; keep callable identity so
        // bootstrap call chains remain followable.
        BinOp::InContextOf => left,
    }
}

fn numeric_binary(op: BinOp, left: SymValue, right: SymValue) -> SymValue {
    let (Some(a), Some(b)) = (value_to_int(&left), value_to_int(&right)) else {
        return SymValue::Unknown;
    };
    match op {
        BinOp::Add => SymValue::Int(a.wrapping_add(b)),
        BinOp::Sub => SymValue::Int(a.wrapping_sub(b)),
        BinOp::Mul => SymValue::Int(a.wrapping_mul(b)),
        BinOp::Div if b != 0 => a
            .checked_div(b)
            .map(SymValue::Int)
            .unwrap_or(SymValue::Unknown),
        BinOp::IDiv if b != 0 => a
            .checked_div(b)
            .map(SymValue::Int)
            .unwrap_or(SymValue::Unknown),
        BinOp::Mod if b != 0 => a
            .checked_rem(b)
            .map(SymValue::Int)
            .unwrap_or(SymValue::Unknown),
        BinOp::Shl => SymValue::Int(a.wrapping_shl((b as u32) & 63)),
        BinOp::Shr => SymValue::Int(a.wrapping_shr((b as u32) & 63)),
        BinOp::UShr => SymValue::Int(((a as u64) >> ((b as u32) & 63)) as i64),
        BinOp::BitAnd => SymValue::Int(a & b),
        BinOp::BitOr => SymValue::Int(a | b),
        BinOp::BitXor => SymValue::Int(a ^ b),
        _ => SymValue::Unknown,
    }
}

fn compare_binary(op: BinOp, left: SymValue, right: SymValue) -> SymValue {
    if let (Some(a), Some(b)) = (value_to_int(&left), value_to_int(&right)) {
        return SymValue::Bool(match op {
            BinOp::Lt => a < b,
            BinOp::Le => a <= b,
            BinOp::Gt => a > b,
            BinOp::Ge => a >= b,
            _ => false,
        });
    }
    if let (SymValue::Str(a), SymValue::Str(b)) = (left, right) {
        return SymValue::Bool(match op {
            BinOp::Lt => a < b,
            BinOp::Le => a <= b,
            BinOp::Gt => a > b,
            BinOp::Ge => a >= b,
            _ => false,
        });
    }
    SymValue::Unknown
}

fn value_to_number(value: &SymValue) -> SymValue {
    match value {
        SymValue::Int(v) => SymValue::Int(*v),
        SymValue::Real(v) => SymValue::Real(*v),
        SymValue::Bool(v) => SymValue::Int(if *v { 1 } else { 0 }),
        SymValue::Str(v) => {
            let text = v.trim();
            if let Ok(value) = text.parse::<i64>() {
                SymValue::Int(value)
            } else if let Ok(value) = text.parse::<f64>() {
                SymValue::Real(value)
            } else {
                SymValue::Unknown
            }
        }
        _ => SymValue::Unknown,
    }
}

fn value_to_real(value: &SymValue) -> SymValue {
    match value {
        SymValue::Real(v) => SymValue::Real(*v),
        SymValue::Int(v) => SymValue::Real(*v as f64),
        SymValue::Bool(v) => SymValue::Real(if *v { 1.0 } else { 0.0 }),
        SymValue::Str(v) => v
            .trim()
            .parse::<f64>()
            .map(SymValue::Real)
            .unwrap_or(SymValue::Unknown),
        _ => SymValue::Unknown,
    }
}

fn value_to_int(value: &SymValue) -> Option<i64> {
    match value {
        SymValue::Int(v) => Some(*v),
        SymValue::Bool(v) => Some(if *v { 1 } else { 0 }),
        SymValue::Real(v) if v.is_finite() => Some(*v as i64),
        SymValue::Str(v) => v.trim().parse().ok(),
        _ => None,
    }
}

fn value_to_string(value: &SymValue) -> SymValue {
    match value {
        SymValue::Str(v) => SymValue::Str(v.clone()),
        SymValue::Int(v) => SymValue::Str(v.to_string()),
        SymValue::Real(v) => SymValue::Str(v.to_string()),
        SymValue::Bool(v) => SymValue::Str(v.to_string()),
        SymValue::Void => SymValue::Str("void".into()),
        SymValue::Null => SymValue::Str("null".into()),
        _ => SymValue::Unknown,
    }
}

fn utf16_units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn string_substr(value: &str, args: &[SymValue]) -> SymValue {
    let Some(start) = args.first().and_then(value_to_int) else {
        return SymValue::Unknown;
    };
    let units = utf16_units(value);
    let len = units.len() as i64;
    let start = if start < 0 { (len + start).max(0) } else { start.min(len) } as usize;
    let end = args
        .get(1)
        .and_then(value_to_int)
        .map(|count| (start as i64 + count.max(0)).min(len) as usize)
        .unwrap_or(units.len());
    SymValue::Str(String::from_utf16_lossy(&units[start..end]))
}

fn string_substring(value: &str, args: &[SymValue]) -> SymValue {
    let Some(mut start) = args.first().and_then(value_to_int) else {
        return SymValue::Unknown;
    };
    let units = utf16_units(value);
    let len = units.len() as i64;
    start = start.clamp(0, len);
    let mut end = args
        .get(1)
        .and_then(value_to_int)
        .unwrap_or(len)
        .clamp(0, len);
    if start > end {
        std::mem::swap(&mut start, &mut end);
    }
    SymValue::Str(String::from_utf16_lossy(&units[start as usize..end as usize]))
}

fn string_char_at(value: &str, args: &[SymValue]) -> SymValue {
    let Some(index) = args.first().and_then(value_to_int) else {
        return SymValue::Unknown;
    };
    if index < 0 {
        return SymValue::Str(String::new());
    }
    let units = utf16_units(value);
    let Some(unit) = units.get(index as usize) else {
        return SymValue::Str(String::new());
    };
    SymValue::Str(String::from_utf16_lossy(std::slice::from_ref(unit)))
}

/// Symbolically execute compiled TJS2 and report concrete arguments reaching
/// bootstrap-relevant native calls.  This is intentionally bounded; an
/// unresolved call is reported as unresolved rather than guessed from the
/// constant/string pool.
pub fn symbolically_execute_tjs2(bytes: &[u8]) -> Result<TjsSymbolicReport> {
    let file = load_tjs2_bytecode(bytes)
        .map_err(|e| Error::invalid(format!("TJS2 bytecode load failed: {e}")))?;
    let toplevel = usize::try_from(file.toplevel)
        .map_err(|_| Error::invalid(format!("invalid TJS2 toplevel object {}", file.toplevel)))?;
    let mut executor = Executor::new(&file);
    let memory = HashMap::new();
    let _ = executor.execute_object(toplevel, &[], &memory, 0)?;
    Ok(executor.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_addition_is_folded() {
        assert_eq!(
            eval_binary(
                BinOp::Add,
                SymValue::Str("archive-".into()),
                SymValue::Str("secret".into())
            ),
            SymValue::Str("archive-secret".into())
        );
    }

    #[test]
    fn opaque_vm_add_is_folded() {
        assert_eq!(
            eval_opaque_vm_op(
                "ADD",
                &[SymValue::Str("archive-".into()), SymValue::Str("secret".into())],
            ),
            Some(SymValue::Str("archive-secret".into()))
        );
        assert_eq!(
            eval_opaque_vm_op(
                "vm_add",
                &[SymValue::Str("a".into()), SymValue::Str("b".into())],
            ),
            Some(SymValue::Str("ab".into()))
        );
    }

    #[test]
    fn utf16_substring_uses_tjs_units() {
        assert_eq!(
            string_substring(
                "A😀B",
                &[SymValue::Int(1), SymValue::Int(3)]
            ),
            SymValue::Str("😀".into())
        );
    }

    #[test]
    fn inter_object_is_recognized() {
        assert_eq!(parse_inter_callable("#InterObject(17)"), Some(17));
        assert_eq!(parse_inter_callable("#InterGenerator(23)"), Some(23));
        assert_eq!(parse_inter_callable("#Unknown"), None);
    }

    #[test]
    fn chgthis_preserves_inter_object_callable() {
        assert_eq!(
            eval_opaque_vm_op(
                "VM_CHGTHIS",
                &[SymValue::Function(17), SymValue::Path("global".into())],
            ),
            Some(SymValue::Function(17))
        );
    }

    #[test]
    fn vm_str_uses_the_real_mnemonic() {
        assert_eq!(
            eval_opaque_vm_op("VM_STR", &[SymValue::Int(1234)]),
            Some(SymValue::Str("1234".into()))
        );
    }

    #[test]
    fn typeof_uses_tjs2_type_names() {
        assert_eq!(
            eval_unary(UnOp::Typeof, SymValue::Path("global.Storages.setupArchiveData".into())),
            SymValue::Str("Object".into())
        );
        assert_eq!(
            eval_unary(UnOp::Typeof, SymValue::Str("value".into())),
            SymValue::Str("String".into())
        );
        assert_eq!(
            eval_unary(UnOp::Typeof, SymValue::Int(1)),
            SymValue::Str("Integer".into())
        );
        assert_eq!(
            eval_unary(UnOp::Typeof, SymValue::Real(1.0)),
            SymValue::Str("Real".into())
        );
    }
    #[test]
    fn inline_collection_values_are_truthy_and_indexable() {
        let array = SymValue::Array(vec![
            SymValue::Str("first".into()),
            SymValue::Int(2),
        ]);
        assert_eq!(array.truthy(), Some(true));
        let state = ExecState::new(0);
        let executor_file = Tjs2File {
            toplevel: 0,
            const_pools: Default::default(),
            objects: Vec::new(),
        };
        let executor = Executor::new(&executor_file);
        assert_eq!(
            executor.read_index(array, SymValue::Int(0), &state),
            SymValue::Str("first".into())
        );
    }
}
