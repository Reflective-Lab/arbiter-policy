// Real Cedar policy for expense approval and reimbursement governance.
//
// Principal attributes:
// - authority: advisory | supervisory | participatory | sovereign
// - domains: set<string>
//
// Resource attributes:
// - resource_type: expense | quote | contract | invoice
// - phase: intent | framing | convergence | commitment
// - gates_passed: set<string>
//
// Context:
// - commitment_type
// - amount
// - human_approval_present
// - required_gates_met

// Any persona can submit an expense report into the flow.
permit(principal, action == Action::"propose", resource)
when {
  resource.resource_type == "expense" &&
  context.commitment_type == "expense"
};

// Finance can validate expense reports once the receipt is present.
permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") &&
  (principal.authority == "supervisory" ||
   principal.authority == "participatory" ||
   principal.authority == "sovereign") &&
  resource.gates_passed.contains("receipt")
};

// Promotion to reimbursement-ready requires finance ownership and both key gates.
permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") &&
  (principal.authority == "supervisory" ||
   principal.authority == "sovereign") &&
  resource.gates_passed.contains("receipt") &&
  resource.gates_passed.contains("manager_approval") &&
  context.required_gates_met == true
};

// Sovereign can commit payment once the expense has fully cleared gates.
permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("receipt") &&
  resource.gates_passed.contains("manager_approval") &&
  context.required_gates_met == true
};

// Supervisory finance can commit lower-value reimbursements with explicit human approval.
permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") &&
  principal.authority == "supervisory" &&
  context.amount <= 5000 &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("receipt") &&
  resource.gates_passed.contains("manager_approval") &&
  context.required_gates_met == true
};

// High-value reimbursement cannot commit without explicit human approval.
forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  context.amount > 5000 &&
  context.human_approval_present == false
};

// Expense validation and payment actions are reserved to finance.
forbid(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  principal.domains.contains("finance") == false
};

// Promotion and commit both require receipt + manager approval + passed gates.
forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "expense" &&
  (resource.gates_passed.contains("receipt") == false ||
   resource.gates_passed.contains("manager_approval") == false ||
   context.required_gates_met == false)
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "expense" &&
  (resource.gates_passed.contains("receipt") == false ||
   resource.gates_passed.contains("manager_approval") == false ||
   context.required_gates_met == false)
};
