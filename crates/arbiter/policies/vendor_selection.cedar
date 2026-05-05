// Real Cedar policy for procurement-backed vendor selection and spend commitment.
//
// Principal attributes:
// - authority: advisory | supervisory | participatory | sovereign
// - domains: set<string>
//
// Resource attributes:
// - resource_type: spend
// - phase: intent | framing | convergence | commitment
// - gates_passed: set<string>
//
// Context:
// - commitment_type
// - amount
// - human_approval_present
// - required_gates_met

// Procurement may validate a vendor recommendation when due diligence is complete.
permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  (principal.authority == "supervisory" ||
   principal.authority == "participatory" ||
   principal.authority == "sovereign") &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review")
};

// Procurement may promote the recommendation into a finalist when core gates pass.
permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  (principal.authority == "supervisory" ||
   principal.authority == "sovereign") &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

// Sovereign procurement can commit any fully-gated vendor selection.
permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

// Supervisory procurement can commit lower-value selections with explicit human approval.
permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  principal.authority == "supervisory" &&
  context.amount <= 20000 &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

// High-value procurement cannot commit without human approval.
forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  context.amount > 20000 &&
  context.human_approval_present == false
};

// Procurement-only actions.
forbid(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") == false
};

// All consequential actions require due diligence and competitive review.
forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "spend" &&
  (resource.gates_passed.contains("vendor_due_diligence") == false ||
   resource.gates_passed.contains("competitive_review") == false ||
   context.required_gates_met == false)
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  (resource.gates_passed.contains("vendor_due_diligence") == false ||
   resource.gates_passed.contains("competitive_review") == false ||
   context.required_gates_met == false)
};
