// Real Cedar policy for default governed business flows.
//
// Principal attributes:
// - authority: advisory | supervisory | participatory | sovereign
// - domains: set<string>
//
// Resource attributes:
// - resource_type: quote | spend | contract | invoice | period
// - phase: intent | framing | convergence | commitment
// - gates_passed: set<string>
//
// Context:
// - commitment_type
// - amount
// - human_approval_present
// - required_gates_met

// Quotes ---------------------------------------------------------------------

permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") &&
  principal.authority == "sovereign" &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") &&
  principal.authority == "supervisory" &&
  context.human_approval_present == true &&
  context.required_gates_met == true
};

forbid(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "quote" &&
  principal.domains.contains("sales") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "quote" &&
  context.required_gates_met == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "quote" &&
  context.required_gates_met == false
};

// Spend ----------------------------------------------------------------------

permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  (principal.authority == "supervisory" ||
   principal.authority == "participatory" ||
   principal.authority == "sovereign") &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "spend" &&
  principal.domains.contains("procurement") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("vendor_due_diligence") &&
  resource.gates_passed.contains("competitive_review") &&
  context.required_gates_met == true
};

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

// Contracts ------------------------------------------------------------------

permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  resource.gates_passed.contains("legal_review") &&
  resource.gates_passed.contains("counterparty_signed") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  resource.gates_passed.contains("legal_review") &&
  resource.gates_passed.contains("counterparty_signed") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("legal_review") &&
  resource.gates_passed.contains("counterparty_signed") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") &&
  principal.authority == "supervisory" &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("legal_review") &&
  resource.gates_passed.contains("counterparty_signed") &&
  context.required_gates_met == true
};

forbid(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "contract" &&
  principal.domains.contains("legal") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "contract" &&
  (resource.gates_passed.contains("legal_review") == false ||
   resource.gates_passed.contains("counterparty_signed") == false ||
   context.required_gates_met == false)
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "contract" &&
  (resource.gates_passed.contains("legal_review") == false ||
   resource.gates_passed.contains("counterparty_signed") == false ||
   context.required_gates_met == false)
};

// Invoices -------------------------------------------------------------------

permit(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  resource.gates_passed.contains("customer_validated") &&
  resource.gates_passed.contains("line_items_balanced") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") &&
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  resource.gates_passed.contains("customer_validated") &&
  resource.gates_passed.contains("line_items_balanced") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("customer_validated") &&
  resource.gates_passed.contains("line_items_balanced") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") &&
  principal.authority == "supervisory" &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("customer_validated") &&
  resource.gates_passed.contains("line_items_balanced") &&
  context.required_gates_met == true
};

forbid(principal, action == Action::"validate", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "invoice" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"promote", resource)
when {
  resource.resource_type == "invoice" &&
  (resource.gates_passed.contains("customer_validated") == false ||
   resource.gates_passed.contains("line_items_balanced") == false ||
   context.required_gates_met == false)
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "invoice" &&
  (resource.gates_passed.contains("customer_validated") == false ||
   resource.gates_passed.contains("line_items_balanced") == false ||
   context.required_gates_met == false)
};

// Period close ---------------------------------------------------------------

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "period" &&
  principal.domains.contains("finance") &&
  principal.authority == "supervisory" &&
  context.human_approval_present == true &&
  resource.gates_passed.contains("reconciliation_complete") &&
  context.required_gates_met == true
};

permit(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "period" &&
  principal.domains.contains("finance") &&
  principal.authority == "sovereign" &&
  resource.gates_passed.contains("reconciliation_complete") &&
  context.required_gates_met == true
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "period" &&
  principal.domains.contains("finance") == false
};

forbid(principal, action == Action::"commit", resource)
when {
  resource.resource_type == "period" &&
  (resource.gates_passed.contains("reconciliation_complete") == false ||
   context.required_gates_met == false)
};
