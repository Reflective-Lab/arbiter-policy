// Converge Policy: agent authority and commitment governance
//
// Principals are Agent::Persona with attribute "authority":
//   "advisory", "supervisory", "participatory", "sovereign"
//
// Actions: propose, validate, promote, commit, advance_phase
//
// Context carries: commitment_type, amount, human_approval_present, required_gates_met

// ---------- Base rule: any persona can propose ----------
permit(principal, action == Action::"propose", resource)
when {
  principal.authority == "advisory" ||
  principal.authority == "supervisory" ||
  principal.authority == "participatory" ||
  principal.authority == "sovereign"
};

// ---------- Validation: supervisory+ can validate ----------
permit(principal, action == Action::"validate", resource)
when {
  principal.authority == "supervisory" ||
  principal.authority == "participatory" ||
  principal.authority == "sovereign"
};

// ---------- Promotion: supervisory or sovereign can promote ----------
permit(principal, action == Action::"promote", resource)
when {
  principal.authority == "supervisory" ||
  principal.authority == "sovereign"
};

// ---------- Commit: sovereign can commit autonomously ----------
permit(principal, action == Action::"commit", resource)
when {
  principal.authority == "sovereign"
};

// ---------- Commit: supervisory can commit with human approval ----------
permit(principal, action == Action::"commit", resource)
when {
  principal.authority == "supervisory" &&
  context.human_approval_present == true
};

// ---------- Commit: block if amount exceeds 50k without approval ----------
forbid(principal, action == Action::"commit", resource)
when {
  context.amount > 50000 &&
  context.human_approval_present == false
};

// ---------- Phase advancement: require gates + supervisory+ ----------
permit(principal, action == Action::"advance_phase", resource)
when {
  (principal.authority == "supervisory" || principal.authority == "sovereign") &&
  context.required_gates_met == true
};

// ---------- Advisory agents: cap spend proposals at 10k ----------
forbid(principal, action == Action::"propose", resource)
when {
  principal.authority == "advisory" &&
  context.commitment_type == "spend" &&
  context.amount > 10000
};
