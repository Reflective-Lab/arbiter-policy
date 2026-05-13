Feature: Expense approval policy invariants

  Scenario: Non-finance cannot commit a high-value expense
    Given a supervisory persona outside the finance domain
    And a high-value expense with receipt and manager approval gates passed
    And explicit human approval is present
    When the persona attempts to commit the expense
    Then Arbiter must reject the decision
