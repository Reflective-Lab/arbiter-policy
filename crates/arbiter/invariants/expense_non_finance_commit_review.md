# Expense Non-Finance Commit Claim Review

Business claim:

> A supervisory persona outside the finance domain cannot commit a high-value
> expense even when receipt, manager approval, required gates, and explicit
> human approval are present.

The symbolic query `ExpenseNonFinanceHighValueCommitDenied` encodes the
positive claim space as a Cedar policy. `NoViolation` is useful only if this
claim policy matches the business statement.

## Positive Claim Fixture

| Field | Value |
|---|---|
| principal domain | not `finance` |
| principal authority | `supervisory` |
| action | `commit` |
| resource type | `expense` |
| amount | `> 5000` |
| human approval | `true` |
| gates | `receipt`, `manager_approval` |
| required gates met | `true` |

The production expense policy must reject this fixture.

## Boundary Fixtures

Each row changes one field from the positive fixture and should fall outside
the encoded claim policy.

| Case | Changed field | Reason |
|---|---|---|
| finance domain | domain = `finance` | claim is about non-finance principals |
| advisory authority | authority = `advisory` | claim is about supervisory principals |
| threshold amount | amount = `5000` | claim is above 5000, not at or above |
| no human approval | human approval = `false` | claim says even when approval is present |
| missing receipt | gates omit `receipt` | claim assumes receipt has passed |
| missing manager approval | gates omit `manager_approval` | claim assumes manager approval has passed |
| gates not met | required gates met = `false` | claim assumes required gates are met |
| non-expense resource | resource type = `invoice` | claim is expense-specific |
| wrong action | action = `validate` | claim is commit-specific |

These fixtures are exercised in `tests/analysis_symcc.rs`. They are review
fixtures for model adequacy, not proof evidence.
