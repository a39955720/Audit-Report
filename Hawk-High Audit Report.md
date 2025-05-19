# Hawk High - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Unenforced cutOffScore Threshold in Graduation Logic](#H-01)
    - ### [H-02. Silent Failure to Upgrade in LevelOne::graduateAndUpgrade](#H-02)
    - ### [H-03. Public Access to LevelTwo::graduate Allows Unauthorized Reinitializer](#H-03)
- ## Medium Risk Findings
    - ### [M-01. Storage Collision in LevelTwo Due to Removed schoolFees Variable](#M-01)
- ## Low Risk Findings
    - ### [L-01. Missing reviewCount Incrementation in LevelOne::giveReview](#L-01)
    - ### [L-02. Permanent Session Lock from inSession Never Reset](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #39

### Dates: May 1st, 2025 - May 8th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-05-hawk-high)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 3
- Medium: 1
- Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. Unenforced cutOffScore Threshold in Graduation Logic            



## Summary

The `cutOffScore` variable in the `LevelOne` contract is intended to represent the minimum score a student must achieve to graduate or qualify for rewards. While it is set during the `startSession` function, **it is never actually used in any part of the graduation or reward logic**, which in your upgraded design now resides in `LevelTwo::graduate`. As a result, all students—regardless of performance—are allowed to graduate, and the intended score-based filtering is silently bypassed.

***

## Vulnerability Details

```solidity
// In LevelOne:
function startSession(uint256 _cutOffScore) public onlyPrincipal notYetInSession {
    sessionEnd = block.timestamp + 4 weeks;
    inSession = true;
    cutOffScore = _cutOffScore;

    emit SchoolInSession(block.timestamp, sessionEnd);
}

// @audit-issue cutOffScore is never used to enforce graduation conditions
// @> No logic in LevelTwo::graduate() checks if studentScore >= cutOffScore

// In LevelTwo:
function graduate() public reinitializer(2) {
    // @> Missing: should filter students by studentScore >= cutOffScore
}
```

### Issue Explanation

1. **Unused Threshold**
   The `cutOffScore` set in LevelOne is never read or enforced in the actual graduation function `LevelTwo::graduate()`.

2. **Bypassed Academic Requirements**
   Without checking `studentScore` against `cutOffScore`, students with failing performance still graduate.

3. **Misleading Design**
   Stakeholders expect a score threshold to gate graduation, but the contract logic does not implement it, creating a deceptive interface.

***

## Impact

* **Business Logic Flaw**: Students who did not meet minimum performance requirements are still graduated.
* **Loss of Intended Incentive**: Reviews and performance tracking have no real consequence.
* **User Confusion**: Users and auditors assume the threshold is enforced, but it is not.

***

## Tools Used

* Manual Code Review

***

## Recommendations

### Option A – Enforce `cutOffScore` in LevelTwo::graduate()

Add a check in the `graduate()` function to only graduate and distribute rewards to students whose score meets or exceeds the threshold:

```solidity
function graduate() public reinitializer(2) onlyPrincipal {
    uint256 totalTeachers = listOfTeachers.length;
    // Prepare payout values as needed...
    // Example: uint256 payPerTeacher = (bursary * TEACHER_WAGE_L2) / PRECISION;
    //          uint256 principalPay   = (bursary * PRINCIPAL_WAGE_L2) / PRECISION;

    for (uint256 i = 0; i < listOfStudents.length; i++) {
        address student = listOfStudents[i];
        // @fix Only graduate students meeting the cutOffScore
        if (studentScore[student] >= cutOffScore) {
            // Perform graduation logic for this student:
            // e.g., call upgrade, record event, etc.
        }
    }

    // Optionally distribute bursary among qualified students and principal, then reset
    bursary = 0;
    inSession = false;
}
```

### Option B – Enforce in LevelOne::graduateAndUpgrade()

If you still use `LevelOne::graduateAndUpgrade` for the actual payout, add the same filtering there:

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    // ... existing setup ...
    for (uint256 n = 0; n < listOfStudents.length; n++) {
        address student = listOfStudents[n];
        if (studentScore[student] >= cutOffScore) {
            // distribute to corresponding teachers/principal
        }
    }
    bursary = 0;
}
```

***

## <a id='H-02'></a>H-02. Silent Failure to Upgrade in LevelOne::graduateAndUpgrade            



## Summary

The `LevelOne::graduateAndUpgrade` function intends to perform contract upgrade logic alongside graduation and reward distribution. However, it incorrectly calls `_authorizeUpgrade(_levelTwo)` directly, which only performs an access control check but **does not execute the actual upgrade**. As a result, the proxy contract's implementation is **never changed**, and the upgrade silently fails.

***

## Vulnerability Details

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    ...
    _authorizeUpgrade(_levelTwo); // @audit-issue only performs access check
    // @> Proxy implementation is never updated; upgradeTo is never called
}
```

### Issue Explanation

1. **Misunderstanding of** **`_authorizeUpgrade`** **Role**
   `_authorizeUpgrade()` is a hook meant to be called *by* the upgrade mechanism to verify permissions. Calling it manually **does not trigger any upgrade**.

2. **No Use of** **`upgradeTo`** **or** **`upgradeToAndCall`**
   The correct upgrade mechanism provided by OpenZeppelin’s `UUPSUpgradeable` is never invoked, meaning the proxy continues pointing to the old implementation.

3. **Silent Failure**
   Since `_authorizeUpgrade()` will pass if `msg.sender` is authorized, the function appears to succeed, misleading developers and users into thinking the upgrade was applied.

***

## Impact

* **Functionality Breakage**: Proxy contract remains on the old implementation despite expecting a transition.
* **Upgrade Failure**: New logic in `LevelTwo` (e.g., updated `graduate()` or state variables) never becomes active.
* **Misleading Execution**: Graduation proceeds with the belief of successful upgrade, leading to inconsistencies.

***

## Tools Used

* Manual Code Review

***

## Recommendations

Replace the manual `_authorizeUpgrade` call with an actual upgrade operation:

### Option A – Use `upgradeTo`

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    upgradeTo(_levelTwo); // @fix triggers actual proxy upgrade via UUPS
    ...
}
```

### Option B – Use `upgradeToAndCall` (if initialization logic is required)

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory data) public onlyPrincipal {
    upgradeToAndCall(_levelTwo, data); // @fix upgrade + initialize new implementation
    ...
}
```

Ensure that the contract extends `UUPSUpgradeable` and that `_authorizeUpgrade()` is properly implemented for access control:

```solidity
function _authorizeUpgrade(address newImplementation) internal override onlyPrincipal {}
```

***

## <a id='H-03'></a>H-03. Public Access to LevelTwo::graduate Allows Unauthorized Reinitializer            



## Summary

The `LevelTwo::graduate` function is marked with the `reinitializer(2)` modifier and is publicly accessible without any access control. This means **any external user** can invoke it once, consuming the contract's version 2 reinitialization slot. As a result, the legitimate contract owner (e.g., the principal) may be permanently prevented from executing critical upgrade-time logic, such as setting new variables or distributing funds.

***

## Vulnerability Details

```solidity
// @audit-issue Public graduate() function lacks access control, allowing any user to consume reinitializer(2)
function graduate() public reinitializer(2) {
    // no access restriction
    // @> Anyone can trigger this, permanently locking out reinitialization logic
}
```

### Issue Explanation

1. **Unrestricted Access**
   Since the function is `public` and has no `onlyPrincipal` or equivalent modifier, any address can call it.

2. **Consumes reinitializer(2)**
   The `reinitializer(2)` modifier ensures that this function can only be executed once. If a malicious user calls it first, the contract is marked as "initialized to version 2", blocking any future `reinitializer(2)` logic.

3. **Breaks Upgrade Safety**
   This may prevent proper initialization of new state variables or distribution of resources introduced in LevelTwo, leading to broken business logic and stuck funds.

***

## Impact

* **Denial of Initialization**: Legitimate parties are blocked from performing upgrade-time setup.
* **Potential Logic Incompleteness**: Contract may remain in a partially-upgraded, unusable state.
* **System Integrity Loss**: Future UUPS upgrades or state transitions may silently fail.

***

## Tools Used

* Manual Code Review

***

## Recommendations

Add appropriate access control (e.g., `onlyPrincipal`) to restrict `graduate()` execution to authorized parties only:

```solidity
modifier onlyPrincipal() {
    require(msg.sender == principal, "Not authorized");
    _;
}

function graduate() public reinitializer(2) onlyPrincipal {
    // upgrade-time logic here
}
```

Alternatively, consider making `graduate()` `internal` if it is only intended to be called within another controlled flow.

***

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Storage Collision in LevelTwo Due to Removed schoolFees Variable            



## Summary

The `LevelTwo` contract omits the `schoolFees` variable that exists in `LevelOne`, breaking the expected storage layout. Since Solidity stores state variables sequentially in storage slots, removing or reordering inherited variables in an upgradeable contract leads to **storage collisions**, where new variables overwrite existing data. This can cause unpredictable behavior, including fund misrouting, broken access control, or permanent data corruption.

***

## Vulnerability Details

```solidity
  // LevelOne layout
  address principal;          // slot 0
  bool inSession;             // slot 1
  uint256 schoolFees;         // slot 2
  IERC20 usdc;                // slot 3

  // LevelTwo layout (schoolFees missing!)
  address principal;          // slot 0
  bool inSession;             // slot 1
  // @audit-issue now incorrectly occupies slot 2
@> IERC20 usdc; 
```

### Issue Explanation

1. **Shared Storage via Proxy**
   Upgradeable contracts share one storage layout defined by the proxy. Changing that layout in newer implementations causes serious inconsistencies.

2. **Slot Misalignment**
   By removing `schoolFees`, the `usdc` variable is now occupying the original slot for `schoolFees`, and its expected value becomes corrupted.

3. **Downstream Corruption**
   Calls to `usdc.safeTransfer(...)` will likely fail, misroute tokens, or interact with an invalid address.

***

## Impact

* **Fund Corruption**: Transfers using `usdc` may go to unintended addresses due to corrupted address values.
* **Broken Logic**: Access control, balances, and other logic relying on overwritten slots will malfunction.
* **Irrecoverable State**: Once data is corrupted by a storage collision, it cannot be restored.

***

## Tools Used

* Manual Code Review

***

## Recommendations

To prevent storage collisions, preserve the exact variable layout from previous versions:

```solidity
// LevelTwo (corrected layout)
address principal;
bool inSession;
uint256 schoolFees; // @fix preserved from LevelOne
uint256 public immutable reviewTime = 1 weeks;
uint256 public sessionEnd;
uint256 public bursary;
uint256 public cutOffScore;
mapping(address => bool) public isTeacher;
mapping(address => bool) public isStudent;
mapping(address => uint256) public studentScore;
mapping(address => uint256) private reviewCount;
mapping(address => uint256) private lastReviewTime;
address[] listOfStudents;
address[] listOfTeachers;

uint256 public constant TEACHER_WAGE = 35;
uint256 public constant PRINCIPAL_WAGE = 5;
uint256 public constant PRECISION = 100;

IERC20 usdc;
```

If new variables are needed, **append them** after all existing ones.

***


# Low Risk Findings

## <a id='L-01'></a>L-01. Missing reviewCount Incrementation in LevelOne::giveReview            



## Summary

The `LevelOne::giveReview` function allows teachers to review students once per week, up to a maximum of 5 reviews per student. However, the function **never increments the** **`reviewCount`** **variable**, meaning the condition `reviewCount[_student] < 5` is always true. As a result, teachers can indefinitely lower a student’s score, bypassing intended review limits.

***

## Vulnerability Details

```solidity
// @audit-issue reviewCount is never incremented, so the limit check is ineffective
function giveReview(address _student, bool review) public onlyTeacher {
    if (!isStudent[_student]) {
        revert HH__StudentDoesNotExist();
    }
    require(reviewCount[_student] < 5, "Student review count exceeded!!!");
    require(block.timestamp >= lastReviewTime[_student] + reviewTime, "Reviews can only be given once per week");

    if (!review) {
        studentScore[_student] -= 10;
    }

    lastReviewTime[_student] = block.timestamp;

    emit ReviewGiven(_student, review, studentScore[_student]);
    // @> reviewCount[_student] is never incremented
}
```

### Issue Explanation

The function intends to limit reviews to five per student, but fails to enforce it due to missing state update:

1. **Bypass Review Cap**
   Teachers can continuously give negative reviews every week since `reviewCount[_student]` is never updated.

2. **Unbounded Score Reduction**
   A malicious teacher could reduce a student’s score to zero or below over time, preventing graduation or other benefits.

3. **Misleading Access Control**
   The presence of a cap (`< 5`) gives the illusion of protection, but is effectively non-functional.

***

## Impact

* **Academic Manipulation**: Teachers can unfairly target students, causing failure or disqualification.
* **Broken Business Logic**: Graduation criteria based on `studentScore` can be easily sabotaged.

***

## Tools Used

* Manual Code Review

***

## Recommendations

Increment `reviewCount[_student]` after a successful review to properly enforce the 5-review limit:

```solidity
function giveReview(address _student, bool review) public onlyTeacher {
    ...
    if (!review) {
        studentScore[_student] -= 10;
    }

    lastReviewTime[_student] = block.timestamp;
    reviewCount[_student] += 1; // @fix increment to enforce review cap

    emit ReviewGiven(_student, review, studentScore[_student]);
}
```

***

## <a id='L-02'></a>L-02. Permanent Session Lock from inSession Never Reset            



## Summary

The `LevelOne::startSession` function sets the `inSession` flag to `true` to indicate the start of a school term. However, **no function in either LevelOne or LevelTwo resets** **`inSession`** **to** **`false`**, even after graduation. As a result, once a session starts, the contract remains stuck in an "active session" state, permanently preventing future sessions or student enrollments.

***

## Vulnerability Details

```solidity
function startSession(uint256 _cutOffScore) public onlyPrincipal notYetInSession {
    sessionEnd = block.timestamp + 4 weeks;
    inSession = true;
    cutOffScore = _cutOffScore;

    emit SchoolInSession(block.timestamp, sessionEnd);
}

// @audit-issue `inSession` is never set back to false, locking the contract in a permanent session
// @> No logic in LevelOne or LevelTwo resets `inSession`
```

### Issue Explanation

1. **One-Way State Transition**
   Once `inSession` is set to `true`, it remains true indefinitely unless explicitly reset.

2. **No Session Reset Logic**
   Neither `graduateAndUpgrade` in LevelOne nor `graduate()` in LevelTwo resets this flag, leaving the contract stuck in "session in progress".

3. **Enrollment and Session Initiation Blocked**
   The `notYetInSession` modifier prevents `startSession` from being called again, blocking future school terms and new student enrollments.

***

## Impact

* **Denial of Functionality**: Only one session can ever occur.
* **Enrollment Frozen**: No new students can enroll in future terms.
* **Protocol Halt**: The core lifecycle of the school system is broken after a single use.

***

## Tools Used

* Manual Code Review

***

## Recommendations

### Option A – Reset `inSession` in `LevelTwo::graduate()`

If the graduation and reward logic is now handled in `LevelTwo`, the proper place to reset `inSession` is at the end of the `graduate()` function:

```solidity
function graduate() public reinitializer(2) onlyPrincipal {
    // Graduation logic with score filtering and fund distribution...

    inSession = false;      // @fix reset session status
    sessionEnd = 0;
    bursary = 0;            // optional: clear remaining funds if unused
}
```

### Option B – Reset `inSession` in `LevelOne::graduateAndUpgrade()`

If the graduation logic still resides in LevelOne, you can reset the session flag at the end of `graduateAndUpgrade`:

```solidity
function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {
    // Existing distribution and upgrade logic...

    bursary = 0;
    inSession = false; // @fix allow future sessions
}
```

### Option C – Add a Separate `endSession()` Admin Function

If you want to keep session control flexible, consider exposing a dedicated function:

```solidity
function endSession() public onlyPrincipal {
    require(inSession, "Session is not active");
    inSession = false;
    sessionEnd = block.timestamp;
}
```

***



