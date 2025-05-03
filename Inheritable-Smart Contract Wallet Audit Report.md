# Inheritable Smart Contract Wallet - Findings Report

# Table of contents

- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
  - ### [H-01. Improper Beneficiary Removal Leaves Empty Slots in Array](#H-01)
  - ### [H-02. Incorrect Implementation of nonReentrant Modifier Due to Wrong Transient Storage Slot Usage](#H-02)

# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #35

### Dates: Mar 6th, 2025 - Mar 13th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-03-inheritable-smart-contract-wallet)

# <a id='results-summary'></a>Results Summary

### Number of findings:

- High: 2
- Medium: 0
- Low: 0

# High Risk Findings

## <a id='H-01'></a>H-01. Improper Beneficiary Removal Leaves Empty Slots in Array

## Summary

The `InheritanceManager::removeBeneficiary` function in `InheritanceManager` is intended to remove a specified beneficiary from the `beneficiaries` array. However, the implementation incorrectly uses `delete`, which only resets the value at the given index to `address(0)` without reducing the array length. This results in empty slots in the array, leading to incorrect beneficiary calculations, unnecessary gas consumption, and potential unintended behavior when iterating over the list.

## Vulnerability Details

```Solidity
function removeBeneficiary(address _beneficiary) external onlyOwner {
       // @audit-issue Using `delete` leaves an empty slot in the array, causing gas inefficiency and potential logic errors
       uint256 indexToRemove = _getBeneficiaryIndex(_beneficiary);
    @> delete beneficiaries[indexToRemove];
}
```

### Issue Explanation

When `delete beneficiaries[indexToRemove]` is executed, the element at that index is replaced with `address(0)`, but the overall length of the array remains unchanged. This creates an empty slot that still occupies space in storage, which can cause issues when iterating over `beneficiaries`.

Functions that rely on the correct number of beneficiaries, such as `withdrawInheritedFunds`, may incorrectly count `address(0)` as a valid entry, leading to incorrect fund distribution. Additionally, iterating over an array with empty slots increases gas costs, as unnecessary checks need to be performed to skip `address(0)`.

## Impact

The use of `delete` causes the array to retain an incorrect structure, leading to inefficient gas usage and potential miscalculations in fund distribution. If `withdrawInheritedFunds` splits funds equally among `beneficiaries.length`, empty slots could cause either an incorrect division of funds or failed transactions. The increased gas costs from iterating over a larger-than-necessary array further degrades the contract’s efficiency.

## Tools Used

- Manual Code Review

## Recommendations

Instead of using `delete`, which leaves gaps, the function should use the swap-and-pop method to efficiently remove the beneficiary while maintaining a contiguous array.

### **Fixed Code**

```solidity
function removeBeneficiary(address _beneficiary) external onlyOwner {
    uint256 indexToRemove = _getBeneficiaryIndex(_beneficiary);
    uint256 lastIndex = beneficiaries.length - 1;

    if (indexToRemove != lastIndex) {
        beneficiaries[indexToRemove] = beneficiaries[lastIndex]; // Move last element to removed index
    }

    beneficiaries.pop(); // Remove last element to shrink array
}
```

## <a id='H-02'></a>H-02. Incorrect Implementation of nonReentrant Modifier Due to Wrong Transient Storage Slot Usage

## Summary

The `InheritanceManager::nonReentrant` modifier in the `InheritanceManager` contract incorrectly uses transient storage (`tload(1)` instead of the correct slot `tload(0)`), effectively rendering the reentrancy protection ineffective. This implementation mistake breaks the core security assumption of functions protected by this modifier, potentially making them vulnerable to future reentrancy attacks if the functions become publicly callable or ownership is compromised.

---

## Vulnerability Details

```Solidity
modifier nonReentrant() {
    assembly {
        // @audit-issue Incorrect transient storage slot is checked here
    @>  if tload(1) { revert(0, 0) }
        tstore(0, 1)
    }
    _;
    assembly {
        tstore(0, 0)
    }
}

```

The above code mistakenly checks `tload(1)` while setting and clearing the transient storage in slot `0`. Because transient storage slot `1` is never written to, it always returns `0`, causing the condition to never revert and thus never protecting the contract from reentrancy attacks as intended.

---

## Impact

Currently, the functions protected by `nonReentrant` (`sendETH`, `sendERC20`, `contractInteractions`) have the `onlyOwner` access control modifier, significantly reducing immediate exploitability. Thus, the direct risk of reentrancy attacks by external attackers is currently minimal.

However, this incorrect modifier implementation significantly weakens the contract's security posture. If, in the future, developers introduce additional functionalities without strict access controls (for example, allowing beneficiaries or external parties to trigger token transfers or interactions), these functions would immediately become susceptible to severe reentrancy vulnerabilities, potentially leading to loss of user funds.

In short:

- **Indirect risk to user funds**: Funds could become at risk in the future.
- **Reduced security assurance**: The intended protection mechanism is entirely bypassed, providing no actual protection against reentrancy.
- **Potential future high-risk vulnerability**: Any later addition or changes could unknowingly introduce serious vulnerabilities due to the false sense of security provided by the incorrect modifier implementation.

---

## Tools Used

- Manual Code Review

---

## Recommendation

Immediately fix the implementation of `nonReentrant` by correctly referencing the transient storage slot `0`:

### Corrected Modifier Implementation

```Solidity
modifier nonReentrant() {
    assembly {
        if tload(0) { revert(0, 0) } //Correct transient storage slot
        tstore(0, 1)
    }
    _;
    assembly {
        tstore(0, 0)
    }
}

```

This correctly locks and unlocks the function execution within the same transaction, effectively preventing any form of reentrancy attack.

---
