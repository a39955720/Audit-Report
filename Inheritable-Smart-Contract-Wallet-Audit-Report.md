# Inheritable Smart Contract Wallet - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Denial of Service (DoS) Risk Due to Long Beneficiary List in onlyBeneficiaryWithIsInherited Modifier](#H-01)
    - ### [H-02. Improper Beneficiary Removal Leaves Empty Slots in Array](#H-02)
    - ### [H-03. Incorrect Implementation of nonReentrant Modifier Due to Wrong Transient Storage Slot Usage](#H-03)
- ## Medium Risk Findings
    - ### [M-01. Arbitrary External Calls in contractInteractions Allow Potential Misuse and Security Risks](#M-01)
- ## Low Risk Findings
    - ### [L-01. Arbitrary ERC20 Withdrawal in withdrawInheritedFunds Function](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #35

### Dates: Mar 6th, 2025 - Mar 13th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-03-inheritable-smart-contract-wallet)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 3
- Medium: 1
- Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Denial of Service (DoS) Risk Due to Long Beneficiary List in onlyBeneficiaryWithIsInherited Modifier            



## Summary

The `InheritanceManager::onlyBeneficiaryWithIsInherited` modifier in the `InheritanceManager` contract iterates over the `beneficiaries` array using a `while` loop. If the number of beneficiaries is excessively large, the function execution may consume an excessive amount of gas, potentially exceeding the block gas limit. This could lead to a **denial of service (DoS) attack**, preventing beneficiaries from executing inheritance-related functions such as `appointTrustee` and `buyOutEstateNFT`.

***

## Vulnerability Details

```Solidity
modifier onlyBeneficiaryWithIsInherited() {
       uint256 i = 0;
       // @audit-issue Unbounded iteration over the `beneficiaries` array leads to high gas costs and potential DoS
    @> while (i < beneficiaries.length + 1) {
        if (msg.sender == beneficiaries[i] && isInherited) {
            break;
        }
        i++;
    }
    _;
}
```

### Issues Identified

1. Unbounded Iteration
   * The `while` loop iterates through **every** element in `beneficiaries`. If the array becomes too large, the gas cost for each function call using this modifier will scale linearly.
   * If `beneficiaries.length` becomes **too large**, execution will require more gas than the **block gas limit**, causing **permanent function failure**.

2. Denial of Service (DoS) Risk
   * If the number of beneficiaries is too high, **no function protected by this modifier will be executable** due to exceeding gas limits.
   * This can result in beneficiaries being **unable to withdraw inherited funds or perform essential operations**.

***

## Impact

🚨 **Critical Consequences**

* **Denial of Service (DoS)**: If the `beneficiaries` array grows too large, any function using `onlyBeneficiaryWithIsInherited` will require excessive gas to iterate through the list. This can cause the function execution to exceed the block gas limit, making it impossible for beneficiaries to invoke critical inheritance-related functions.

* **Locked Funds**: If protected functions such as `appointTrustee` and `buyOutEstateNFT` become uncallable due to gas exhaustion, beneficiaries may be unable to access or distribute inherited assets, effectively locking funds within the contract.

* **Inefficient Execution**: Every call to functions using this modifier will incur unnecessary gas costs as the loop iterates through all beneficiaries. This inefficiency could discourage users from interacting with the contract and increase transaction fees unnecessarily.

***

## Proof of Concept (PoC)

### PoC Explanation

### **PoC Explanation**

1. **Populate the Beneficiary List**
   * The test begins by adding **42,000 beneficiaries** to the contract using `addBeneficiery`.
   * This ensures that any function requiring iteration over the `beneficiaries` list will have **high gas consumption**.
   * Each beneficiary is assigned a unique address (`address(uint160(i + 1000))`).

2. **Simulate the Inheritance Activation**
   * The test **warps time forward by 90 days**, fulfilling the condition to mark the contract as "inherited."
   * A valid beneficiary (`address(1000)`) **calls** **`inherit()`**, setting `isInherited = true`.

3. **Trigger a Function with the DoS Risk**
   * Another beneficiary (`address(40000)`) attempts to call `appointTrustee`, which uses the `onlyBeneficiaryWithIsInherited` modifier.
   * Since there are **42,000 beneficiaries**, the modifier must iterate through the entire array to confirm the sender is in the list.
   * This results in **excessive gas consumption**, eventually leading to an **out-of-gas (OOG) error**.

4. **Expected Outcome**
   * The transaction should **fail** due to gas exhaustion when executing `appointTrustee()`.
   * The test uses `vm.expectRevert();` to ensure that the transaction **fails as expected**, confirming that functions with `onlyBeneficiaryWithIsInherited` become **unusable when too many beneficiaries exist**.
   * If the transaction unexpectedly succeeds, the test will fail, highlighting a potential gas efficiency issue.

```solidity
    function test_DOS_DueToLargeBeneficiaryList() public {
        for (uint256 i = 0; i < 42_000; i++) {
            vm.prank(owner);
            im.addBeneficiery(address(uint160(i + 1000)));
        }
        vm.warp(1 + 90 days);
        vm.prank(address(1000));
        im.inherit();
        address trusteeAddr = makeAddr("Trustee");
        vm.prank(address(40000));
        vm.expectRevert(); //Out of gas error
        im.appointTrustee(trusteeAddr);
    }
```

***

## Tools Used

* **Manual Review**
* **Foundry Unit Tests**

***

## Recommendations

Instead of looping through an array, use a `mapping(address => bool)` for **O(1) lookup time**:

```solidity
mapping(address => bool) public isBeneficiary;

modifier onlyBeneficiaryWithIsInherited() {
    require(isInherited, "Not inherited yet");
    require(isBeneficiary[msg.sender], "Not a beneficiary");
    _;
}

function addBeneficiery(address _beneficiary) external onlyOwner {
    require(!isBeneficiary[_beneficiary], "Already a beneficiary");
    isBeneficiary[_beneficiary] = true;
    beneficiaries.push(_beneficiary);
}
```

✔ **Reduces gas costs from O(n) to O(1).**\
✔ **Eliminates DoS risk from excessive iteration.**

***

## <a id='H-02'></a>H-02. Improper Beneficiary Removal Leaves Empty Slots in Array            



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

* Manual Code Review

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

## <a id='H-03'></a>H-03. Incorrect Implementation of nonReentrant Modifier Due to Wrong Transient Storage Slot Usage            



## Summary

The `InheritanceManager::nonReentrant` modifier in the `InheritanceManager` contract incorrectly uses transient storage (`tload(1)` instead of the correct slot `tload(0)`), effectively rendering the reentrancy protection ineffective. This implementation mistake breaks the core security assumption of functions protected by this modifier, potentially making them vulnerable to future reentrancy attacks if the functions become publicly callable or ownership is compromised.

***

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

***

## Impact

Currently, the functions protected by `nonReentrant` (`sendETH`, `sendERC20`, `contractInteractions`) have the `onlyOwner` access control modifier, significantly reducing immediate exploitability. Thus, the direct risk of reentrancy attacks by external attackers is currently minimal.

However, this incorrect modifier implementation significantly weakens the contract's security posture. If, in the future, developers introduce additional functionalities without strict access controls (for example, allowing beneficiaries or external parties to trigger token transfers or interactions), these functions would immediately become susceptible to severe reentrancy vulnerabilities, potentially leading to loss of user funds.

In short:

* **Indirect risk to user funds**: Funds could become at risk in the future.
* **Reduced security assurance**: The intended protection mechanism is entirely bypassed, providing no actual protection against reentrancy.
* **Potential future high-risk vulnerability**: Any later addition or changes could unknowingly introduce serious vulnerabilities due to the false sense of security provided by the incorrect modifier implementation.

***

## Tools Used

* Manual Code Review

***

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

***

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Arbitrary External Calls in contractInteractions Allow Potential Misuse and Security Risks            



## Summary

The `InheritanceManager::contractInteractions` function allows the contract owner to execute arbitrary external calls with any calldata and an optional ETH transfer. While the function is restricted to `onlyOwner`, this design introduces significant risks if the owner's private key is compromised or if the owner mistakenly interacts with a malicious contract.

This function effectively grants the owner **unrestricted execution power**, making it equivalent to an externally owned account (EOA) in terms of contract interaction. If misused or compromised, it could lead to **loss of funds, execution of unintended operations, or exposure to external contract vulnerabilities**.

***

## Vulnerability Details

```Solidity
function contractInteractions(address _target, bytes calldata _payload, uint256 _value, bool _storeTarget)
    external
    nonReentrant
    onlyOwner
{
    // @audit-issue Allows arbitrary contract calls, which may result in unintended interactions, loss of funds, or security vulnerabilities if the owner interacts with a malicious contract
 @> (bool success, bytes memory data) = _target.call{value: _value}(_payload);
    require(success, "interaction failed");
    if (_storeTarget) {
        interactions[_target] = data;
    }
}
```

### Issue Explanation

1. **Owner Key Compromise Could Lead to Total Loss of Funds**
   * Since `contractInteractions` allows **arbitrary calls**, if an attacker gains access to the owner's private key, they could call external contracts (e.g., swap all assets to another address or withdraw all ETH and tokens).
   * This effectively grants full control over the contract’s assets to whoever controls the owner key.

2. **No Whitelist or Safety Checks on** **`_target`**
   * The function does not restrict which contracts can be called. The owner could unknowingly interact with:
     * **Malicious smart contracts** that drain assets.
     * **Buggy or unverified contracts** that cause unexpected state changes.
     * **Blacklisted contracts** that could have compliance implications.

3. **Potential for Reentrancy and Unexpected Behavior**
   * Although `nonReentrant` is applied, if it is not correctly implemented, reentrancy may still be possible if a called contract has callbacks into this contract.
   * Even without reentrancy, calling unknown contracts introduces **execution risk**, such as failed transactions, state corruption, or infinite loops.

***

## Impact

1. **Potential Total Loss of Funds**
   * If the owner's private key is compromised, all contract assets could be drained via arbitrary calls.

2. **Unrestricted Execution Power Without Verification**
   * The owner may mistakenly interact with malicious or high-risk contracts.

3. **Risk of Contract Misbehavior**
   * External contract calls could result in unintended state changes or vulnerabilities being introduced in the future.

4. **Unnecessary Storage and Gas Costs**
   * Tracking every call through `_storeTarget` could increase contract storage overhead and operational costs.

***

## Tools Used

* Manual Review

***

## Recommendations

### Restrict Allowed Targets (`_target`)

Limit `contractInteractions` to interact only with **whitelisted contracts**.

```solidity
mapping(address => bool) public approvedContracts;

function setApprovedContract(address _contract, bool _status) external onlyOwner {
    approvedContracts[_contract] = _status;
}

function contractInteractions(address _target, bytes calldata _payload, uint256 _value, bool _storeTarget)
    external
    nonReentrant
    onlyOwner
{
    require(approvedContracts[_target], "Unauthorized target contract");
    (bool success, bytes memory data) = _target.call{value: _value}(_payload);
    require(success, "interaction failed");
    if (_storeTarget) {
        interactions[_target] = data;
    }
}
```

***


# Low Risk Findings

## <a id='L-01'></a>L-01. Arbitrary ERC20 Withdrawal in withdrawInheritedFunds Function            



## Summary

The `InheritanceManager::withdrawInheritedFunds` function allows beneficiaries to withdraw any ERC20 token held by the contract, without restricting which token may be withdrawn. This design permits the dispersion of any ERC20 token—including those not intended by the contract owner—to beneficiaries. Although the function includes a check to ensure that inheritance has been triggered (`isInherited`), it lacks any additional validation on the `_asset` parameter. This means that if any arbitrary ERC20 token is sent to the contract, beneficiaries can withdraw it, which may lead to unintended or malicious token interactions.

## Vulnerability Details

### Code Snippet

```Solidity
/**
 * @dev called by the beneficiaries to disperse remaining assets within the contract in equal parts.
 * @notice use address(0) to disperse ether
 * @param _asset asset address to disperse
 */
function withdrawInheritedFunds(address _asset) external {
    if (!isInherited) {
        revert NotYetInherited();
    }
    uint256 divisor = beneficiaries.length;
    if (_asset == address(0)) {
        uint256 ethAmountAvailable = address(this).balance;
        uint256 amountPerBeneficiary = ethAmountAvailable / divisor;
        for (uint256 i = 0; i < divisor; i++) {
            address payable beneficiary = payable(beneficiaries[i]);
            (bool success,) = beneficiary.call{value: amountPerBeneficiary}("");
            require(success, "something went wrong");
        }
    } else {
        uint256 assetAmountAvailable = IERC20(_asset).balanceOf(address(this));
        uint256 amountPerBeneficiary = assetAmountAvailable / divisor;
        for (uint256 i = 0; i < divisor; i++) {
        // @audit-issue No restriction on which ERC20 token can be withdrawn; any ERC20 token held by the contract can be dispersed
    @>  IERC20(_asset).safeTransfer(beneficiaries[i], amountPerBeneficiary);
        }
    }
}

```

### Issue Explanation

* **Lack of Token Restriction:**\
  The function does not limit the type of ERC20 token that can be withdrawn. Beneficiaries can call `withdrawInheritedFunds` with any ERC20 token address, meaning that if an unintended or malicious token is present in the contract, it will be automatically dispersed among the beneficiaries.
* **Impact on Fund Distribution:**\
  This unrestricted design could lead to scenarios where tokens not meant for inheritance (e.g., tokens sent by mistake or malicious tokens designed to exploit further logic in beneficiary contracts) are distributed, potentially causing confusion or loss of funds.
* **Potential for Malicious Exploitation:**\
  An attacker might deliberately send a malicious ERC20 token to the contract. Since the function will distribute any token passed as `_asset`, beneficiaries could end up receiving and interacting with harmful tokens without proper safeguards in place.

### Impact

* **Incorrect Asset Distribution:**\
  Funds may be dispersed in an unintended manner if arbitrary tokens are withdrawn, which could lead to financial losses or mismanagement of assets.
* **Security Risk Through Malicious Tokens:**\
  Beneficiaries may inadvertently interact with malicious tokens if such tokens are withdrawn from the contract, potentially exposing them to further exploits.
* **Operational Complexity:**\
  Without restrictions, the contract's inheritance mechanism may handle tokens that the owner did not intend to include, leading to additional complexity in managing and accounting for assets.

## Recommendations

**Implement a Whitelist for Allowed Tokens:**\
Introduce a mechanism to restrict withdrawals to a predefined list of approved ERC20 tokens. This ensures that only tokens intended for inheritance are subject to withdrawal.

```solidity
mapping(address => bool) public allowedTokens;

function setAllowedToken(address _token, bool _status) external onlyOwner {
    allowedTokens[_token] = _status;
}

function withdrawInheritedFunds(address _asset) external {
    if (!isInherited) {
        revert NotYetInherited();
    }
    if (_asset != address(0)) {
        require(allowedTokens[_asset], "Token not allowed");
    }

    uint256 divisor = beneficiaries.length;
    if (_asset == address(0)) {
        uint256 ethAmountAvailable = address(this).balance;
        uint256 amountPerBeneficiary = ethAmountAvailable / divisor;
        for (uint256 i = 0; i < divisor; i++) {
            address payable beneficiary = payable(beneficiaries[i]);
            (bool success,) = beneficiary.call{value: amountPerBeneficiary}("");
            require(success, "Transfer failed");
        }
    } else {
        uint256 assetAmountAvailable = IERC20(_asset).balanceOf(address(this));
        uint256 amountPerBeneficiary = assetAmountAvailable / divisor;
        for (uint256 i = 0; i < divisor; i++) {
            IERC20(_asset).safeTransfer(beneficiaries[i], amountPerBeneficiary);
        }
    }
}
```



