# Core Contracts - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Unauthorized Access in `updateUserBoost` Allows Manipulation of User Boost Data](#H-01)
- ## Medium Risk Findings
    - ### [M-01. Tax Calculation Logic Flaw Allows Total Tax Rate to Exceed Design Limit](#M-01)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: Regnum Aurum Acquisition Corp

### Dates: Feb 3rd, 2025 - Feb 24th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-02-raac)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 1
- Medium: 1
- Low: 0


# High Risk Findings

## <a id='H-01'></a>H-01. Unauthorized Access in `updateUserBoost` Allows Manipulation of User Boost Data            



## Summary

The `BoostController::updateUserBoost` function in the `BoostController` contract ([`contracts/core/governance/boost/BoostController.sol`](https://github.com/Cyfrin/2025-02-raac/blob/89ccb062e2b175374d40d824263a4c0b601bcb7f/contracts/core/governance/boost/BoostController.sol#L177)) **lacks proper access control**, allowing **any external caller** to update boost data for any user. This vulnerability enables malicious actors to **manipulate boost parameters**, potentially resulting in **unfair advantages** and **undermining the protocol's economic model**.

## Vulnerability Details

```solidity
// @audit-issue No access control, allowing unauthorized users to modify boost values
@> function updateUserBoost(address user, address pool) external override nonReentrant whenNotPaused {
    if (paused()) revert EmergencyPaused();
    if (user == address(0)) revert InvalidPool();
    if (!supportedPools[pool]) revert PoolNotSupported();
    
    UserBoost storage userBoost = userBoosts[user][pool];
    PoolBoost storage poolBoost = poolBoosts[pool];
    
    uint256 oldBoost = userBoost.amount;
    // Calculate new boost based on current veToken balance
    uint256 newBoost = _calculateBoost(user, pool, 10000); // Base amount
    
    userBoost.amount = newBoost;
    userBoost.lastUpdateTime = block.timestamp;
    
    // Update pool totals safely
    if (newBoost >= oldBoost) {
        poolBoost.totalBoost = poolBoost.totalBoost + (newBoost - oldBoost);
    } else {
        poolBoost.totalBoost = poolBoost.totalBoost - (oldBoost - newBoost);
    }
    poolBoost.workingSupply = newBoost; // Set working supply directly to new boost
    poolBoost.lastUpdateTime = block.timestamp;
    
    emit BoostUpdated(user, pool, newBoost);
    emit PoolBoostUpdated(pool, poolBoost.totalBoost, poolBoost.workingSupply);
}
```

* **Issue:**
  * The function is declared as `external`, meaning any account can call it.
  * There is no access control mechanism (e.g., `onlyRole(MANAGER_ROLE)` or `require(msg.sender == user)`).
  * As a result, an attacker can arbitrarily modify boost values for any user.

## Impact

* **Economic Manipulation:**
  * Attackers can artificially increase their boost or reduce others’ boost, skewing rewards distribution.
* **Unfair Advantage:**
  * Malicious actors may gain undue benefits in reward systems or influence governance outcomes.
* **Protocol Exploitation:**
  * Manipulated boost data could destabilize the protocol’s economic model, leading to financial loss for legitimate participants.

## Tools Used

* Manual Code Review

## Recommendations

* **Implement Role-Based Access Control:**
  * Add an access control modifier such as `onlyRole(MANAGER_ROLE)` to ensure that only authorized accounts can update boost data:
    ```solidity
    function updateUserBoost(address user, address pool) external override nonReentrant whenNotPaused onlyRole(MANAGER_ROLE) {
        // ... original logic ...
    }
    ```
* **Alternative Approach:**
  * If users should only update their own boost data, enforce a check to ensure that `msg.sender` is either the user or has the proper role:
    ```solidity
    function updateUserBoost(address user, address pool) external override nonReentrant whenNotPaused {
        require(msg.sender == user || hasRole(MANAGER_ROLE, msg.sender), "Unauthorized");
        // ... original logic ...
    }
    ```
* **Conduct Further Testing:**
  * Validate the fix with comprehensive unit tests and consider a formal audit to ensure no other functions are vulnerable to unauthorized modifications.

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Tax Calculation Logic Flaw Allows Total Tax Rate to Exceed Design Limit            



## Summary

The `RAACToken::_update` function in the `RAACToken` contract ([`contracts/core/tokens/RAACToken.sol`](https://github.com/Cyfrin/2025-02-raac/blob/89ccb062e2b175374d40d824263a4c0b601bcb7f/contracts/core/tokens/RAACToken.sol#L190)) computes a base tax in its `_update` function as the sum of `swapTaxRate` and `burnTaxRate` without enforcing that their combined value does not exceed the maximum allowable tax rate (`MAX_TAX_RATE` of 10%). As a result, multiple incremental updates can lead to an unintended total tax rate beyond the design limit.

## Vulnerability Details

```solidity
function _update(
    address from,
    address to,
    uint256 amount
) internal virtual override {
    // @audit-issue No check to ensure combined tax rate does not exceed MAX_TAX_RATE
    @> uint256 baseTax = swapTaxRate + burnTaxRate;

    // Skip tax for whitelisted addresses or when fee collector disabled
    if (baseTax == 0 || from == address(0) || to == address(0) || whitelistAddress[from] || whitelistAddress[to] || feeCollector == address(0)) {
        super._update(from, to, amount);
        return;
    }

    // All other cases where tax is applied
    uint256 totalTax = amount.percentMul(baseTax);
    uint256 burnAmount = totalTax * burnTaxRate / baseTax;
    
    super._update(from, feeCollector, totalTax - burnAmount);
    super._update(from, address(0), burnAmount);
    super._update(from, to, amount - totalTax);
}

```

* There is no check ensuring that `swapTaxRate + burnTaxRate` is ≤ `MAX_TAX_RATE`.
* Although each tax rate is individually capped (i.e., cannot exceed `MAX_TAX_RATE`), their sum can potentially exceed 10% if both are raised near the limit.
* This logic flaw could be exploited by the owner (or an attacker with minter privileges if compromised) to set tax rates that impose unexpectedly high fees on transfers.

## Impact

* **Excessive Fees:** Users may be charged higher-than-intended fees during token transfers.
* **Economic Distortion:** The token’s utility and market trust could be adversely affected due to unexpected token burns and fee deductions.
* **Potential Manipulation:** Over-taxation could disrupt token liquidity and market dynamics, leading to broader economic consequences for the token ecosystem.

## Tools Used

* Manual Code Review

## Recommendations

* **Enforce Combined Tax Cap:** In the `_setTaxRate` function, add a check to ensure that the new rate, when combined with the other tax rate, does not exceed `MAX_TAX_RATE`. For example:
  ```solidity
  function _setTaxRate(uint256 newRate, bool isSwapTax) private {
      if (newRate > MAX_TAX_RATE) revert TaxRateExceedsLimit();
      
      uint256 currentRate = isSwapTax ? swapTaxRate : burnTaxRate;

      if (currentRate != 0) {
          uint256 maxChange = currentRate.percentMul(taxRateIncrementLimit);
          bool isTooHighOrTooLow = newRate > currentRate + maxChange || 
                                     (newRate < currentRate && currentRate - newRate > maxChange);

          if (isTooHighOrTooLow) {
              revert TaxRateChangeExceedsAllowedIncrement();
          }
      }

      // New check for combined tax rate
      if (isSwapTax) {
          require(newRate + burnTaxRate <= MAX_TAX_RATE, "Combined tax rate exceeds maximum");
          swapTaxRate = newRate;
          emit SwapTaxRateUpdated(newRate);
      } else {
          require(swapTaxRate + newRate <= MAX_TAX_RATE, "Combined tax rate exceeds maximum");
          burnTaxRate = newRate;
          emit BurnTaxRateUpdated(newRate);
      }
  }
  ```
* **Audit All Tax-Related Logic:** Ensure that other parts of the contract dealing with tax calculations are similarly guarded against cumulative rate violations.
* **Consider Separate Limits:** If applicable, consider enforcing individual tax rate caps as well as a combined cap to maintain overall design integrity.





