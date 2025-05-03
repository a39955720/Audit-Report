# Rock Paper Scissors - Findings Report

# Table of contents

- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings

  - ### [H-01. Prize-Payment "Push" Pattern Enables Permanent DoS on Game Funds](#H-01)
  - ### [H-02. Stale revealDeadline Enables Premature Timeout and Game Exploitation](#H-02)

- ## Low Risk Findings
  - ### [L-01. Missing Initial Supply and Lack of Supply Cap](#L-01)
  - ### [L-02. Fee Calculation Truncates Remainder, Causing ETH Dust to Accumulate in Contract](#L-02)
  - ### [L-03. Unbounded Token Inflation via \_finishGame and \_handleTie](#L-03)
  - ### [L-04. Unchecked transferFrom Return Value in Token-Based Game Functions](#L-04)
  - ### [L-05. Unspecific and Unlocked Solidity Compiler Version Exposing Known Critical Bugs](#L-05)
  - ### [L-06. Magic Number Usage for Timeout Interval in createGameWithEth & createGameWithToken](#L-06)

# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #38

### Dates: Apr 17th, 2025 - Apr 24th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-04-rock-paper-scissors)

# <a id='results-summary'></a>Results Summary

### Number of findings:

- High: 2
- Medium: 0
- Low: 6

# High Risk Findings

## <a id='H-01'></a>H-01. Prize-Payment "Push" Pattern Enables Permanent DoS on Game Funds

## Summary

The `RockPaperScissors::_finishGame`, `RockPaperScissors::_handleTie`, and `RockPaperScissors::_cancelGame` functions in the `RockPaperScissors` contract use low-level `call{value: ...}("")` operations combined with `require(success, ...)` to distribute ETH prizes and refunds. If any recipient is a smart contract that rejects ETH transfers—by reverting in its `receive()` or `fallback()` function—these calls will fail. As a result, the entire function reverts, permanently preventing game finalization, refunds, or tie resolution. This creates a **denial-of-service (DoS)** vulnerability, where ETH becomes locked in the contract and core gameplay operations are halted.

---

## Vulnerability Details

The issue affects three critical internal functions:

```solidity
// _finishGame function

    // @audit-issue ETH transfer via low-level call; reverts if recipient rejects ETH
    @> (bool success,) = _winner.call{value: prize}("");
    require(success, "Transfer failed");


// _handleTie function

    // @audit-issue Direct ETH transfer to both players; reverts entire function if either rejects payment
    @> (bool successA,) = game.playerA.call{value: refundPerPlayer}("");
    @> (bool successB,) = game.playerB.call{value: refundPerPlayer}("");
    require(successA && successB, "Transfer failed");


// _cancelGame function

    // @audit-issue Refunds use call and require pattern; can be blocked if player contracts revert
    @> (bool successA,) = game.playerA.call{value: game.bet}("");
    require(successA, "Transfer to player A failed");

    if (game.playerB != address(0)) {
        @> (bool successB,) = game.playerB.call{value: game.bet}("");
        require(successB, "Transfer to player B failed");
    }

```

### Issues Identified

1. **Unprotected ETH Transfer**

   - The low-level `.call{value: ...}("")` pattern directly sends ETH without proper safeguards, leaving the contract vulnerable to reverts from malicious recipients.

2. **Hard Revert with** **`require(success, ...)`**

   - Each failed ETH transfer causes a hard revert, rolling back the entire function execution, making it impossible to continue or finish the current game action.

3. **Permanent Denial-of-Service (DoS)**

   - Malicious or improperly configured recipient contracts can intentionally or unintentionally lock ETH and permanently block game operations.

4. **Affected Critical Functions**
   - `_finishGame` distributes prizes to the winner, `_handleTie` refunds both players after a tie, and `_cancelGame` refunds players upon cancellation.
   - All become vulnerable to permanent DoS scenarios upon ETH transfer failure.

---

## Impact

**Critical Consequences**

- **Denial of Service (DoS)**: Malicious or faulty recipients permanently block prize distribution, refunds, or game cancellation, effectively freezing critical functions.
- **Locked Funds**: ETH becomes irretrievably locked within the contract, causing permanent loss of liquidity and undermining user confidence.
- **Game Logic Freezing**: Stalled games become permanently stuck in incomplete states (`Finished`, `Cancelled`), negatively impacting player experience and trust.
- **Admin Operations Blocked**: Inability to finalize games or issue refunds may negatively affect administrative operations and fee collections.

---

## Proof of Concept (PoC)

### PoC Explanation

1. **Deploy a malicious contract (`MaliciousReceiver`)** with a `receive()` function that deliberately reverts on receiving ETH.
2. **Player A creates a game** with an ETH bet, and the malicious contract joins the game.
3. Both parties commit and reveal moves, with the malicious player winning.
4. **During** **`_finishGame()`**, the prize transfer fails, causing a revert.
5. Similar reverts can also occur in `_handleTie` or `_cancelGame` scenarios when refunding malicious contracts.

```solidity
contract MaliciousReceiver {
    receive() external payable {
        revert("Reject ETH transfers");
    }
}

function testPrizePaymentDoS() public {
    MaliciousReceiver attacker = new MaliciousReceiver();
    vm.deal(address(attacker), 1 ether);
    vm.deal(playerA, 1 ether);

    // Player A creates a game
    vm.prank(playerA);
    uint256 gameId = game.createGameWithEth{value: 0.1 ether}(1, 5 minutes);

    // Malicious player joins
    vm.prank(address(attacker));
    game.joinGameWithEth{value: 0.1 ether}(gameId);

    // Both commit moves
    bytes32 saltA = keccak256("saltA");
    vm.prank(playerA);
    game.commitMove(gameId, keccak256(abi.encodePacked(uint8(1), saltA)));

    bytes32 saltB = keccak256("saltB");
    vm.prank(address(attacker));
    game.commitMove(gameId, keccak256(abi.encodePacked(uint8(2), saltB)));

    // Reveal moves and trigger revert due to malicious recipient
    vm.prank(playerA);
    game.revealMove(gameId, 1, saltA);

    vm.expectRevert("Transfer failed");
    vm.prank(address(attacker));
    game.revealMove(gameId, 2, saltB);
}
```

---

## Tools Used

- **Manual Code Review**
- **Foundry Unit Tests**

---

## Recommendations

**Refactor to Pull-Payment Pattern**:

Introduce a pull-payment approach where prize recipients or refund recipients explicitly withdraw funds. This avoids direct transfers, ensuring malicious or faulty recipients cannot trigger reverts.

### Recommended Pull-Payment Fix

Implement a withdraw function:

```solidity
mapping(address => uint256) public pendingWithdrawals;

function withdraw() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Withdraw failed");
}
```

Update affected functions to use this mapping:

```solidity
// Example fix for _finishGame()
if (game.bet > 0) {
    uint256 totalPot = game.bet * 2;
    uint256 fee = (totalPot * PROTOCOL_FEE_PERCENT) / 100;
    uint256 prize = totalPot - fee;
    accumulatedFees += fee;

    pendingWithdrawals[_winner] += prize; // No direct transfer here
    emit FeeCollected(_gameId, fee);
}

// Example fix for _handleTie()
pendingWithdrawals[game.playerA] += refundPerPlayer;
pendingWithdrawals[game.playerB] += refundPerPlayer;

// Example fix for _cancelGame()
pendingWithdrawals[game.playerA] += game.bet;
if (game.playerB != address(0)) {
    pendingWithdrawals[game.playerB] += game.bet;
}
```

This recommended approach completely mitigates the DoS attack vector by deferring ETH transfers to user-initiated withdrawals.

---

## <a id='H-02'></a>H-02. Stale revealDeadline Enables Premature Timeout and Game Exploitation

## Summary

The `RockPaperScissors::_determineWinner` function handles the conclusion of each turn and resets key state variables for the next round. However, it fails to clear or reset the `revealDeadline` field between turns. As a result, a stale `revealDeadline` from a previous round may incorrectly trigger timeouts in future rounds, leading to unintended game cancellations or premature wins.

---

## Vulnerability Details

```solidity
function _determineWinner(uint256 _gameId) internal {
    ...
    if (game.currentTurn < game.totalTurns) {
        game.currentTurn++;
        game.commitA = bytes32(0);
        game.commitB = bytes32(0);
        game.moveA = Move.None;
        game.moveB = Move.None;
        game.state = GameState.Committed;
        // @audit-issue revealDeadline is not cleared or updated for the new turn
        @> // game.revealDeadline remains from previous round
    }
    ...
}
```

### Issue Explanation

The `revealDeadline` is set only after both players commit moves, but **never cleared between rounds**:

1. **Stale Deadline Persists**\
   If a round ends just before the deadline, the next round starts with a leftover `revealDeadline` that may soon expire.

2. **Incorrect Timeout Claims**\
   A malicious player could wait for the new round to begin, then immediately call `timeoutReveal()` using the expired `revealDeadline`, wrongly forcing a win or a refund.

3. **State Corruption Risk**\
   Downstream logic that depends on `revealDeadline` being valid for the current round may behave unpredictably if it's stale.

---

## Impact

- **Game Manipulation**: Players can exploit stale deadlines to claim unfair wins.
- **Denial of Service**: Honest players may find their games cancelled or forfeited without fault.
- **Loss of Trust**: Users may abandon the game if outcomes appear inconsistent or unfair.

---

## Tools Used

- Manual Code Review

---

## Recommendations

Reset `revealDeadline` to `0` at the start of every new round in `_determineWinner`, to prevent stale values from being reused:

```solidity
if (game.currentTurn < game.totalTurns) {
    game.currentTurn++;
    game.commitA = bytes32(0);
    game.commitB = bytes32(0);
    game.moveA = Move.None;
    game.moveB = Move.None;
    game.revealDeadline = 0; // @fix Reset deadline between turns
    game.state = GameState.Committed;
}
```

---

# Low Risk Findings

## <a id='L-01'></a>L-01. Missing Initial Supply and Lack of Supply Cap

## Summary

The `WinningToken` contract does not mint any initial token supply at deployment and lacks a maximum supply cap. While the `mint()` function is restricted to the contract owner, this design introduces potential operational pitfalls and economic risks. The absence of a maximum supply constraint allows for indefinite minting, which may undermine user trust, compromise tokenomics, and increase the likelihood of accidental or malicious over-minting.

---

## Vulnerability Details

```solidity
constructor() ERC20("Rock Paper Scissors Winner Token", "RPSW") Ownable(msg.sender) {
    // @audit-issue No initial supply minted at deployment — this requires additional post-deployment action and may lead to inconsistent environments
    @> // No initial supply
}

function mint(address to, uint256 amount) external onlyOwner {
    // @audit-issue Missing supply cap allows unlimited minting, leading to potential abuse or unintentional inflation
    @> _mint(to, amount);
}
```

### Issue Explanation

There are **two major issues** with the current design:

1. **No Initial Supply Minted at Deployment**\
   The constructor lacks logic to mint tokens, requiring a manual `mint()` call post-deployment. If omitted, this could cause dependent contracts or frontends to break due to a zero `totalSupply()`. It also introduces inconsistency in automated deployments and testnets.

2. **No Maximum Supply Cap Defined**\
   The `mint()` function allows unbounded minting. Without a hard cap, the total supply can grow indefinitely, which:
   - Undermines the economic model of the token
   - Breaks trust in the scarcity and value of the token
   - Introduces risks if the owner key is compromised or misused

---

## Impact

- **Loss of Trust**: Users and integrators cannot be assured of token scarcity or supply integrity.
- **Tokenomics Breakdown**: Without a hard cap, it's impossible to define a predictable economic model.
- **Potential Over-Minting**: Future developers or compromised owners could mint excessive tokens, leading to dilution or economic collapse of the token system.

---

## Tools Used

- Manual Code Review

---

## Recommendations

To resolve both issues and ensure robustness:

1. **Define a constant** **`MAX_SUPPLY`** to restrict total mintable tokens.
2. **Enforce the supply cap within** **`mint()`**.
3. **Optionally mint an initial supply** in the constructor for immediate utility.

```solidity
uint256 public immutable maxSupply;

constructor(uint256 _maxSupply) ERC20("Rock Paper Scissors Winner Token", "RPSW") Ownable(msg.sender) {
    maxSupply = _maxSupply;
}

function mint(address to, uint256 amount) external onlyOwner {
    require(totalSupply() + amount <= maxSupply, "Max supply exceeded");
    _mint(to, amount);
}
```

---

## <a id='L-02'></a>L-02. Fee Calculation Truncates Remainder, Causing ETH Dust to Accumulate in Contract

## Summary

The `RockPaperScissors::_finishGame` and `_handleTie` functions calculate the protocol fee using Solidity's integer division. If the `totalPot` is not perfectly divisible by 100, the remainder will be silently discarded. This leads to **unclaimable "dust" ETH** that stays permanently locked in the contract and causes accounting discrepancies. Over time, this could accumulate to a noticeable amount, especially as the number of games increases.

---

## Vulnerability Details

```solidity
// Inside _finishGame and _handleTie
uint256 totalPot = game.bet * 2;
// @audit-issue Integer division truncates remainder, leading to dust ETH locked in contract
@> uint256 fee = (totalPot * PROTOCOL_FEE_PERCENT) / 100;
uint256 prize = totalPot - fee;
```

### Issues Identified

1. **Integer Truncation**

   - Solidity truncates results when performing division with integers.
   - For example, `3 * 10 / 100 = 0` when ideally you want 0.3 → 1 wei or round up.

2. **Locked ETH (Dust)**

   - Any leftover remainder from the division will not be included in either `fee` or `prize`.
   - This remainder becomes permanently **trapped** in the contract.

3. **Accounting Discrepancy**
   - `accumulatedFees` only tracks the truncated fee, but `address(this).balance` will include the leftover.
   - This mismatch can create confusion during audits or when calculating withdrawable fees.

---

## Impact

- **Lost Funds**: Small ETH amounts will be **unrecoverable**, especially impactful over many games.
- **Balance Mismatch**: The tracked `accumulatedFees` will **not match** the actual contract balance.
- **User Trust Impact**: Players may be concerned about **unexplained leftover balances**.

---

## Proof of Concept (PoC)

### PoC Explanation

This test creates a game where the total pot is **not divisible by 100**, ensuring a truncated remainder. The PoC confirms that `fee < ceil(fee)`, proving dust is created.

```solidity
function test_PoC_DustFee_Truncation() public {
    // Choose a bet amount that causes fee truncation
    uint256 dustBet = 1510000000000001; // 0.01510000000000001 ether
    uint256 totalPot = dustBet * 2;     // 0.03020000000000002 ether

    uint256 actualFee = (totalPot * game.PROTOCOL_FEE_PERCENT()) / 100;
    uint256 ceilFee = (totalPot * game.PROTOCOL_FEE_PERCENT() + 99) / 100;

    console.log("Dust fee: %s", actualFee);
    console.log("Ceil fee: %s", ceilFee);
    assertTrue(actualFee < ceilFee, "Expected fee to be truncated and produce dust");
}
```

### Expected Output

```Solidity
Dust fee: 3020000000000000
Ceil fee: 3020000000000001
```

This confirms a **1 wei discrepancy**, which will remain locked in the contract and **unaccounted for in accumulatedFees**.

---

## Tools Used

- **Manual Review**
- **Foundry Unit Test**

---

## Recommendations

1. **Use Safe Rounding Up**\
   Prevent truncation using:

   ```solidity
   uint256 fee = (totalPot * PROTOCOL_FEE_PERCENT + 99) / 100;
   ```

2. **Use Subtractive Fee Calculation**

   ```solidity
   uint256 prize = totalPot * 90 / 100;
   uint256 fee = totalPot - prize;
   ```

3. **Add Dust Recovery (Optional)**\
   Let admin recover any excess ETH not tracked in `accumulatedFees`.

   ```solidity
   function recoverDust() external onlyAdmin {
       uint256 dust = address(this).balance - accumulatedFees;
       require(dust > 0, "No dust");
       (bool success,) = adminAddress.call{value: dust}("");
       require(success, "Recover failed");
   }
   ```

---

## <a id='L-03'></a>L-03. Unbounded Token Inflation via \_finishGame and \_handleTie

## Summary

The `RockPaperScissors::_finishGame` and `RockPaperScissors::_handleTie` functions in token-based games **mint new** **`WinningToken`** **tokens as rewards or refunds**, but **do not return or burn** the tokens that were originally staked via `transferFrom`.

This leads to two critical issues:

- **Permanent lock of staked tokens** inside the contract.
- **Unbounded inflation** of the token supply due to redundant minting.

As players can repeatedly create and win or tie games, they can **farm tokens** without real economic input, severely diluting the value of `WinningToken`.

---

## Vulnerability Details

```solidity
// RockPaperScissors::_createGameWithToken and joinGameWithToken
// @audit-issue Staked tokens are transferred to the contract but never returned or burned
@> winningToken.transferFrom(msg.sender, address(this), 1);

// RockPaperScissors::_finishGame
if (game.bet == 0) {
    // @audit-issue Mints 2 new tokens even though 2 are already locked inside the contract
    @> winningToken.mint(_winner, 2);
}

// RockPaperScissors::_handleTie
if (game.bet == 0) {
    // @audit-issue Mints new tokens instead of returning or burning the staked tokens
    @> winningToken.mint(game.playerA, 1);
    @> winningToken.mint(game.playerB, 1);
}
```

### Issues Identified

1. **Permanent Token Lock**

   - Players’ staked tokens (2 per game) are transferred into the contract and never returned or burned.

2. **Unbounded Token Inflation & Value Dilution**
   - Every token‑based game outcome mints new tokens without reusing stakes.
   - Circulating supply grows uncontrollably, diluting the token’s economic value and breaking scarcity.

---

## Impact

- **Total supply grows linearly** with gameplay volume.
- **Staked tokens are stuck forever**, clogging contract state.
- **WinningToken's economic model becomes meaningless**, breaking trust and reducing incentive integrity.

---

## Proof of Concept (PoC)

### PoC Explanation

This PoC simulates **five 1-turn token-based games** where Player A always wins. Each time:

- Player A and Player B each stake 1 `WinningToken` via `transferFrom`.
- The contract mints 2 new tokens to Player A upon winning (`_finishGame`).
- The 2 staked tokens remain locked in the contract and are never returned or burned.

After 5 rounds:

- Player A gains **5 net tokens**.
- The contract holds **10 permanently locked tokens**.
- The total token supply increases by **10** (5 rounds × 2 minted).

This confirms the vulnerability: **token inflation** and **unrecoverable stake lock**.

```Solidity
function test_TokenInflationByWinLoop() public {
    uint256 initialPlayerBalance = token.balanceOf(playerA);
    uint256 initialTotalSupply   = token.totalSupply();

    for (uint256 i = 0; i < 5; i++) {
        // Create and join token-based game
        vm.startPrank(playerA);
        token.approve(address(game), 1);
        uint256 id = game.createGameWithToken(1, TIMEOUT);
        vm.stopPrank();

        vm.startPrank(playerB);
        token.approve(address(game), 1);
        game.joinGameWithToken(id);
        vm.stopPrank();

        // Player A always wins (Paper vs Rock)
        bytes32 saltA = keccak256(abi.encodePacked("A", i));
        bytes32 commitA = keccak256(abi.encodePacked(uint8(RockPaperScissors.Move.Paper), saltA));
        vm.prank(playerA); game.commitMove(id, commitA);

        bytes32 saltB = keccak256(abi.encodePacked("B", i));
        bytes32 commitB = keccak256(abi.encodePacked(uint8(RockPaperScissors.Move.Rock), saltB));
        vm.prank(playerB); game.commitMove(id, commitB);

        vm.prank(playerA); game.revealMove(id, uint8(RockPaperScissors.Move.Paper), saltA);
        vm.prank(playerB); game.revealMove(id, uint8(RockPaperScissors.Move.Rock), saltB);
    }

    assertEq(token.balanceOf(playerA), initialPlayerBalance + 5);
    assertEq(token.balanceOf(address(game)), 10);
    assertEq(token.totalSupply(), initialTotalSupply + 10);
}
```

---

## Tools Used

- Manual Review
- Foundry Unit Testing

---

## Recommendations

1. **Return Deposited Tokens Instead of Minting**

   ```solidity
   // In _finishGame
   winningToken.transfer(_winner, 2);
   // In _handleTie
   winningToken.transfer(game.playerA, 1);
   winningToken.transfer(game.playerB, 1);
   ```

2. **Burn Deposits Before Minting (if return is not feasible)**
   ```solidity
   winningToken.burn(2);
   winningToken.mint(_winner, 2);
   ```

---

## <a id='L-04'></a>L-04. Unchecked transferFrom Return Value in Token-Based Game Functions

## Summary

The `transferFrom` calls in `RockPaperScissors::createGameWithToken` and `RockPaperScissors::joinGameWithToken` interact with the external `WinningToken` contract without verifying the returned boolean value. This is a violation of the ERC20 standard introduced in [EIP-20](https://eips.ethereum.org/EIPS/eip-20), where `transferFrom` should return `true` on success. Ignoring this return value opens the contract to logic inconsistencies, where the function continues execution even if the token transfer fails.

---

## Vulnerability Details

```solidity
function createGameWithToken(...) external returns (uint256) {
    ...
    // @audit-issue Unchecked return value from transferFrom
    @> winningToken.transferFrom(msg.sender, address(this), 1);
    ...
}

function joinGameWithToken(...) external {
    ...
    // @audit-issue Unchecked return value from transferFrom
    @> winningToken.transferFrom(msg.sender, address(this), 1);
    ...
}
```

### Issue Explanation

1. **ERC20** **`transferFrom`** **Returns a Boolean**\
   Per the standard, `transferFrom` returns a `bool` indicating success or failure. However, both functions above fail to check this return value.

2. **Token Transfer Can Fail Silently**\
   If `transferFrom` fails—due to insufficient allowance, paused token, or transfer restrictions—the function proceeds as if the transfer succeeded. This leads to:

   - Invalid game state where a user appears to have paid but hasn’t
   - Game logic continuing with mismatched stakes
   - Potential denial of service in future rounds

3. **Violates Checks-Effects-Interactions Pattern**\
   External calls should not be trusted blindly. Not checking the return value makes the function vulnerable to subtle failures or malicious token behavior.

---

## Impact

- **Logic Inconsistency**: Games can be created or joined without actual token transfer, breaking fairness.
- **Silent Failure**: Users may believe they’ve successfully entered a game when they haven’t.
- **Denial of Service**: Malicious tokens that always return `false` can disrupt the platform’s flow.
- **Potential Exploit Path**: If any game flow depends on token stake but doesn’t confirm its presence, the system becomes exploitable.

---

## Tools Used

- Slither&#x20;
- Manual Review

---

## Recommendations

Always check the return value of `transferFrom`. Either use a `require` statement or import `SafeERC20` from OpenZeppelin.

### Option 1: Manual Check

```solidity
require(
    winningToken.transferFrom(msg.sender, address(this), 1),
    "Token transfer failed"
);
```

### Option 2: SafeERC20 Library

```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

// Then call:
winningToken.safeTransferFrom(msg.sender, address(this), 1);
```

This ensures that if the token transfer fails for any reason, the function will revert and prevent any further incorrect state changes.

---

## <a id='L-05'></a>L-05. Unspecific and Unlocked Solidity Compiler Version Exposing Known Critical Bugs

## Summary

The `RockPaperScissors` and `WinningToken` contracts specify the Solidity version as `^0.8.13`, which includes known **compiler-level bugs** affecting program behavior and security. While these issues may not manifest immediately, they introduce subtle risks—especially in contracts involving Ether transfers, low-level calls, or complex storage manipulations. Failing to upgrade may leave the contract vulnerable to edge-case bugs that have since been patched in later versions of Solidity.

Additionally, **using a caret (`^`) version specifier** can result in compiling against unintended future versions. This undermines audit guarantees, since contract behavior may subtly change with compiler upgrades.

---

## Vulnerability Details

```solidity
// SPDX-License-Identifier: MIT
// @audit-issue Solidity version ^0.8.13 contains known critical bugs
@> pragma solidity ^0.8.13;
```

### Issue Explanation

Using `^0.8.13` introduces exposure to the following **known bugs**:

- VerbatimInvalidDeduplication
- FullInlinerNonExpressionSplitArgumentEvaluationOrder
- MissingSideEffectsOnSelectorAccess
- StorageWriteRemovalBeforeConditionalTermination
- AbiReencodingHeadOverflowWithStaticArrayCleanup
- DirtyBytesArrayToStorage
- InlineAssemblyMemorySideEffects
- DataLocationChangeInInternalOverride
- NestedCalldataArrayAbiReencodingSizeValidation

These bugs are documented on the [Solidity GitHub Bug Tracker](https://github.com/ethereum/solidity/blob/develop/docs/bugs.json).

Additionally, the caret specifier `^` allows any compiler version up to (but not including) 0.9.0, which may introduce breaking changes in newer compiler versions outside of the developer’s control.

---

## Impact

- **Silent Logic Errors**: State updates or function behavior may silently fail without reverting.
- **Compiler-Induced Bugs**: Contracts may behave differently on different compiler versions despite identical code.
- **Long-Term Incompatibility**: Future toolchains, verifiers, or auditors may reject outdated or imprecisely-versioned compiler targets.
- **Undermines Audit Integrity**: Audits lose their validity if contracts are later compiled under different versions than originally audited.

---

## Tools Used

- Slither
- Aderyn

---

## Recommendations

Upgrade all contracts to a **patched and stable version** of Solidity (e.g., `0.8.24`) and explicitly lock the compiler version using an **exact match**, not a caret:

```solidity
// Recommended safe compiler version (locked)
pragma solidity 0.8.24;
```

After updating, recompile and re-audit the contracts to ensure no new warnings, incompatibilities, or unexpected behavior are introduced by the upgraded compiler version.

---

## <a id='L-06'></a>L-06. Magic Number Usage for Timeout Interval in createGameWithEth & createGameWithToken

## Summary

The `RockPaperScissors::createGameWithEth` and `RockPaperScissors::createGameWithToken` functions use a hardcoded value of `5 minutes` to enforce a minimum `_timeoutInterval`. While functionally correct, this constitutes a **magic number**, which harms readability and maintainability. Replacing this literal with a named constant improves clarity and supports easier refactoring.

---

## Vulnerability Details

```solidity
function createGameWithEth(uint256 _totalTurns, uint256 _timeoutInterval) external payable returns (uint256) {
    ...
    // @audit-issue Magic number usage for timeout interval
    @> require(_timeoutInterval >= 5 minutes, "Timeout must be at least 5 minutes");
    ...
}
```

```solidity
function createGameWithToken(uint256 _totalTurns, uint256 _timeoutInterval) external returns (uint256) {
    ...
    // @audit-issue Magic number usage for timeout interval
    @> require(_timeoutInterval >= 5 minutes, "Timeout must be at least 5 minutes");
    ...
}
```

### Issue Explanation

The direct use of `5 minutes` in both functions introduces the following problems:

1. **Reduced Readability**\
   The intent of the number is not obvious without additional context. A named constant like `MIN_TIMEOUT_INTERVAL` makes the purpose explicit.

2. **Harder to Modify**\
   Updating the minimum timeout value later requires searching for and replacing all literal values, which is error-prone.

3. **Consistency Risk**\
   Different developers may introduce slightly different timeout logic (e.g., `4 minutes`, `6 minutes`) without realizing the intended global standard.

---

## Impact

- **Developer Confusion**: Code is harder to interpret at a glance.
- **Maintainability Issues**: Future changes to timeout logic are more difficult and error-prone.
- **Code Duplication Risk**: Inconsistencies may arise in other parts of the codebase.

---

## Tools Used

- Aderyn

---

## Recommendations

Introduce a descriptive constant to replace the `5 minutes` literal:

```solidity
uint256 public constant MIN_TIMEOUT_INTERVAL = 5 minutes;
```

Then update the relevant code:

```solidity
require(_timeoutInterval >= MIN_TIMEOUT_INTERVAL, "Timeout must be at least 5 minutes");
```

This makes the code more readable, configurable, and less prone to errors.

---
