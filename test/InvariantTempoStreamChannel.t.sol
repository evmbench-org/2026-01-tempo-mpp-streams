// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/TempoStreamChannel.sol";

contract MockTIP20 is ERC20 {
    constructor() ERC20("Mock TIP-20 USD", "mUSD") {
        _mint(msg.sender, 1000000e6);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract ChannelHandler is Test {
    TempoStreamChannel public channel;
    MockTIP20 public token;
    bytes32 public channelId;
    address public payer;
    address public payee;
    uint256 public signerPrivateKey;
    uint256 public lastNonce;

    constructor(
        TempoStreamChannel _channel,
        MockTIP20 _token,
        bytes32 _channelId,
        address _payer,
        address _payee,
        uint256 _signerPrivateKey
    ) {
        channel = _channel;
        token = _token;
        channelId = _channelId;
        payer = _payer;
        payee = _payee;
        signerPrivateKey = _signerPrivateKey;
    }

    function addDeposit(uint256 amount) external {
        uint256 balance = token.balanceOf(payer);
        if (balance == 0) return;

        uint256 bounded = bound(amount, 1, balance);
        vm.prank(payer);
        channel.addDeposit(channelId, bounded);
    }

    function settle(uint256 addAmount) external {
        (, , , , uint256 deposit, uint256 settled, , bool finalized) = channel
            .channels(channelId);
        if (finalized) return;
        if (deposit <= settled) return;

        uint256 available = deposit - settled;
        uint256 delta = bound(addAmount, 1, available);
        uint256 nextCumulative = settled + delta;
        uint256 nextNonce = lastNonce + 1;

        TempoStreamChannel.Voucher memory voucher = TempoStreamChannel.Voucher({
            channelId: channelId,
            cumulativeAmount: nextCumulative,
            nonce: nextNonce,
            expiry: block.timestamp + 30 days
        });

        bytes memory sig = _signVoucher(voucher);
        channel.settle(voucher, sig);
        lastNonce = nextNonce;
    }

    function _signVoucher(
        TempoStreamChannel.Voucher memory voucher
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                channel.VOUCHER_TYPEHASH(),
                voucher.channelId,
                voucher.cumulativeAmount,
                voucher.nonce,
                voucher.expiry
            )
        );

        bytes32 domainSeparator = channel.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}

contract TempoStreamChannelInvariantTest is StdInvariant, Test {
    TempoStreamChannel public channel;
    MockTIP20 public token;
    ChannelHandler public handler;

    address public payer;
    address public payee;
    address public signer;
    uint256 public signerPrivateKey;
    bytes32 public channelId;

    uint256 public constant INITIAL_DEPOSIT = 10000e6;
    uint256 public constant INITIAL_MINT = 50000e6;

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);

        payer = makeAddr("payer");
        payee = makeAddr("payee");

        channel = new TempoStreamChannel();
        token = new MockTIP20();

        token.mint(payer, INITIAL_MINT);
        vm.prank(payer);
        token.approve(address(channel), type(uint256).max);

        vm.prank(payer);
        channelId = channel.openChannel(
            payee,
            IERC20(address(token)),
            INITIAL_DEPOSIT,
            signer,
            block.timestamp + 1 days
        );

        handler = new ChannelHandler(
            channel,
            token,
            channelId,
            payer,
            payee,
            signerPrivateKey
        );

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ChannelHandler.addDeposit.selector;
        selectors[1] = ChannelHandler.settle.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
        targetContract(address(handler));
    }

    function invariant_DepositAlwaysGteSettled() public {
        (, , , , uint256 deposit, uint256 settled, , ) = channel.channels(
            channelId
        );
        assertGe(deposit, settled, "Deposit must cover settled amount");
    }

    function invariant_ContractBalanceMatchesOutstanding() public {
        (, , , , uint256 deposit, uint256 settled, , ) = channel.channels(
            channelId
        );
        uint256 expected = deposit - settled;
        assertEq(
            token.balanceOf(address(channel)),
            expected,
            "Contract balance must equal outstanding deposit"
        );
    }

    function invariant_SettledNonceMonotonic() public {
        uint256 storedNonce = channel.settledNonces(channelId);
        assertEq(
            storedNonce,
            handler.lastNonce(),
            "Stored nonce must track latest settlement"
        );
    }
}

