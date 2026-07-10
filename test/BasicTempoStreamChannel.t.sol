// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/TempoStreamChannel.sol";

contract MockTIP20Basic is ERC20 {
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

contract BasicTempoStreamChannelTest is Test {
    TempoStreamChannel public channel;
    MockTIP20Basic public token;

    address public payer;
    address public payee;
    uint256 public payerPrivateKey;
    uint256 public signerPrivateKey;
    address public signer;

    uint256 public constant DEPOSIT_AMOUNT = 10000e6;

    function setUp() public {
        payerPrivateKey = 0xBEEF;
        payer = vm.addr(payerPrivateKey);
        payee = makeAddr("payee");
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);

        channel = new TempoStreamChannel();
        token = new MockTIP20Basic();

        token.mint(payer, DEPOSIT_AMOUNT * 2);

        vm.prank(payer);
        token.approve(address(channel), type(uint256).max);
    }

    function testOpenAndAddDeposit() public {
        vm.prank(payer);
        bytes32 channelId = channel.openChannel(
            payee,
            IERC20(address(token)),
            DEPOSIT_AMOUNT,
            signer,
            block.timestamp + 1 hours
        );

        uint256 contractBalance = token.balanceOf(address(channel));
        assertEq(contractBalance, DEPOSIT_AMOUNT, "Deposit should be escrowed");

        vm.prank(payer);
        channel.addDeposit(channelId, 500e6);

        (, , , , uint256 deposit, , , ) = channel.channels(channelId);
        assertEq(deposit, DEPOSIT_AMOUNT + 500e6, "Deposit should increase");
    }

    function testSettleVoucherUpdatesBalances() public {
        vm.prank(payer);
        bytes32 channelId = channel.openChannel(
            payee,
            IERC20(address(token)),
            DEPOSIT_AMOUNT,
            signer,
            block.timestamp + 1 hours
        );

        TempoStreamChannel.Voucher memory voucher = TempoStreamChannel.Voucher({
            channelId: channelId,
            cumulativeAmount: 2500e6,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });

        bytes memory sig = signVoucher(voucher);

        uint256 payeeBefore = token.balanceOf(payee);
        channel.settle(voucher, sig);

        uint256 payeeAfter = token.balanceOf(payee);
        assertEq(payeeAfter - payeeBefore, 2500e6, "Payee paid by voucher");

        (, , , , , uint256 settled, , ) = channel.channels(channelId);
        assertEq(settled, 2500e6, "Settled should track cumulative amount");
    }

    function testInitiateCloseAndFinalizeRefundsPayer() public {
        vm.prank(payer);
        bytes32 channelId = channel.openChannel(
            payee,
            IERC20(address(token)),
            DEPOSIT_AMOUNT,
            signer,
            block.timestamp + 1 hours
        );

        TempoStreamChannel.Voucher memory voucher = TempoStreamChannel.Voucher({
            channelId: channelId,
            cumulativeAmount: 4000e6,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });
        bytes memory sig = signVoucher(voucher);
        channel.settle(voucher, sig);

        vm.prank(payer);
        channel.initiateClose(channelId);

        vm.warp(block.timestamp + channel.GRACE_PERIOD() + 1);

        uint256 payerBefore = token.balanceOf(payer);
        channel.finalize(channelId);

        uint256 payerAfter = token.balanceOf(payer);
        assertEq(
            payerAfter - payerBefore,
            DEPOSIT_AMOUNT - 4000e6,
            "Payer receives remaining refund"
        );
    }

    function testCooperativeCloseFinalizesAndRefunds() public {
        vm.prank(payer);
        bytes32 channelId = channel.openChannel(
            payee,
            IERC20(address(token)),
            DEPOSIT_AMOUNT,
            signer,
            block.timestamp + 1 hours
        );

        TempoStreamChannel.Voucher memory voucher = TempoStreamChannel.Voucher({
            channelId: channelId,
            cumulativeAmount: 7000e6,
            nonce: 1,
            expiry: block.timestamp + 1 hours
        });

        bytes memory sig = signVoucher(voucher);
        bytes memory payerSig = signClose(channelId, voucher.cumulativeAmount);

        uint256 payerBefore = token.balanceOf(payer);
        uint256 payeeBefore = token.balanceOf(payee);

        channel.close(voucher, sig, payerSig);

        uint256 payerAfter = token.balanceOf(payer);
        uint256 payeeAfter = token.balanceOf(payee);

        assertEq(payeeAfter - payeeBefore, 7000e6, "Payee paid on close");
        assertEq(payerAfter - payerBefore, 3000e6, "Payer refunded on close");

        (, , , , , , , bool finalized) = channel.channels(channelId);
        assertTrue(finalized, "Channel finalized on cooperative close");
    }

    function signVoucher(
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

    function signClose(
        bytes32 channelId,
        uint256 cumulativeAmount
    ) internal view returns (bytes memory) {
        bytes32 closeHash = keccak256(
            abi.encodePacked("CLOSE", channelId, cumulativeAmount)
        );
        bytes32 closeDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", closeHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            payerPrivateKey,
            closeDigest
        );
        return abi.encodePacked(r, s, v);
    }
}

