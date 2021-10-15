package main

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"

	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/accounts"
	consensusAccounts "github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/consensusaccounts"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/testing"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
)

const (
	timeout = 1 * time.Minute
)

func ensureStakingEvent(log *logging.Logger, ch <-chan *staking.Event, check func(*staking.Event) bool) error {
	log.Info("waiting for expected staking event...")
	for {
		select {
		case ev := <-ch:
			log.Debug("received event", "event", ev)
			if check(ev) {
				return nil
			}

		case <-time.After(timeout):
			return fmt.Errorf("timeout waiting for event")
		}
	}
}

func SimpleConsensusTest(sc *RuntimeScenario, log *logging.Logger, conn *grpc.ClientConn, rtc client.RuntimeClient) error {
	ctx := context.Background()

	cons := consensus.NewConsensusClient(conn)
	stakingClient := cons.Staking()
	ch, sub, err := stakingClient.WatchEvents(ctx)
	defer sub.Close()
	if err != nil {
		return err
	}

	consDenomination := types.Denomination("TEST")

	consAccounts := consensusAccounts.NewV1(rtc)
	ac := accounts.NewV1(rtc)

	log.Info("alice depositing into runtime")
	amount := types.NewBaseUnits(*quantity.NewFromUint64(50), consDenomination)
	tb := consAccounts.Deposit(testing.Bob.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Alice.SigSpec, 0)
	_ = tb.AppendSign(ctx, testing.Alice.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		return err
	}

	if err = ensureStakingEvent(log, ch, func(e *staking.Event) bool {
		if e.Transfer == nil {
			return false
		}
		if e.Transfer.From != staking.Address(testing.Alice.Address) {
			return false
		}
		if e.Transfer.To != staking.NewRuntimeAddress(runtimeID) {
			return false
		}
		return e.Transfer.Amount.Cmp(&amount.Amount) == 0
	}); err != nil {
		return fmt.Errorf("ensuring alice deposit consensus event: %w", err)
	}

	resp, err := consAccounts.Balance(ctx, client.RoundLatest, &consensusAccounts.BalanceQuery{
		Address: testing.Bob.Address,
	})
	if err != nil {
		return err
	}
	if resp.Balance.Cmp(quantity.NewFromUint64(50)) != 0 {
		return fmt.Errorf("after deposit, expected bob balance 50, got %s", resp.Balance)
	}

	amount.Amount = *quantity.NewFromUint64(40)
	log.Info("bob depositing into runtime")
	tb = consAccounts.Deposit(testing.Alice.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Bob.SigSpec, 0)
	_ = tb.AppendSign(ctx, testing.Bob.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		return err
	}
	if err = ensureStakingEvent(log, ch, func(e *staking.Event) bool {
		if e.Transfer == nil {
			return false
		}
		if e.Transfer.From != staking.Address(testing.Bob.Address) {
			return false
		}
		if e.Transfer.To != staking.NewRuntimeAddress(runtimeID) {
			return false
		}
		return e.Transfer.Amount.Cmp(&amount.Amount) == 0
	}); err != nil {
		return fmt.Errorf("ensuring bob deposit consensus event: %w", err)
	}
	resp, err = consAccounts.Balance(ctx, client.RoundLatest, &consensusAccounts.BalanceQuery{
		Address: testing.Alice.Address,
	})
	if err != nil {
		return err
	}
	if resp.Balance.Cmp(quantity.NewFromUint64(40)) != 0 {
		return fmt.Errorf("after deposit, expected alice balance 50, got %s", resp.Balance)
	}

	amount.Amount = *quantity.NewFromUint64(25)
	log.Info("alice withdrawing")
	tb = consAccounts.Withdraw(testing.Bob.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Alice.SigSpec, 1)
	_ = tb.AppendSign(ctx, testing.Alice.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		return err
	}
	if err = ensureStakingEvent(log, ch, func(e *staking.Event) bool {
		if e.Transfer == nil {
			return false
		}
		if e.Transfer.To != staking.Address(testing.Bob.Address) {
			return false
		}
		if e.Transfer.From != staking.NewRuntimeAddress(runtimeID) {
			return false
		}
		return e.Transfer.Amount.Cmp(&amount.Amount) == 0
	}); err != nil {
		return fmt.Errorf("ensuring alice withdraw consensus event: %w", err)
	}

	amount.Amount = *quantity.NewFromUint64(50)
	log.Info("charlie withdrawing")
	tb = consAccounts.Withdraw(testing.Charlie.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Charlie.SigSpec, 0)
	_ = tb.AppendSign(ctx, testing.Charlie.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		log.Info("charlie withdrawing failed (as expected)", "err", err)
	} else {
		return fmt.Errorf("charlie withdrawing should fail")
	}

	log.Info("alice withdrawing with invalid nonce")
	tb = consAccounts.Withdraw(testing.Bob.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Alice.SigSpec, 1)
	_ = tb.AppendSign(ctx, testing.Alice.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		log.Info("alice invalid nonce failed request failed (as expected)", "err", err)
	} else {
		return fmt.Errorf("alice withdrawing with invalid nonce should fail")
	}

	log.Info("alice query balance")
	balanceQuery := &consensusAccounts.BalanceQuery{
		Address: testing.Alice.Address,
	}
	resp, err = consAccounts.Balance(ctx, client.RoundLatest, balanceQuery)
	if err != nil {
		return err
	}
	if resp.Balance.Cmp(quantity.NewFromUint64(40 - 25)) != 0 {
		return fmt.Errorf("unexpected bob balance, got: %s", resp.Balance)
	}

	log.Info("query bob consensus account")
	accountsQuery := &consensusAccounts.AccountQuery{
		Address: testing.Alice.Address,
	}
	acc, err := consAccounts.ConsensusAccount(ctx, client.RoundLatest, accountsQuery)
	if err != nil {
		return err
	}
	if acc.General.Balance.Cmp(quantity.NewFromUint64(100 - 40 + 25)) != 0 {
		return fmt.Errorf("unexpected bob consensus account balance, got: %s", acc.General.Balance)
	}

	log.Info("dave depositing (secp256k1)")
	amount.Amount = *quantity.NewFromUint64(50)
	tb = consAccounts.Deposit(testing.Dave.Address, amount).
		SetFeeConsensusMessages(1).
		AppendAuthSignature(testing.Dave.SigSpec, 0)
	_ = tb.AppendSign(ctx, testing.Dave.Signer)
	if err = tb.SubmitTx(ctx, nil); err != nil {
		log.Info("dave depositing failed (as expected)", "err", err)
	} else {
		return fmt.Errorf("dave depositing should fail")
	}

	log.Info("query consensus addresses")
	addrs, err := ac.Addresses(ctx, client.RoundLatest, consDenomination)
	if err != nil {
		return err
	}
	if len(addrs) != 2 { // Alice, Bob (Charlie has 0 balance).
		return fmt.Errorf("unexpected number of addresses (expected: %d, got: %d)", 2, len(addrs))
	}

	return nil
}
