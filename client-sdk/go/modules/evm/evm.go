package evm

import (
	"context"

	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
)

const (
	// Callable methods.
	methodCreate = "evm.Create"
	methodCall   = "evm.Call"

	// Queries.
	methodStorage      = "evm.Storage"
	methodCode         = "evm.Code"
	methodBalance      = "evm.Balance"
	methodSimulateCall = "evm.SimulateCall"
)

// V1 is the v1 EVM module interface.
type V1 interface {
	// Create generates an EVM CREATE transaction.
	// Note that the transaction's gas limit should be set to cover both the
	// SDK gas limit and the EVM gas limit.  The transaction fee should be
	// high enough to cover the EVM gas price multiplied by the EVM gas limit.
	Create(value []byte, initCode []byte) *client.TransactionBuilder

	// Call generates an EVM CALL transaction.
	// Note that the transaction's gas limit should be set to cover both the
	// SDK gas limit and the EVM gas limit.  The transaction fee should be
	// high enough to cover the EVM gas price multiplied by the EVM gas limit.
	Call(address []byte, value []byte, data []byte) *client.TransactionBuilder

	// Storage queries the EVM storage.
	Storage(ctx context.Context, address []byte, index []byte) ([]byte, error)

	// Code queries the EVM code storage.
	Code(ctx context.Context, address []byte) ([]byte, error)

	// Balance queries the EVM account balance.
	Balance(ctx context.Context, address []byte) (*types.Quantity, error)

	// SimulateCall simulates an EVM CALL.
	SimulateCall(ctx context.Context, gasPrice []byte, gasLimit uint64, caller []byte, address []byte, value []byte, data []byte) ([]byte, error)
}

type v1 struct {
	rtc client.RuntimeClient
}

// Implements V1.
func (a *v1) Create(value []byte, initCode []byte) *client.TransactionBuilder {
	return client.NewTransactionBuilder(a.rtc, methodCreate, &Create{
		Value:    value,
		InitCode: initCode,
	})
}

// Implements V1.
func (a *v1) Call(address []byte, value []byte, data []byte) *client.TransactionBuilder {
	return client.NewTransactionBuilder(a.rtc, methodCall, &Call{
		Address: address,
		Value:   value,
		Data:    data,
	})
}

// Implements V1.
func (a *v1) Storage(ctx context.Context, address []byte, index []byte) ([]byte, error) {
	var res []byte
	q := StorageQuery{
		Address: address,
		Index:   index,
	}
	if err := a.rtc.Query(ctx, client.RoundLatest, methodStorage, q, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// Implements V1.
func (a *v1) Code(ctx context.Context, address []byte) ([]byte, error) {
	var res []byte
	q := CodeQuery{
		Address: address,
	}
	if err := a.rtc.Query(ctx, client.RoundLatest, methodCode, q, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// Implements V1.
func (a *v1) Balance(ctx context.Context, address []byte) (*types.Quantity, error) {
	var res types.Quantity
	q := BalanceQuery{
		Address: address,
	}
	if err := a.rtc.Query(ctx, client.RoundLatest, methodBalance, q, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Implements V1.
func (a *v1) SimulateCall(ctx context.Context, gasPrice []byte, gasLimit uint64, caller []byte, address []byte, value []byte, data []byte) ([]byte, error) {
	var res []byte
	q := SimulateCallQuery{
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		Caller:   caller,
		Address:  address,
		Value:    value,
		Data:     data,
	}
	if err := a.rtc.Query(ctx, client.RoundLatest, methodSimulateCall, q, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// NewV1 generates a V1 client helper for the EVM module.
func NewV1(rtc client.RuntimeClient) V1 {
	return &v1{rtc: rtc}
}
