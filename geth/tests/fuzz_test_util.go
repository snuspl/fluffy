// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sort"
)

func GetTxDataBytes(tx *Transaction) []byte {
	if tx.GetIsCreateTx() {
		result := append(tx.GetCreateTxConstructor(), tx.GetCreateTxConstructorPostfix()...)
		result = append(result, tx.GetCreateTxContract()...)
		result = append(result, tx.GetCreateTxContractPostfix()...)
		return result
	} else {
		return tx.CallTxData
	}
}

func RunFuzz(fuzzed Fuzzed) FuzzResult {
	memDB := rawdb.NewMemoryDatabase()
	sdb := state.NewDatabase(memDB)
	statedb, _ := state.New(common.Hash{}, sdb, nil) 

	genesisAccount := fuzzed.GenesisAccount
	genesisAccountAddress := common.HexToAddress(genesisAccount.GetAddress())
	statedb.SetNonce(genesisAccountAddress, genesisAccount.GetNonce())
	statedb.SetBalance(genesisAccountAddress, new(big.Int).SetUint64(genesisAccount.GetBalance()))

	for _, builtin := range fuzzed.GetBuiltinAddrs() {
		builtinAccountAddress := common.HexToAddress(builtin)
		statedb.SetNonce(builtinAccountAddress, 0)
		statedb.SetBalance(builtinAccountAddress, new(big.Int).SetUint64(1))
	}

	*statedb.GetActivatedAddrs() = append(*statedb.GetActivatedAddrs(), genesisAccountAddress)

	for _, builtinAddr := range fuzzed.GetBuiltinAddrs() {
		*statedb.GetActivatedAddrs() = append(*statedb.GetActivatedAddrs(), common.HexToAddress(builtinAddr))
	}

	_, err := statedb.Commit(false) 
	if err != nil {
	}

	var rootHashes []string
	var stateDumps []string
	var traces []string

	var nonce uint64 = 0

	sort.Slice(fuzzed.GetBlocks(), func(i, j int) bool {
		return fuzzed.GetBlocks()[i].GetNumber() < fuzzed.GetBlocks()[j].GetNumber()
	})
	
	for i := 0; i < len(fuzzed.GetBlocks()); i++ {
		block := fuzzed.GetBlocks()[i]
		for j := 0; j < len(block.GetTransactions()); j++ {
			transaction := block.GetTransactions()[j]

			var receiverCopy common.Address
			var receiver *common.Address
			if transaction.GetIsCreateTx() {
				receiver = nil 
			} else {
				receiverOffset := transaction.GetReceiver() % uint32(len(*statedb.GetActivatedAddrs()))
				receiverCopy = (*statedb.GetActivatedAddrs())[receiverOffset] 
				receiver = &receiverCopy
			}
			msg := types.NewMessage(
				common.HexToAddress(transaction.GetSender()),
				receiver,
				nonce,
				new(big.Int).SetUint64(transaction.GetValue()),
				transaction.GetGas(),
				new(big.Int).SetUint64(transaction.GetGasPrice()),
				GetTxDataBytes(transaction),
				true)

			nonce = nonce + 1

			var vmConfig vm.Config

			var traceBuffer bytes.Buffer
			jsonLogger := vm.NewJSONLogger(&vm.LogConfig{
				false,
				false,
				false,
				false,
				0,
			}, &traceBuffer)

			if fuzzed.GetIsDebugMode() {
				vmConfig = vm.Config{
					Tracer: jsonLogger,
					Debug: true,
				}
			} else {
				vmConfig = vm.Config{
					Tracer: nil,
					Debug:  false, /
				}
			}

			chainConfig := params.MainnetChainConfig
			context := vm.Context{
				CanTransfer: core.CanTransfer,
				Transfer:    core.Transfer,
				GetHash:     fuzzBlockHash, /
				Origin:      common.HexToAddress(transaction.GetSender()),
				Coinbase:    common.HexToAddress(block.GetAuthor()),
				BlockNumber: new(big.Int).SetUint64(block.GetNumber()),
				Time:        new(big.Int).SetUint64(block.GetTimestamp()),
				Difficulty:  new(big.Int).SetUint64(block.GetDifficulty()),
				GasLimit:    block.GetGasLimit(),
				GasPrice:    new(big.Int).SetUint64(1),
			}

			evm := vm.NewEVM(context, statedb, chainConfig, vmConfig)

			gaspool := new(core.GasPool)
			gaspool.AddGas(block.GetGasLimit())
			snapshot := statedb.Snapshot()

			if _, err := core.ApplyMessage(evm, msg, gaspool); err != nil {
				statedb.RevertToSnapshot(snapshot)
			}

			statedb.Commit(chainConfig.IsEIP158(new(big.Int).SetUint64(block.GetNumber())))

			statedb.AddBalance(common.HexToAddress(block.GetAuthor()), new(big.Int))

			root := statedb.IntermediateRoot(chainConfig.IsEIP158(new(big.Int).SetUint64(block.GetNumber())))

			rootHashes = append(rootHashes, root.Hex())

			if fuzzed.GetIsDebugMode() {
				stateDumps = append(stateDumps, string(statedb.Dump(false, false, false)))
				traces = append(traces, traceBuffer.String())
			} else {
				stateDumps = append(stateDumps, "")
				traces = append(traces, "")
			}
		}
	}

	result := FuzzResult{}
	result.Roots = rootHashes
	result.Dumps = stateDumps
	result.Traces = traces
	return result
}

func fuzzBlockHash(n uint64) common.Hash {
	return common.HexToHash("00")
}
