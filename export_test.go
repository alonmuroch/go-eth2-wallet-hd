// Copyright 2019, 2020 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hd_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExportWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet("test wallet", []byte{}, store, encryptor)
	require.Nil(t, err)
	err = wallet.Unlock([]byte{})
	require.Nil(t, err)

	account1, err := wallet.CreateAccount("Account 1", []byte("account 1 passphrase"))
	require.Nil(t, err)
	account2, err := wallet.CreateAccount("Account 2", []byte("account 2 passphrase"))
	require.Nil(t, err)

	dump, err := wallet.(wtypes.WalletExporter).Export([]byte("dump"))
	require.Nil(t, err)

	// Import it
	store2 := scratch.New()
	wallet2, err := hd.Import(dump, []byte("dump"), store2, encryptor)
	require.Nil(t, err)

	// Confirm the accounts are present
	account1Present := false
	account2Present := false
	for account := range wallet2.Accounts() {
		if account.ID().String() == account1.ID().String() {
			account1Present = true
		}
		if account.ID().String() == account2.ID().String() {
			account2Present = true
		}
	}
	assert.True(t, account1Present && account2Present)

	// Try to import it again; should fail
	_, err = hd.Import(dump, []byte("dump"), store2, encryptor)
	require.NotNil(t, err)
}

func TestWalletFromSeed(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := hd.CreateWallet("test wallet", []byte{}, store, encryptor)
	require.Nil(t, err)
	err = wallet.Unlock([]byte{})
	require.Nil(t, err)
	seed, err := wallet.(wtypes.WalletKeyProvider).Key()
	require.Nil(t, err)

	importedWallet, err := hd.CreateWalletFromSeed("imported wallet", 0, []byte{}, store, encryptor, seed)
	require.Nil(t, err)
	err = importedWallet.Unlock([]byte{})
	require.Nil(t, err)
	importedSeed, err := importedWallet.(wtypes.WalletKeyProvider).Key()
	require.Nil(t, err)

	assert.Equal(t, seed, importedSeed)
}
