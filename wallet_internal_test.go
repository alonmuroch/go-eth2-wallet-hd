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

package hd

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalWallet(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		err        error
		id         uuid.UUID
		version    uint
		walletType string
	}{
		{
			name: "Nil",
			err:  errors.New("unexpected end of JSON input"),
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   errors.New("unexpected end of JSON input"),
		},
		{
			name:  "NotJSON",
			input: []byte(`bad`),
			err:   errors.New(`invalid character 'b' looking for beginning of value`),
		},
		{
			name:  "MissingID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1}`),
			err:   errors.New("wallet ID missing"),
		},
		{
			name:  "WrongID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":7,"name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet ID invalid"),
		},
		{
			name:  "BadID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"wadbadba-dbad-badb-adba-badbadbadbad","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("invalid UUID format"),
		},
		{
			name:  "WrongOldID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"id":7,"name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet ID invalid"),
		},
		{
			name:  "BadOldID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"id":"wadbadba-dbad-badb-adba-badbadbadbad","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("invalid UUID format"),
		},
		{
			name:  "MissingName",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"id":"7603a428-999c-49d0-8241-ddfd63ee143d","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet name missing"),
		},
		{
			name:  "WrongName",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":2,"nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet name invalid"),
		},
		{
			name:  "MissingCrypto",
			input: []byte(`{"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1}`),
			err:   errors.New("wallet crypto missing"),
		},
		{
			name:  "WrongCrypto",
			input: []byte(`{"crypto":"foo","uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1}`),
			err:   errors.New("wallet crypto invalid"),
		},
		{
			name:  "MissingNextAccount",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet next account missing"),
		},
		{
			name:  "BadNextAccount",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":"bad","type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			err:   errors.New("wallet next account invalid"),
		},
		{
			name:  "MissingType",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"version":1,"walletIndex":0}`),
			err:   errors.New("wallet type missing"),
		},
		{
			name:  "WrongType",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":2,"version":1,"walletIndex":0}`),
			err:   errors.New("wallet type invalid"),
		},
		{
			name:  "BadType",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"xd","version":1,"walletIndex":0}`),
			err:   errors.New(`wallet type "xd" unexpected`),
		},
		{
			name:  "MissingVersion",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","walletIndex":0}`),
			err:   errors.New("wallet version missing"),
		},
		{
			name:  "WrongVersion",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":false,"walletIndex":0}`),
			err:   errors.New("wallet version invalid"),
		},
		{
			name:  "WrongWalletIndex",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":false,"walletIndex":"z"}`),
			err:   errors.New("wallet index invalid"),
		},
		{
			name:  "MissingWalletIndex",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":false}`),
			err:   errors.New("wallet index missing"),
		},
		{
			name:       "Good",
			input:      []byte(`{"crypto":{"checksum":{"function":"sha256","message":"d6f4c3898450a44666538785f419a78decde53da5f3ec17e611a961e204ed617","params":{}},"cipher":{"function":"aes-128-ctr","message":"0040872e1ba675bfe39053565f7ec02bc1560b2a95670b046f1a2e17facc1b57","params":{"iv":"7cbadf81a3895dbfee3863f0e5bd19f2"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"fcb4992215d5f84444c6f49a69e2124a899740e76caea09a1d465a71f802023a"}}},"uuid":"7603a428-999c-49d0-8241-ddfd63ee143d","name":"hd wallet","nextaccount":2,"type":"hierarchical deterministic","version":1,"walletIndex":0}`),
			walletType: "hierarchical deterministic",
			id:         uuid.MustParse("7603a428-999c-49d0-8241-ddfd63ee143d"),
			version:    1,
		},

	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := newWallet()
			err := json.Unmarshal(test.input, output)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.id, output.ID())
				assert.Equal(t, test.version, output.Version())
				assert.Equal(t, test.walletType, output.Type())
			}
		})
	}
}
