package trust

import (
	"aead.dev/minisign"
)

// Key is a per-alpha trust entry.
type Key struct {
	Alphas []string
	Public minisign.PublicKey
}

var keys = []Key{
	{
		Alphas: []string{"0.0.23"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWQBhIRg+dOifTWlwgYHe8RfD8bqoDh1cCvygboAl3GOUKiCo0NlF4fw"),
	},
	{
		Alphas: []string{"0.0.23b"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWTsHxQMrRq4xwHisyBa2rNQfAedcINzbTT83jeX4/ZcfVxqLfWB4y8w"),
	},
	{
		Alphas: []string{"0.0.24"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWRcbM/EwV7bucTiQVCcRBhCkYkXmJEO7s4ktyufkB+gW/NxHhOZ38xh"),
	},
	{
		Alphas: []string{"0.0.25"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWTVElEmCfAMGk/jtMc2I9/ElBvoJituKdbDWqqj6D69qz2cKexU4gv+"),
	},
	{
		Alphas: []string{"0.0.25b"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWTVElEmCfAMGk/jtMc2I9/ElBvoJituKdbDWqqj6D69qz2cKexU4gv+"),
	},
	{
		Alphas: []string{"0.0.26"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWQa4XiSn+BLxIYXNrXyz68wwTGWyZ7+kxDtZuLHBXkCtt+lLB8VnpdM"),
	},
	{
		Alphas: []string{"0.0.27"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWQv2alKl8D0zMDJR766jpYvPy4u3y77HL/iKb/lsT1Fnf6ezoMb2x8+"),
	},
	{
		Alphas: []string{"0.0.27.1"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWQv2alKl8D0zMDJR766jpYvPy4u3y77HL/iKb/lsT1Fnf6ezoMb2x8+"),
	},
	{
		Alphas: []string{"0.28.0"},
		Public: mustPub("untrusted comment: minisign public key: 0000000000000000\nRWRoZZuNzi1wX+Hs5NKAf+GghHwye3mFePfBzOFt3mqYUZAkqAvs69W2"),
	},
}

func mustPub(s string) minisign.PublicKey {
	var pk minisign.PublicKey
	if err := pk.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return pk
}

// ForAlpha returns the public key for alpha.
func ForAlpha(alpha string) (minisign.PublicKey, bool) {
	for _, k := range keys {
		for _, a := range k.Alphas {
			if a == alpha {
				return k.Public, true
			}
		}
	}
	return minisign.PublicKey{}, false
}

// ByID returns the key entry for a given key ID.
func ByID(id uint64) (Key, bool) {
	for _, k := range keys {
		if k.Public.ID() == id {
			return k, true
		}
	}
	return Key{}, false
}

// All returns all trust entries.
func All() []Key {
	out := make([]Key, len(keys))
	copy(out, keys)
	return out
}
