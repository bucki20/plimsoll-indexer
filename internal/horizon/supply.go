// Package horizon computes the circulating supply of a Stellar-issued asset
// from Horizon's /assets endpoint.
package horizon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrAssetNotFound means Horizon has no record of the asset (no trustlines yet).
var ErrAssetNotFound = errors.New("asset not found on horizon")

// ErrLedgerMoved means Horizon advanced while a supply was being read and the
// read could not be attributed to a single ledger, so no honest label exists
// for the balances.
var ErrLedgerMoved = errors.New("horizon ledger advanced while supply was read")

// assetsLedgerAttempts is how many times Supply re-reads /assets when it
// cannot pin the ledger the balances were served at.
const assetsLedgerAttempts = 3

// Breakdown is the per-bucket supply. Its canonical JSON encoding is hashed
// and the hash is posted on-chain with the total, so anyone can recompute it.
// Amounts are integer strings in the asset's smallest unit (7 decimals).
type Breakdown struct {
	Asset                           string `json:"asset"`
	Ledger                          uint32 `json:"ledger"`
	Authorized                      string `json:"authorized"`
	AuthorizedToMaintainLiabilities string `json:"authorized_to_maintain_liabilities"`
	Unauthorized                    string `json:"unauthorized"`
	ClaimableBalances               string `json:"claimable_balances"`
	LiquidityPools                  string `json:"liquidity_pools"`
	Contracts                       string `json:"contracts"`
	Total                           string `json:"total"`
}

// Canonical returns the exact bytes that are hashed.
func (b Breakdown) Canonical() []byte {
	out, _ := json.Marshal(b) // struct of strings and a uint32 cannot fail
	return out
}

// Hash is the hex sha256 of Canonical().
func (b Breakdown) Hash() string {
	sum := sha256.Sum256(b.Canonical())
	return hex.EncodeToString(sum[:])
}

// TotalInt returns Total as a big.Int.
func (b Breakdown) TotalInt() *big.Int {
	n, _ := new(big.Int).SetString(b.Total, 10)
	return n
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

type AssetRecord struct {
	Balances struct {
		Authorized                      string `json:"authorized"`
		AuthorizedToMaintainLiabilities string `json:"authorized_to_maintain_liabilities"`
		Unauthorized                    string `json:"unauthorized"`
	} `json:"balances"`
	ClaimableBalancesAmount string `json:"claimable_balances_amount"`
	LiquidityPoolsAmount    string `json:"liquidity_pools_amount"`
	ContractsAmount         string `json:"contracts_amount"`
}

type root struct {
	HistoryLatestLedger uint32 `json:"history_latest_ledger"`
}

type account struct {
	HomeDomain string `json:"home_domain"`
	Balances   []struct {
		AssetType string `json:"asset_type"`
		Balance   string `json:"balance"`
	} `json:"balances"`
}

// LatestLedger returns the newest ledger Horizon has ingested.
func (c *Client) LatestLedger(ctx context.Context) (uint32, error) {
	var r root
	if err := c.get(ctx, "/", &r); err != nil {
		return 0, fmt.Errorf("horizon root: %w", err)
	}
	return r.HistoryLatestLedger, nil
}

// HomeDomain returns the issuer account's home_domain ("" if unset).
func (c *Client) HomeDomain(ctx context.Context, issuer string) (string, error) {
	var a account
	if err := c.get(ctx, "/accounts/"+url.PathEscape(issuer), &a); err != nil {
		return "", fmt.Errorf("horizon account %s: %w", issuer, err)
	}
	return a.HomeDomain, nil
}

// NativeBalance returns the XLM balance of address in stroops (1 XLM = 10 000 000 stroops).
// Returns 0 and ErrAssetNotFound when the account does not exist.
func (c *Client) NativeBalance(ctx context.Context, address string) (int64, error) {
	var a account
	if err := c.get(ctx, "/accounts/"+url.PathEscape(address), &a); err != nil {
		return 0, fmt.Errorf("horizon account %s: %w", address, err)
	}
	for _, b := range a.Balances {
		if b.AssetType == "native" {
			n, err := ParseAmount(b.Balance)
			if err != nil {
				return 0, fmt.Errorf("parse native balance: %w", err)
			}
			return n.Int64(), nil
		}
	}
	return 0, nil
}

// assetPage is the slice of Horizon's /assets response this package reads.
type assetPage struct {
	Embedded struct {
		Records []AssetRecord `json:"records"`
	} `json:"_embedded"`
}

// Supply fetches the asset record and sums every bucket that is a claim on
// the issuer: trustline balances in all authorization states, claimable
// balances, liquidity-pool reserves and balances held by contracts.
//
// The Breakdown.Ledger it returns is the ledger the balances were actually read
// at, never one inferred from a separate call: Horizon stamps /assets responses
// with the Latest-Ledger header, and that is the ledger the response reflects.
// The ledger is part of the hashed breakdown and goes on-chain, so labelling a
// read with a made-up number would break every recomputation at that ledger.
// When the header is missing (an older Horizon, or a proxy that strips it) the
// read is bracketed by two root queries and retried until they agree; if they
// never agree, ErrLedgerMoved is returned rather than a mislabelled breakdown.
func (c *Client) Supply(ctx context.Context, code, issuer string) (Breakdown, error) {
	q := url.Values{"asset_code": {code}, "asset_issuer": {issuer}}.Encode()
	for attempt := 1; attempt <= assetsLedgerAttempts; attempt++ {
		hdr, page, err := c.assets(ctx, q, code, issuer)
		if err != nil {
			return Breakdown{}, err
		}
		if ledger, ok := latestLedgerHeader(hdr); ok {
			return breakdownFromPage(code+":"+issuer, ledger, page)
		}

		// No Latest-Ledger: pin the ledger by watching the root across the read.
		before, err := c.LatestLedger(ctx)
		if err != nil {
			return Breakdown{}, err
		}
		hdr, page, err = c.assets(ctx, q, code, issuer)
		if err != nil {
			return Breakdown{}, err
		}
		if ledger, ok := latestLedgerHeader(hdr); ok {
			return breakdownFromPage(code+":"+issuer, ledger, page)
		}
		after, err := c.LatestLedger(ctx)
		if err != nil {
			return Breakdown{}, err
		}
		if before == after {
			return breakdownFromPage(code+":"+issuer, before, page)
		}
	}
	return Breakdown{}, fmt.Errorf("horizon assets %s:%s: ledgers %d attempts in a row: %w",
		code, issuer, assetsLedgerAttempts, ErrLedgerMoved)
}

// assets performs the /assets request and returns the response headers so the
// caller can read Horizon's Latest-Ledger stamp.
func (c *Client) assets(ctx context.Context, query, code, issuer string) (http.Header, assetPage, error) {
	var page assetPage
	hdr, err := c.getWithHeaders(ctx, "/assets?"+query, &page)
	if err != nil {
		return nil, assetPage{}, fmt.Errorf("horizon assets %s:%s: %w", code, issuer, err)
	}
	return hdr, page, nil
}

func breakdownFromPage(asset string, ledger uint32, page assetPage) (Breakdown, error) {
	if len(page.Embedded.Records) == 0 {
		return Breakdown{}, ErrAssetNotFound
	}
	return BreakdownFromRecord(asset, ledger, page.Embedded.Records[0])
}

// latestLedgerHeader reads Horizon's Latest-Ledger response header, which names
// the ledger the response body was served at.
func latestLedgerHeader(hdr http.Header) (uint32, bool) {
	v := strings.TrimSpace(hdr.Get("Latest-Ledger"))
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// BreakdownFromRecord converts Horizon's decimal strings to integer units.
func BreakdownFromRecord(asset string, ledger uint32, r AssetRecord) (Breakdown, error) {
	type bucket struct {
		name string
		in   string
		out  *string
	}
	b := Breakdown{Asset: asset, Ledger: ledger}
	fields := []bucket{
		{"authorized", r.Balances.Authorized, &b.Authorized},
		{"authorized_to_maintain_liabilities", r.Balances.AuthorizedToMaintainLiabilities, &b.AuthorizedToMaintainLiabilities},
		{"unauthorized", r.Balances.Unauthorized, &b.Unauthorized},
		{"claimable_balances_amount", r.ClaimableBalancesAmount, &b.ClaimableBalances},
		{"liquidity_pools_amount", r.LiquidityPoolsAmount, &b.LiquidityPools},
		{"contracts_amount", r.ContractsAmount, &b.Contracts},
	}
	total := new(big.Int)
	for _, f := range fields {
		n, err := ParseAmount(f.in)
		if err != nil {
			return Breakdown{}, fmt.Errorf("%s: %w", f.name, err)
		}
		*f.out = n.String()
		total.Add(total, n)
	}
	b.Total = total.String()
	return b, nil
}

// ParseAmount converts a Horizon decimal string ("12.3400000") to an integer
// count of the smallest unit (7 decimals). An empty string is zero.
func ParseAmount(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return new(big.Int), nil
	}
	if strings.HasPrefix(s, "-") {
		return nil, fmt.Errorf("negative amount %q", s)
	}
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 7 {
		return nil, fmt.Errorf("amount %q has more than 7 decimals", s)
	}
	frac += strings.Repeat("0", 7-len(frac))
	if whole == "" {
		whole = "0"
	}
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	return n, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	_, err := c.getWithHeaders(ctx, path, out)
	return err
}

// getWithHeaders is get, also returning the response headers.
func (c *Client) getWithHeaders(ctx context.Context, path string, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrAssetNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	return resp.Header, nil
}
