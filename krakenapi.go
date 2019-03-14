package krakenapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/tidwall/gjson"
)

const (
	// APIURL is the official Kraken API Endpoint
	APIURL = "https://api.kraken.com"
	// APIVersion is the official Kraken API Version Number
	APIVersion = "0"
	// APIUserAgent identifies this library with the Kraken API
	APIUserAgent = "Kraken GO API Agent (https://github.com/beldur/kraken-go-api-client)"
)

// List of valid public methods
var publicMethods = []string{
	"Time",
	"Assets",
	"AssetPairs",
	"Ticker",
	"OHLC",
	"Depth",
	"Trades",
	"Spread",
}

// List of valid private methods
var privateMethods = []string{
	"Balance",
	"TradeBalance",
	"OpenOrders",
	"ClosedOrders",
	"QueryOrders",
	"TradesHistory",
	"QueryTrades",
	"OpenPositions",
	"Ledgers",
	"QueryLedgers",
	"TradeVolume",
	"AddOrder",
	"CancelOrder",
	"DepositMethods",
	"DepositAddresses",
	"DepositStatus",
	"WithdrawInfo",
	"Withdraw",
	"WithdrawStatus",
	"WithdrawCancel",
}

var privateMethodTokenCountOverrides = map[string]int{
	"Ledgers":      2,
	"QueryLedgers": 2,
	"ClosedOrders": 2,
	"AddOrder":     0,
	"CancelOrder":  0,
}

// These represent the minimum order sizes for the respective coins
// Should be monitored through here: https://support.kraken.com/hc/en-us/articles/205893708-What-is-the-minimum-order-size-
const (
	MinimumREP  = 0.3
	MinimumXBT  = 0.002
	MinimumBCH  = 0.002
	MinimumDASH = 0.03
	MinimumDOGE = 3000.0
	MinimumEOS  = 3.0
	MinimumETH  = 0.02
	MinimumETC  = 0.3
	MinimumGNO  = 0.03
	MinimumICN  = 2.0
	MinimumLTC  = 0.1
	MinimumMLN  = 0.1
	MinimumXMR  = 0.1
	MinimumXRP  = 30.0
	MinimumXLM  = 300.0
	MinimumZEC  = 0.02
	MinimumUSDT = 5.0
)

// KrakenApi represents a Kraken API Client connection
type KrakenApi struct {
	key               string
	secret            string
	client            *http.Client
	mutex             *sync.Mutex
	serializeRequests bool
	enableRateLimiter bool
	limiter           *rate.Limiter
}

// New creates a new Kraken API client
func New(key, secret string) *KrakenApi {
	return NewWithClient(key, secret, http.DefaultClient)
}

func NewWithClient(key, secret string, httpClient *http.Client) *KrakenApi {
	return NewWithClientSerialized(
		key,
		secret,
		httpClient,
		nil,
	)
}

func NewWithClientSerialized(
	key, secret string,
	httpClient *http.Client,
	mutex *sync.Mutex,
) *KrakenApi {
	return &KrakenApi{
		key:               key,
		secret:            secret,
		client:            httpClient,
		serializeRequests: mutex != nil,
		mutex:             mutex,
	}
}

func NewWithClientSerializedRateLimited(
	key, secret string,
	httpClient *http.Client,
	mutex *sync.Mutex,
	refreshRate time.Duration,
	maxBurst int,
) *KrakenApi {
	k := &KrakenApi{
		key:               key,
		secret:            secret,
		client:            httpClient,
		serializeRequests: mutex != nil,
		mutex:             mutex,
	}

	k.SetRateLimiter(
		refreshRate,
		maxBurst,
	)

	return k
}

func (api *KrakenApi) SetRateLimiter(
	refreshRate time.Duration,
	maxBurst int,
) {
	api.enableRateLimiter = true
	api.limiter = rate.NewLimiter(rate.Every(refreshRate), maxBurst)
}

// Time returns the server's time
func (api *KrakenApi) Time() (*TimeResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPublic("Time", nil, &TimeResponse{})
	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*TimeResponse), httpResp, nil
}

// Assets returns the servers available assets
func (api *KrakenApi) Assets() (*AssetsResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPublic("Assets", nil, &AssetsResponse{})
	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*AssetsResponse), httpResp, nil
}

// AssetPairs returns the servers available asset pairs
func (api *KrakenApi) AssetPairs() (*AssetPairsResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPublic("AssetPairs", nil, &AssetPairsResponse{})
	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*AssetPairsResponse), httpResp, nil
}

// Ticker returns the ticker for given comma separated pairs
func (api *KrakenApi) Ticker(pairs ...string) (*TickerResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPublic("Ticker", url.Values{
		"pair": {strings.Join(pairs, ",")},
	}, &TickerResponse{})
	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*TickerResponse), httpResp, nil
}

// Trades returns the recent trades for given pair
func (api *KrakenApi) Trades(pair string, since int64) (*TradesResponse, *http.Response, error) {
	values := url.Values{"pair": {pair}}
	if since > 0 {
		values.Set("since", strconv.FormatInt(since, 10))
	}
	resp, httpResp, err := api.queryPublic("Trades", values, nil)
	if err != nil {
		return nil, httpResp, err
	}

	v := resp.(map[string]interface{})

	last, err := strconv.ParseInt(v["last"].(string), 10, 64)
	if err != nil {
		return nil, httpResp, err
	}

	result := &TradesResponse{
		Last:   last,
		Trades: make([]TradeInfo, 0),
	}

	trades := v[pair].([]interface{})
	for _, v := range trades {
		trade := v.([]interface{})

		priceString := trade[0].(string)
		price, _ := strconv.ParseFloat(priceString, 64)

		volumeString := trade[1].(string)
		volume, _ := strconv.ParseFloat(trade[1].(string), 64)

		tradeInfo := TradeInfo{
			Price:         priceString,
			PriceFloat:    price,
			Volume:        volumeString,
			VolumeFloat:   volume,
			Time:          int64(trade[2].(float64)),
			Buy:           trade[3].(string) == BUY,
			Sell:          trade[3].(string) == SELL,
			Market:        trade[4].(string) == MARKET,
			Limit:         trade[4].(string) == LIMIT,
			Miscellaneous: trade[5].(string),
		}

		result.Trades = append(result.Trades, tradeInfo)
	}

	return result, httpResp, nil
}

// Balance returns all account asset balances
func (api *KrakenApi) Balance() (*BalanceResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPrivate("Balance", url.Values{}, nil)
	if err != nil {
		return nil, httpResp, err
	}

	var balance BalanceResponse
	balance = resp.(BalanceResponse)

	return &balance, httpResp, nil
}

// OpenOrders returns all open orders
func (api *KrakenApi) OpenOrders(args map[string]string) (*OpenOrdersResponse, *http.Response, error) {
	params := url.Values{}
	if value, ok := args["trades"]; ok {
		params.Add("trades", value)
	}
	if value, ok := args["userref"]; ok {
		params.Add("userref", value)
	}

	resp, httpResp, err := api.queryPrivate("OpenOrders", params, &OpenOrdersResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*OpenOrdersResponse), httpResp, nil
}

// ClosedOrders returns all closed orders
func (api *KrakenApi) ClosedOrders(args map[string]string) (*ClosedOrdersResponse, *http.Response, error) {
	params := url.Values{}
	if value, ok := args["trades"]; ok {
		params.Add("trades", value)
	}
	if value, ok := args["userref"]; ok {
		params.Add("userref", value)
	}
	if value, ok := args["start"]; ok {
		params.Add("start", value)
	}
	if value, ok := args["end"]; ok {
		params.Add("end", value)
	}
	if value, ok := args["ofs"]; ok {
		params.Add("ofs", value)
	}
	if value, ok := args["closetime"]; ok {
		params.Add("closetime", value)
	}
	resp, httpResp, err := api.queryPrivate("ClosedOrders", params, &ClosedOrdersResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*ClosedOrdersResponse), httpResp, nil
}

// Depth returns the order book for given pair and orders count.
func (api *KrakenApi) Depth(pair string, count int) (*OrderBook, *http.Response, error) {
	dr := DepthResponse{}
	_, httpResp, err := api.queryPublic("Depth", url.Values{
		"pair": {pair}, "count": {strconv.Itoa(count)},
	}, &dr)

	if err != nil {
		return nil, httpResp, err
	}

	if book, found := dr[pair]; found {
		return &book, httpResp, nil
	}

	return nil, httpResp, errors.New("invalid response")
}

// CancelOrder cancels order
func (api *KrakenApi) CancelOrder(txid string) (*CancelOrderResponse, *http.Response, error) {
	params := url.Values{}
	params.Add("txid", txid)
	resp, httpResp, err := api.queryPrivate("CancelOrder", params, &CancelOrderResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*CancelOrderResponse), httpResp, nil
}

// QueryOrders shows order
func (api *KrakenApi) QueryOrders(txids string, args map[string]string) (*QueryOrdersResponse, *http.Response, error) {
	params := url.Values{"txid": {txids}}
	if value, ok := args["trades"]; ok {
		params.Add("trades", value)
	}
	if value, ok := args["userref"]; ok {
		params.Add("userref", value)
	}
	resp, httpResp, err := api.queryPrivate("QueryOrders", params, &QueryOrdersResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*QueryOrdersResponse), httpResp, nil
}

// QueryTrades
func (api *KrakenApi) QueryTrades(txid string, trades bool) (*QueryTradesResponse, *http.Response, error) {
	params := url.Values{}
	params.Add("txid", txid)
	params.Add("trades", strconv.FormatBool(trades))

	resp, httpResp, err := api.queryPrivate("QueryTrades", params, &QueryTradesResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*QueryTradesResponse), httpResp, nil
}

// DepositStatus retrieves deposit statuses
func (api *KrakenApi) DepositStatus(asset string, args map[string]string) (*DepositStatusResponse, *http.Response, error) {
	resp, httpResp, err := api.movementStatus("DepositStatus", asset, args, &DepositStatusResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*DepositStatusResponse), httpResp, nil
}

// WithdrawStatus retrieves withdraw statuses
func (api *KrakenApi) WithdrawStatus(asset string, args map[string]string) (*WithdrawStatusResponse, *http.Response, error) {
	resp, httpResp, err := api.movementStatus("WithdrawStatus", asset, args, &WithdrawStatusResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*WithdrawStatusResponse), httpResp, nil
}

func (api *KrakenApi) movementStatus(movementType string, asset string, args map[string]string, typ interface{}) (interface{}, *http.Response, error) {
	params := url.Values{}
	params.Add("asset", asset)

	if value, ok := args["method"]; ok {
		params.Add("method", value)
	}

	if value, ok := args["aclass"]; ok {
		params.Add("aclass", value)
	}

	return api.queryPrivate(movementType, params, typ)
}

// GetOpenPositions retrieves the open positions
func (api *KrakenApi) GetOpenPositions(args map[string]string) (*PositionsResponse, *http.Response, error) {
	params := url.Values{}
	if value, ok := args["txid"]; ok {
		params.Add("txid", value)
	}
	if value, ok := args["docalcs"]; ok {
		params.Add("docalcs", value)
	}

	resp, httpResp, err := api.queryPrivate("OpenPositions", params, &PositionsResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*PositionsResponse), httpResp, nil
}

// AddOrder adds new order
func (api *KrakenApi) AddOrder(pair string, direction string, orderType string, volume string, args map[string]string) (*AddOrderResponse, *http.Response, error) {
	params := url.Values{
		"pair":      {pair},
		"type":      {direction},
		"ordertype": {orderType},
		"volume":    {volume},
	}

	if value, ok := args["price"]; ok {
		params.Add("price", value)
	}
	if value, ok := args["price2"]; ok {
		params.Add("price2", value)
	}
	if value, ok := args["leverage"]; ok {
		params.Add("leverage", value)
	}
	if value, ok := args["oflags"]; ok {
		params.Add("oflags", value)
	}
	if value, ok := args["starttm"]; ok {
		params.Add("starttm", value)
	}
	if value, ok := args["expiretm"]; ok {
		params.Add("expiretm", value)
	}
	if value, ok := args["validate"]; ok {
		params.Add("validate", value)
	}
	if value, ok := args["close_order_type"]; ok {
		params.Add("close[ordertype]", value)
	}
	if value, ok := args["close_price"]; ok {
		params.Add("close[price]", value)
	}
	if value, ok := args["close_price2"]; ok {
		params.Add("close[price2]", value)
	}
	if value, ok := args["trading_agreement"]; ok {
		params.Add("trading_agreement", value)
	}
	resp, httpResp, err := api.queryPrivate("AddOrder", params, &AddOrderResponse{})

	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*AddOrderResponse), httpResp, nil
}

// DepositAddresses returns deposit addresses
func (api *KrakenApi) DepositAddresses(asset string, method string) (*DepositAddressesResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPrivate("DepositAddresses", url.Values{
		"asset":  {asset},
		"method": {method},
	}, &DepositAddressesResponse{})
	if err != nil {
		return nil, httpResp, err
	}
	return resp.(*DepositAddressesResponse), httpResp, nil
}

// Withdraw executes a withdrawal, returning a reference ID
func (api *KrakenApi) Withdraw(asset string, key string, amount *big.Float) (*WithdrawResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPrivate("Withdraw", url.Values{
		"asset":  {asset},
		"key":    {key},
		"amount": {amount.String()},
	}, &WithdrawResponse{})
	if err != nil {
		return nil, httpResp, err
	}
	return resp.(*WithdrawResponse), httpResp, nil
}

// WithdrawInfo returns withdrawal information
func (api *KrakenApi) WithdrawInfo(asset string, key string, amount *big.Float) (*WithdrawInfoResponse, *http.Response, error) {
	resp, httpResp, err := api.queryPrivate("WithdrawInfo", url.Values{
		"asset":  {asset},
		"key":    {key},
		"amount": {amount.String()},
	}, &WithdrawInfoResponse{})
	if err != nil {
		return nil, httpResp, err
	}
	return resp.(*WithdrawInfoResponse), httpResp, nil
}

// TradeBalance returns all account asset balances
func (api *KrakenApi) TradeBalance(args map[string]string) (*TradeBalanceResponse, *http.Response, error) {
	params := url.Values{}
	if value, ok := args["aclass"]; ok {
		params.Add("aclass", value)
	}
	if value, ok := args["asset"]; ok {
		params.Add("asset", value)
	}

	resp, httpResp, err := api.queryPrivate("TradeBalance", params, &TradeBalanceResponse{})
	if err != nil {
		return nil, httpResp, err
	}

	return resp.(*TradeBalanceResponse), httpResp, nil
}

// Query sends a query to Kraken api for given method and parameters
func (api *KrakenApi) Query(method string, data map[string]string) (interface{}, *http.Response, error) {
	values := url.Values{}
	for key, value := range data {
		values.Set(key, value)
	}

	// Check if method is public or private
	if isStringInSlice(method, publicMethods) {
		return api.queryPublic(method, values, nil)
	} else if isStringInSlice(method, privateMethods) {
		return api.queryPrivate(method, values, nil)
	}

	return nil, nil, fmt.Errorf("Method '%s' is not valid", method)
}

// Execute a public method query
func (api *KrakenApi) queryPublic(method string, values url.Values, typ interface{}) (interface{}, *http.Response, error) {
	url := fmt.Sprintf("%s/%s/public/%s", APIURL, APIVersion, method)
	resp, httpResp, err := api.doRequest(url, values, nil, typ)

	return resp, httpResp, err
}

// queryPrivate executes a private method query
func (api *KrakenApi) queryPrivate(method string, values url.Values, typ interface{}) (interface{}, *http.Response, error) {
	urlPath := fmt.Sprintf("/%s/private/%s", APIVersion, method)
	reqURL := fmt.Sprintf("%s%s", APIURL, urlPath)
	secret, _ := base64.StdEncoding.DecodeString(api.secret)

	if api.serializeRequests {
		api.mutex.Lock()
		defer api.mutex.Unlock()
	}

	// Determine the number of tokens to count
	if api.enableRateLimiter {
		count, ok := privateMethodTokenCountOverrides[method]
		if !ok {
			count = 1
		}

		for i := 0; i < count; i++ {
			api.limiter.Wait(context.Background())
		}
	}

	values.Set("nonce", fmt.Sprintf("%d", time.Now().UnixNano())) // Likely have to mutex this.

	// Create signature
	signature := createSignature(urlPath, values, secret)

	// Add Key and signature to request headers
	headers := map[string]string{
		"API-Key":  api.key,
		"API-Sign": signature,
	}

	resp, httpResp, err := api.doRequest(reqURL, values, headers, typ)

	return resp, httpResp, err
}

// doRequest executes a HTTP Request to the Kraken API and returns the result
func (api *KrakenApi) doRequest(reqURL string, values url.Values, headers map[string]string, typ interface{}) (interface{}, *http.Response, error) {

	// Create request
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("Could not execute request! #1 (%s)", err.Error())
	}

	req.Header.Add("User-Agent", APIUserAgent)
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Execute request
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, resp, fmt.Errorf("Could not execute request! #2 (%s)", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return nil, resp, fmt.Errorf("Could not execute request!(%s)", resp.Status)
	}

	// Read request
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, fmt.Errorf("Could not execute request! #3 (%s)", err.Error())
	}

	// Check mime type of response
	mimeType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, resp, fmt.Errorf("Could not execute request #4! (%s)", err.Error())
	}
	if mimeType != "application/json" {
		return nil, resp, fmt.Errorf("Could not execute request #5! (%s)", fmt.Sprintf("Response Content-Type is '%s', but should be 'application/json'.", mimeType))
	}

	if typ == nil {
		result := gjson.GetBytes(body, "result")
		mapList := BalanceResponse{}
		result.ForEach(
			func(key, value gjson.Result) bool {
				mapList[key.String()] = value.Float()
				return true
			},
		)

		return mapList, resp, nil
	}

	// Parse request
	var jsonData KrakenResponse

	// Set the KrakenResponse.Result to typ so `json.Unmarshal` will
	// unmarshal it into given type, instead of `interface{}`.
	if typ != nil {
		jsonData.Result = typ
	}

	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		return nil, resp, fmt.Errorf("Could not execute request! #6 (%s)", err.Error())
	}

	// Check for Kraken API error
	if len(jsonData.Error) > 0 {
		return nil, resp, fmt.Errorf("Could not execute request! #7 (%s)", jsonData.Error)
	}

	return jsonData.Result, resp, nil
}

// isStringInSlice is a helper function to test if given term is in a list of strings
func isStringInSlice(term string, list []string) bool {
	for _, found := range list {
		if term == found {
			return true
		}
	}
	return false
}

// getSha256 creates a sha256 hash for given []byte
func getSha256(input []byte) []byte {
	sha := sha256.New()
	sha.Write(input)
	return sha.Sum(nil)
}

// getHMacSha512 creates a hmac hash with sha512
func getHMacSha512(message, secret []byte) []byte {
	mac := hmac.New(sha512.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}

func createSignature(urlPath string, values url.Values, secret []byte) string {
	// See https://www.kraken.com/help/api#general-usage for more information
	shaSum := getSha256([]byte(values.Get("nonce") + values.Encode()))
	macSum := getHMacSha512(append([]byte(urlPath), shaSum...), secret)
	return base64.StdEncoding.EncodeToString(macSum)
}
