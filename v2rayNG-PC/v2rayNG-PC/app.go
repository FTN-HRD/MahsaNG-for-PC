package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx          context.Context
	serverList   []string
	servers      map[string]*ServerConfig
	serverAff    map[string]*ServerAffiliationInfo
	subscriptions map[string]*SubscriptionItem
	selectedServer string
	mu           sync.RWMutex
	dataDir      string
}

// EConfigType represents the configuration type
type EConfigType int

const (
	EConfigTypeVMESS EConfigType = iota + 1
	EConfigTypeCUSTOM
	EConfigTypeSHADOWSOCKS
	EConfigTypeSOCKS
	EConfigTypeVLESS
	EConfigTypeTROJAN
	EConfigTypeWIREGUARD
)

// ServerConfig represents a server configuration
type ServerConfig struct {
	ConfigVersion  int              `json:"configVersion"`
	ConfigType     EConfigType      `json:"configType"`
	SubscriptionID string           `json:"subscriptionId"`
	AddedTime      int64            `json:"addedTime"`
	Remarks        string           `json:"remarks"`
	OutboundBean   *OutboundBean    `json:"outboundBean,omitempty"`
	FullConfig     interface{}      `json:"fullConfig,omitempty"`
}

// OutboundBean represents outbound settings
type OutboundBean struct {
	Tag            string             `json:"tag"`
	Protocol       string             `json:"protocol"`
	Settings       *OutSettingsBean   `json:"settings,omitempty"`
	StreamSettings *StreamSettingsBean `json:"streamSettings,omitempty"`
	Mux            *MuxBean           `json:"mux,omitempty"`
}

// OutSettingsBean represents outbound settings
type OutSettingsBean struct {
	Vnext     []VnextBean     `json:"vnext,omitempty"`
	Servers   []ServersBean   `json:"servers,omitempty"`
	Response  *ResponseBean   `json:"response,omitempty"`
	Network   string          `json:"network,omitempty"`
	Address   interface{}     `json:"address,omitempty"`
	Port      int             `json:"port,omitempty"`
	SecretKey string          `json:"secretKey,omitempty"`
	Peers     []WireGuardBean `json:"peers,omitempty"`
}

// VnextBean represents vnext settings
type VnextBean struct {
	Address string        `json:"address"`
	Port    int           `json:"port"`
	Users   []UsersBean   `json:"users"`
}

// UsersBean represents user settings
type UsersBean struct {
	ID       string `json:"id"`
	AlterID  int    `json:"alterId"`
	Security string `json:"security"`
	Level    int    `json:"level"`
	Flow     string `json:"flow,omitempty"`
	Email    string `json:"email,omitempty"`
}

// ServersBean represents server settings
type ServersBean struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Level    int    `json:"level"`
	Email    string `json:"email,omitempty"`
	Method   string `json:"method,omitempty"`
}

// StreamSettingsBean represents stream settings
type StreamSettingsBean struct {
	Network       string        `json:"network"`
	Security      string        `json:"security"`
	TCPSettings   interface{}   `json:"tcpSettings,omitempty"`
	KCPSettings   interface{}   `json:"kcpSettings,omitempty"`
	WSSettings    *WSSettingsBean   `json:"wsSettings,omitempty"`
	HTTPSettings  interface{}   `json:"httpSettings,omitempty"`
	QuicSettings  interface{}   `json:"quicSettings,omitempty"`
	RealitySettings interface{} `json:"realitySettings,omitempty"`
	GRPCSettings  *GRPCSettingsBean `json:"grpcSettings,omitempty"`
	TLSSettings   *TLSSettingsBean  `json:"tlsSettings,omitempty"`
	Sockopt       *SockoptBean  `json:"sockopt,omitempty"`
}

// WSSettingsBean represents WebSocket settings
type WSSettingsBean struct {
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"maxEarlyData,omitempty"`
	EarlyDataHeaderName string            `json:"earlyDataHeaderName,omitempty"`
}

// GRPCSettingsBean represents gRPC settings
type GRPCSettingsBean struct {
	ServiceName string `json:"serviceName"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

// TLSSettingsBean represents TLS settings
type TLSSettingsBean struct {
	ServerName         string   `json:"serverName,omitempty"`
	AllowInsecure      bool     `json:"allowInsecure,omitempty"`
	ALPN               []string `json:"alpn,omitempty"`
	Fingerprint        string   `json:"fingerprint,omitempty"`
	Certificates       interface{} `json:"certificates,omitempty"`
	DisableSystemRoot  bool     `json:"disableSystemRoot,omitempty"`
}

// SockoptBean represents socket options
type SockoptBean struct {
	Tproxy        string `json:"tproxy,omitempty"`
	Mark          int    `json:"mark,omitempty"`
	TCPMptcp      bool   `json:"tcpMptcp,omitempty"`
	PenaltyBox    string `json:"penaltyBox,omitempty"`
	DialerProxy   string `json:"dialerProxy,omitempty"`
	TCPKeepAliveInterval int `json:"tcpKeepAliveInterval,omitempty"`
	TCPKeepAliveIdle   int `json:"tcpKeepAliveIdle,omitempty"`
}

// MuxBean represents mux settings
type MuxBean struct {
	Enabled     bool   `json:"enabled"`
	Concurrency int    `json:"concurrency,omitempty"`
	XudpConcurrency int `json:"xudpConcurrency,omitempty"`
	XudpProxyUDP443 string `json:"xudpProxyUDP443,omitempty"`
}

// ResponseBean represents response settings
type ResponseBean struct {
	Type string `json:"type"`
}

// WireGuardBean represents WireGuard peer settings
type WireGuardBean struct {
	PublicKey    string `json:"publicKey"`
	PreSharedKey string `json:"preSharedKey,omitempty"`
	Endpoint     string `json:"endpoint"`
	KeepAlive    int    `json:"keepAlive,omitempty"`
}

// ServerAffiliationInfo represents server test results
type ServerAffiliationInfo struct {
	TestDelayMillis int64 `json:"testDelayMillis"`
	TestSpeed       int64 `json:"testSpeed"`
	TestTime        int64 `json:"testTime"`
}

// SubscriptionItem represents a subscription
type SubscriptionItem struct {
	Remarks    string `json:"remarks"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	AddedTime  int64  `json:"addedTime"`
	UserAgent  string `json:"userAgent,omitempty"`
	Filter     string `json:"filter,omitempty"`
	Convert    string `json:"convert,omitempty"`
}

// VmessQRCode represents VMess QR code data
type VmessQRCode struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	Sni  string `json:"sni"`
	ALPN string `json:"alpn"`
	Fp   string `json:"fp"`
}

// ThemeSettings represents theme preferences
type ThemeSettings struct {
	IsDark bool `json:"isDark"`
}

// AppStatus represents the current app status
type AppStatus struct {
	IsRunning   bool   `json:"isRunning"`
	SelectedID  string `json:"selectedId"`
	Remarks     string `json:"remarks"`
	ConnectionState string `json:"connectionState"`
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		serverList:   make([]string, 0),
		servers:      make(map[string]*ServerConfig),
		serverAff:    make(map[string]*ServerAffiliationInfo),
		subscriptions: make(map[string]*SubscriptionItem),
		mu:           sync.RWMutex{},
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.dataDir = a.getDataDir()
	a.loadConfig()
}

// getDataDir returns the data directory for storing configurations
func (a *App) getDataDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./v2rayng_data"
	}
	dataDir := filepath.Join(homeDir, ".v2rayng")
	os.MkdirAll(dataDir, 0755)
	return dataDir
}

// loadConfig loads configuration from disk
func (a *App) loadConfig() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Load server list
	listPath := filepath.Join(a.dataDir, "server_list.json")
	if data, err := os.ReadFile(listPath); err == nil {
		json.Unmarshal(data, &a.serverList)
	}

	// Load servers
	serversPath := filepath.Join(a.dataDir, "servers.json")
	if data, err := os.ReadFile(serversPath); err == nil {
		json.Unmarshal(data, &a.servers)
	}

	// Load server affiliations
	affPath := filepath.Join(a.dataDir, "server_aff.json")
	if data, err := os.ReadFile(affPath); err == nil {
		json.Unmarshal(data, &a.serverAff)
	}

	// Load subscriptions
	subPath := filepath.Join(a.dataDir, "subscriptions.json")
	if data, err := os.ReadFile(subPath); err == nil {
		json.Unmarshal(data, &a.subscriptions)
	}

	// Load selected server
	selectedPath := filepath.Join(a.dataDir, "selected.json")
	if data, err := os.ReadFile(selectedPath); err == nil {
		var selected struct {
			SelectedID string `json:"selected"`
		}
		if json.Unmarshal(data, &selected) == nil {
			a.selectedServer = selected.SelectedID
		}
	}
}

// saveConfig saves configuration to disk
func (a *App) saveConfig() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Save server list
	if data, err := json.MarshalIndent(a.serverList, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, "server_list.json"), data, 0644)
	}

	// Save servers
	if data, err := json.MarshalIndent(a.servers, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, "servers.json"), data, 0644)
	}

	// Save server affiliations
	if data, err := json.MarshalIndent(a.serverAff, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, "server_aff.json"), data, 0644)
	}

	// Save subscriptions
	if data, err := json.MarshalIndent(a.subscriptions, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, "subscriptions.json"), data, 0644)
	}

	// Save selected server
	if data, err := json.MarshalIndent(map[string]string{"selected": a.selectedServer}, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dataDir, "selected.json"), data, 0644)
	}
}

// GetServerList returns the list of server IDs
func (a *App) GetServerList() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverList
}

// GetServer returns a server configuration by ID
func (a *App) GetServer(id string) *ServerConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.servers[id]
}

// GetAllServers returns all server configurations
func (a *App) GetAllServers() map[string]*ServerConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.servers
}

// AddServer adds a new server configuration
func (a *App) AddServer(configJSON string) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var config ServerConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return ""
	}

	id := uuid.New().String()
	config.AddedTime = time.Now().UnixMilli()
	a.servers[id] = &config
	a.serverList = append([]string{id}, a.serverList...)

	if a.selectedServer == "" {
		a.selectedServer = id
	}

	a.saveConfig()
	return id
}

// RemoveServer removes a server configuration
func (a *App) RemoveServer(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.servers[id]; !exists {
		return false
	}

	delete(a.servers, id)
	delete(a.serverAff, id)

	for i, sid := range a.serverList {
		if sid == id {
			a.serverList = append(a.serverList[:i], a.serverList[i+1:]...)
			break
		}
	}

	if a.selectedServer == id {
		a.selectedServer = ""
		if len(a.serverList) > 0 {
			a.selectedServer = a.serverList[0]
		}
	}

	a.saveConfig()
	return true
}

// SelectServer selects a server
func (a *App) SelectServer(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.servers[id]; !exists {
		return false
	}

	a.selectedServer = id
	a.saveConfig()
	return true
}

// GetSelectedServer returns the selected server ID
func (a *App) GetSelectedServer() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.selectedServer
}

// UpdateServerRemarks updates server remarks
func (a *App) UpdateServerRemarks(id, remarks string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if config, exists := a.servers[id]; exists {
		config.Remarks = remarks
		a.saveConfig()
		return true
	}
	return false
}

// ParseVMessURL parses a VMess URL
func (a *App) ParseVMessURL(vmessURL string) *ServerConfig {
	if !strings.HasPrefix(vmessURL, "vmess://") {
		return nil
	}

	data := strings.TrimPrefix(vmessURL, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}

	var qr VmessQRCode
	if err := json.Unmarshal(decoded, &qr); err != nil {
		return nil
	}

	config := CreateVMessConfig()
	config.Remarks = qr.Ps
	config.OutboundBean.Settings.Vnext[0].Address = qr.Add
	config.OutboundBean.Settings.Vnext[0].Port, _ = strconv.Atoi(qr.Port)
	config.OutboundBean.Settings.Vnext[0].Users[0].ID = qr.ID
	config.OutboundBean.Settings.Vnext[0].Users[0].AlterID, _ = strconv.Atoi(qr.Aid)
	config.OutboundBean.Settings.Vnext[0].Users[0].Security = qr.Scy

	stream := config.OutboundBean.StreamSettings
	stream.Network = qr.Net
	if qr.Net == "ws" {
		stream.WSSettings = &WSSettingsBean{
			Path: qr.Path,
			Headers: map[string]string{"Host": qr.Host},
		}
	} else if qr.Net == "grpc" {
		stream.GRPCSettings = &GRPCSettingsBean{
			ServiceName: qr.Path,
		}
	}

	if qr.TLS == "tls" {
		stream.Security = "tls"
		stream.TLSSettings = &TLSSettingsBean{
			ServerName: qr.Sni,
		}
	}

	return config
}

// ImportFromClipboard imports configuration from clipboard
func (a *App) ImportFromClipboard() string {
	clipboard, err := runtime.ClipboardGetText(a.ctx)
	if err != nil {
		return ""
	}
	return clipboard
}

// ImportConfig imports configuration from text
func (a *App) ImportConfig(configText string) int {
	count := 0
	lines := strings.Split(configText, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var config *ServerConfig
		if strings.HasPrefix(line, "vmess://") {
			config = a.ParseVMessURL(line)
		} else if strings.HasPrefix(line, "vless://") {
			config = a.ParseVLessURL(line)
		} else if strings.HasPrefix(line, "trojan://") {
			config = a.ParseTrojanURL(line)
		} else if strings.HasPrefix(line, "ss://") {
			config = a.ParseShadowsocksURL(line)
		}

		if config != nil {
			a.AddServer(marshalConfig(config))
			count++
		}
	}

	return count
}

// ParseVLessURL parses a VLESS URL
func (a *App) ParseVLessURL(vlessURL string) *ServerConfig {
	u, err := url.Parse(vlessURL)
	if err != nil || u.Scheme != "vless" {
		return nil
	}

	config := CreateVLESSConfig()
	config.Remarks = u.Fragment
	config.OutboundBean.Settings.Vnext[0].Address = u.Hostname()
	config.OutboundBean.Settings.Vnext[0].Port, _ = strconv.Atoi(u.Port())
	config.OutboundBean.Settings.Vnext[0].Users[0].ID = u.User.Username()

	query := u.Query()
	config.OutboundBean.StreamSettings.Network = query.Get("type")
	
	if query.Get("security") == "tls" || query.Get("security") == "reality" {
		config.OutboundBean.StreamSettings.Security = query.Get("security")
		config.OutboundBean.StreamSettings.TLSSettings = &TLSSettingsBean{
			ServerName: query.Get("sni"),
		}
	}

	return config
}

// ParseTrojanURL parses a Trojan URL
func (a *App) ParseTrojanURL(trojanURL string) *ServerConfig {
	u, err := url.Parse(trojanURL)
	if err != nil || u.Scheme != "trojan" {
		return nil
	}

	config := CreateTrojanConfig()
	config.Remarks = u.Fragment
	config.OutboundBean.Settings.Servers[0].Address = u.Hostname()
	config.OutboundBean.Settings.Servers[0].Port, _ = strconv.Atoi(u.Port())
	config.OutboundBean.Settings.Servers[0].Password = u.User.Username()

	query := u.Query()
	config.OutboundBean.StreamSettings.Network = query.Get("type")
	if query.Get("security") == "tls" {
		config.OutboundBean.StreamSettings.Security = "tls"
		config.OutboundBean.StreamSettings.TLSSettings = &TLSSettingsBean{
			ServerName: query.Get("sni"),
		}
	}

	return config
}

// ParseShadowsocksURL parses a Shadowsocks URL
func (a *App) ParseShadowsocksURL(ssURL string) *ServerConfig {
	u, err := url.Parse(ssURL)
	if err != nil || u.Scheme != "ss" {
		return nil
	}

	config := CreateShadowsocksConfig()
	config.Remarks = u.Fragment
	
	userInfo := u.User.String()
	if decoded, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			config.OutboundBean.Settings.Servers[0].Method = parts[0]
			config.OutboundBean.Settings.Servers[0].Password = parts[1]
		}
	}

	config.OutboundBean.Settings.Servers[0].Address = u.Hostname()
	config.OutboundBean.Settings.Servers[0].Port, _ = strconv.Atoi(u.Port())

	return config
}

// TestServerDelay tests server delay
func (a *App) TestServerDelay(id string) int64 {
	a.mu.RLock()
	config := a.servers[id]
	a.mu.RUnlock()

	if config == nil {
		return -1
	}

	start := time.Now()
	// Simple TCP connection test would go here
	// For now, return simulated delay
	time.Sleep(100 * time.Millisecond)
	delay := time.Since(start).Milliseconds()

	a.mu.Lock()
	if _, exists := a.serverAff[id]; !exists {
		a.serverAff[id] = &ServerAffiliationInfo{}
	}
	a.serverAff[id].TestDelayMillis = delay
	a.serverAff[id].TestTime = time.Now().UnixMilli()
	a.saveConfig()
	a.mu.Unlock()

	return delay
}

// GetAppStatus returns current app status
func (a *App) GetAppStatus() *AppStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := &AppStatus{
		SelectedID:  a.selectedServer,
		ConnectionState: "disconnected",
	}

	if a.selectedServer != "" {
		if config, exists := a.servers[a.selectedServer]; exists {
			status.Remarks = config.Remarks
		}
	}

	return status
}

// GetSubscriptions returns all subscriptions
func (a *App) GetSubscriptions() map[string]*SubscriptionItem {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.subscriptions
}

// AddSubscription adds a new subscription
func (a *App) AddSubscription(remarks, url string) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	id := uuid.New().String()
	a.subscriptions[id] = &SubscriptionItem{
		Remarks:   remarks,
		URL:       url,
		Enabled:   true,
		AddedTime: time.Now().UnixMilli(),
	}

	a.saveConfig()
	return id
}

// RemoveSubscription removes a subscription
func (a *App) RemoveSubscription(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.subscriptions[id]; !exists {
		return false
	}

	delete(a.subscriptions, id)
	a.saveConfig()
	return true
}

// UpdateSubscription updates subscription
func (a *App) UpdateSubscription(id, remarks, url string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if sub, exists := a.subscriptions[id]; exists {
		sub.Remarks = remarks
		sub.URL = url
		a.saveConfig()
		return true
	}
	return false
}

// SortByTestResults sorts servers by test results
func (a *App) SortByTestResults() {
	a.mu.Lock()
	defer a.mu.Unlock()

	type ServerDelay struct {
		GUID string
		Delay int64
	}

	delays := make([]ServerDelay, 0, len(a.serverList))
	for _, guid := range a.serverList {
		delay := int64(999999)
		if aff, exists := a.serverAff[guid]; exists && aff.TestDelayMillis > 0 {
			delay = aff.TestDelayMillis
		}
		delays = append(delays, ServerDelay{GUID: guid, Delay: delay})
	}

	sort.Slice(delays, func(i, j int) bool {
		return delays[i].Delay < delays[j].Delay
	})

	sortedList := make([]string, len(delays))
	for i, d := range delays {
		sortedList[i] = d.GUID
	}
	a.serverList = sortedList
	a.saveConfig()
}

// ClearTestResults clears all test results
func (a *App) ClearTestResults() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for guid := range a.serverAff {
		a.serverAff[guid].TestDelayMillis = 0
	}
	a.saveConfig()
}

// ExportConfig exports configuration as JSON
func (a *App) ExportConfig(id string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if config, exists := a.servers[id]; exists {
		if data, err := json.MarshalIndent(config, "", "  "); err == nil {
			return string(data)
		}
	}
	return ""
}

// ExportAllConfigs exports all configurations
func (a *App) ExportAllConfigs() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if data, err := json.MarshalIndent(a.servers, "", "  "); err == nil {
		return string(data)
	}
	return ""
}

// GetVersion returns app version
func (a *App) GetVersion() string {
	return "1.0.0"
}

// Helper functions to create configs
func CreateVMessConfig() *ServerConfig {
	return &ServerConfig{
		ConfigVersion: 3,
		ConfigType:    EConfigTypeVMESS,
		OutboundBean: &OutboundBean{
			Protocol: "vmess",
			Tag:      "proxy",
			Settings: &OutSettingsBean{
				Vnext: []VnextBean{{
					Users: []UsersBean{{
						Security: "auto",
						Level:    8,
					}},
				}},
			},
			StreamSettings: &StreamSettingsBean{
				Network: "tcp",
			},
			Mux: &MuxBean{Enabled: false},
		},
	}
}

func CreateVLESSConfig() *ServerConfig {
	return &ServerConfig{
		ConfigVersion: 3,
		ConfigType:    EConfigTypeVLESS,
		OutboundBean: &OutboundBean{
			Protocol: "vless",
			Tag:      "proxy",
			Settings: &OutSettingsBean{
				Vnext: []VnextBean{{
					Users: []UsersBean{{
						Flow:     "",
						Level:    8,
					}},
				}},
			},
			StreamSettings: &StreamSettingsBean{
				Network: "tcp",
			},
		},
	}
}

func CreateTrojanConfig() *ServerConfig {
	return &ServerConfig{
		ConfigVersion: 3,
		ConfigType:    EConfigTypeTROJAN,
		OutboundBean: &OutboundBean{
			Protocol: "trojan",
			Tag:      "proxy",
			Settings: &OutSettingsBean{
				Servers: []ServersBean{{
					Level: 8,
				}},
			},
			StreamSettings: &StreamSettingsBean{
				Network: "tcp",
				Security: "tls",
			},
		},
	}
}

func CreateShadowsocksConfig() *ServerConfig {
	return &ServerConfig{
		ConfigVersion: 3,
		ConfigType:    EConfigTypeSHADOWSOCKS,
		OutboundBean: &OutboundBean{
			Protocol: "shadowsocks",
			Tag:      "proxy",
			Settings: &OutSettingsBean{
				Servers: []ServersBean{{
					Level: 8,
				}},
			},
		},
	}
}

func marshalConfig(config *ServerConfig) string {
	if data, err := json.Marshal(config); err == nil {
		return string(data)
	}
	return ""
}
