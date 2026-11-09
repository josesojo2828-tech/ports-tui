// Package client es el cliente HTTPS que usa la TUI para hablar con el daemon.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/josesojo2828-tech/ports-tui/internal/audit"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// Client habla con la API del daemon.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New construye un cliente.
//
// caCert apunta al certificado auto-firmado del daemon y actúa como raíz de
// confianza, lo que fija su identidad. Si insecure es true se omite la
// validación (solo para pruebas).
func New(baseURL, token, caCert string, insecure bool) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("la URL del servidor está vacía")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("no hay token de autenticación configurado")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsConfig.InsecureSkipVerify = true
	} else if caCert != "" {
		pem, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("no se pudo leer el certificado %s: %w", caCert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("el certificado %s no es válido como raíz de confianza", caCert)
		}
		tlsConfig.RootCAs = pool
	}

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// BaseURL devuelve la URL base del daemon.
func (c *Client) BaseURL() string { return c.baseURL }

// do ejecuta una petición autenticada y decodifica la respuesta.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("no se pudo contactar con el daemon en %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &payload) == nil && payload.Error != "" {
			return fmt.Errorf("%s", payload.Error)
		}
		return fmt.Errorf("el daemon respondió %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("respuesta inválida del daemon: %w", err)
	}
	return nil
}

// Health comprueba que el daemon responde.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/api/v1/health", nil, nil)
}

// Snapshot descarga el estado completo.
func (c *Client) Snapshot(ctx context.Context) (*firewall.Snapshot, error) {
	var snapshot firewall.Snapshot
	if err := c.do(ctx, http.MethodGet, "/api/v1/snapshot", nil, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// Status descarga el estado del firewall y sus métricas.
func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	var payload map[string]any
	if err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// Rules descarga las reglas de UFW.
func (c *Client) Rules(ctx context.Context) ([]ufw.Rule, error) {
	var payload struct {
		Rules []ufw.Rule `json:"rules"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/rules", nil, &payload); err != nil {
		return nil, err
	}
	return payload.Rules, nil
}

// AddRule crea una regla nueva.
func (c *Client) AddRule(ctx context.Context, spec ufw.Spec) error {
	body := map[string]string{
		"port":    spec.Port,
		"proto":   spec.Proto,
		"from":    spec.From,
		"action":  spec.Action,
		"comment": spec.Comment,
	}
	return c.do(ctx, http.MethodPost, "/api/v1/rules", body, nil)
}

// DeleteRule elimina una regla por número.
func (c *Client) DeleteRule(ctx context.Context, number int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/rules/%d", number), nil, nil)
}

// SetRuleEnabled habilita o deshabilita una regla.
func (c *Client) SetRuleEnabled(ctx context.Context, number int, enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/rules/%d/%s", number, action), nil, nil)
}

// SetFirewallEnabled habilita o deshabilita el firewall completo.
func (c *Client) SetFirewallEnabled(ctx context.Context, enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	return c.do(ctx, http.MethodPost, "/api/v1/ufw/"+action, nil, nil)
}

// Reload recarga las reglas de UFW.
func (c *Client) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/ufw/reload", nil, nil)
}

// Audit descarga las últimas acciones registradas.
func (c *Client) Audit(ctx context.Context, limit int) ([]audit.Entry, error) {
	var payload struct {
		Entries []audit.Entry `json:"entries"`
	}
	path := "/api/v1/audit"
	if limit > 0 {
		path = fmt.Sprintf("%s?limit=%d", path, limit)
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}
	return payload.Entries, nil
}
