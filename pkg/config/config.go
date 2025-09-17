package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config représente la configuration complète de LogSentinel
type Config struct {
	Logs    []LogConfig   `json:"logs" yaml:"logs"`
	Alerts  AlertsConfig  `json:"alerts" yaml:"alerts"`
	Storage StorageConfig `json:"storage" yaml:"storage"`
	Web     WebConfig     `json:"web" yaml:"web"`
}

// LogConfig représente la configuration d'un fichier de log
type LogConfig struct {
	Path     string    `json:"path" yaml:"path"`
	Patterns []Pattern `json:"patterns" yaml:"patterns"`
	Enabled  bool      `json:"enabled" yaml:"enabled"`
}

// Pattern représente un motif à détecter
type Pattern struct {
	Name     string `json:"name" yaml:"name"`
	Regex    string `json:"regex" yaml:"regex"`
	Severity string `json:"severity" yaml:"severity"` // low, medium, high, critical
	Enabled  bool   `json:"enabled" yaml:"enabled"`
}

// AlertsConfig représente la configuration des alertes
type AlertsConfig struct {
	Console ConsoleConfig `json:"console" yaml:"console"`
	Email   EmailConfig   `json:"email" yaml:"email"`
	Webhook WebhookConfig `json:"webhook" yaml:"webhook"`
}

// ConsoleConfig représente la configuration des alertes console
type ConsoleConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	Colors  bool `json:"colors" yaml:"colors"`
}

// EmailConfig représente la configuration des alertes email
type EmailConfig struct {
	Enabled    bool     `json:"enabled" yaml:"enabled"`
	SMTPServer string   `json:"smtp_server" yaml:"smtp_server"`
	Port       int      `json:"port" yaml:"port"`
	Username   string   `json:"username" yaml:"username"`
	Password   string   `json:"password" yaml:"password"`
	From       string   `json:"from" yaml:"from"`
	To         []string `json:"to" yaml:"to"`
	TLS        bool     `json:"tls" yaml:"tls"`
}

// WebhookConfig représente la configuration des webhooks
type WebhookConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	URL     string `json:"url" yaml:"url"`
	Method  string `json:"method" yaml:"method"`
	Headers map[string]string `json:"headers" yaml:"headers"`
}

// StorageConfig représente la configuration du stockage
type StorageConfig struct {
	Type     string `json:"type" yaml:"type"` // json, sqlite
	Path     string `json:"path" yaml:"path"`
	MaxSize  int64  `json:"max_size" yaml:"max_size"`   // en MB
	MaxAge   int    `json:"max_age" yaml:"max_age"`     // en jours
	Compress bool   `json:"compress" yaml:"compress"`
}

// WebConfig représente la configuration de l'interface web
type WebConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Port    int    `json:"port" yaml:"port"`
	Host    string `json:"host" yaml:"host"`
}

// DefaultConfig retourne une configuration par défaut
func DefaultConfig() *Config {
	return &Config{
		Logs: []LogConfig{},
		Alerts: AlertsConfig{
			Console: ConsoleConfig{
				Enabled: true,
				Colors:  true,
			},
			Email: EmailConfig{
				Enabled: false,
				Port:    587,
				TLS:     true,
			},
			Webhook: WebhookConfig{
				Enabled: false,
				Method:  "POST",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
		Storage: StorageConfig{
			Type:     "json",
			Path:     "alerts.json",
			MaxSize:  100, // 100MB
			MaxAge:   30,  // 30 jours
			Compress: true,
		},
		Web: WebConfig{
			Enabled: false,
			Port:    8080,
			Host:    "localhost",
		},
	}
}

// LoadConfig charge la configuration depuis un fichier
func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier de configuration: %w", err)
	}

	var config Config
	ext := filepath.Ext(path)
	
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("erreur lors du parsing JSON: %w", err)
		}
	case ".yaml", ".yml":
		// TODO: Implémenter le support YAML
		return nil, fmt.Errorf("support YAML pas encore implémenté")
	default:
		return nil, fmt.Errorf("format de fichier non supporté: %s", ext)
	}

	return &config, nil
}

// SaveConfig sauvegarde la configuration dans un fichier
func (c *Config) SaveConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur lors de la sérialisation: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier: %w", err)
	}

	return nil
}

// Validate valide la configuration
func (c *Config) Validate() error {
	if len(c.Logs) == 0 {
		return fmt.Errorf("aucun fichier de log configuré")
	}

	for i, log := range c.Logs {
		if log.Path == "" {
			return fmt.Errorf("chemin du fichier de log %d non spécifié", i)
		}
		
		if len(log.Patterns) == 0 {
			return fmt.Errorf("aucun motif configuré pour le fichier %s", log.Path)
		}

		for j, pattern := range log.Patterns {
			if pattern.Regex == "" {
				return fmt.Errorf("regex vide pour le motif %d du fichier %s", j, log.Path)
			}
		}
	}

	return nil
}