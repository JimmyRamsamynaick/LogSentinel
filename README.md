# 🕵️‍♂️ LogSentinel

<div align="center">
  <h3>Surveillance de logs en temps réel avec système d'alertes intelligent</h3>
  
  ![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go)
  ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
  ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)
</div>

## 🎯 Description

LogSentinel est un outil puissant développé en Go qui surveille en temps réel les fichiers de logs de votre système, détecte des motifs spécifiques et envoie des alertes via différents canaux de notification.

## ✨ Fonctionnalités Principales

### 🔍 Surveillance en Temps Réel
- Surveillance simultanée de plusieurs fichiers de logs
- Détection automatique des nouveaux logs (comme `tail -f`)
- Support des rotations de logs
- Performance optimisée avec goroutines

### 🎯 Détection de Motifs Intelligente
- Expressions régulières personnalisables
- Motifs prédéfinis (erreurs, tentatives de connexion, etc.)
- Filtrage par niveau de sévérité
- Groupement d'alertes pour éviter le spam

### 📢 Système d'Alertes Multi-Canal
- **Console** : Affichage coloré en temps réel
- **Email** : Notifications par SMTP
- **Webhook** : Intégration avec Slack, Discord, etc.
- **Desktop** : Notifications système natives

### 📊 Historique et Reporting
- Stockage local des alertes (JSON/SQLite)
- Statistiques de détection
- Export des rapports
- Dashboard web en temps réel

### ⚙️ Interface CLI Intuitive
- Configuration interactive des règles
- Gestion des canaux d'alerte
- Mode daemon pour exécution en arrière-plan
- Hot-reload de la configuration

## 🚀 Installation Rapide

```bash
# Cloner le repository
git clone https://github.com/JimmyRamsamynaick/LogSentinel.git
cd LogSentinel

# Compiler
go build -o logsentinel ./cmd/logsentinel

# Installer globalement (optionnel)
go install ./cmd/logsentinel
```

## 📖 Utilisation

### Démarrage Rapide

```bash
# Surveiller un fichier avec motifs par défaut
./logsentinel watch /var/log/syslog

# Configuration interactive
./logsentinel config

# Démarrer en mode daemon
./logsentinel daemon --config config.yaml
```

### Configuration Avancée

```yaml
# config.yaml
logs:
  - path: "/var/log/syslog"
    patterns:
      - name: "errors"
        regex: "ERROR|CRITICAL|FATAL"
        severity: "high"
      - name: "failed_login"
        regex: "Failed password|authentication failure"
        severity: "medium"

alerts:
  console:
    enabled: true
    colors: true
  email:
    enabled: true
    smtp_server: "smtp.gmail.com:587"
    from: "alerts@example.com"
    to: ["admin@example.com"]
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/..."
```

## 🛠️ Concepts Go Explorés

- **Goroutines & Channels** : Surveillance concurrente de multiples fichiers
- **Regexp** : Détection de motifs complexes
- **File Streaming** : Lecture continue comme `tail -f`
- **Net/SMTP** : Envoi d'emails natif
- **HTTP Client** : Webhooks et API REST
- **Architecture Modulaire** : Code maintenable et extensible

## 🌟 Fonctionnalités Bonus

### 🌐 Interface Web (WebSocket)
```bash
./logsentinel web --port 8080
```
Accédez à `http://localhost:8080` pour voir les alertes en direct.

### 🔌 API REST
```bash
# Ajouter une règle via API
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{"name":"custom","regex":"CUSTOM_ERROR","severity":"high"}'
```

### 🖥️ Notifications Desktop
Support natif des notifications système sur Linux, macOS et Windows.

## 📁 Structure du Projet

```
LogSentinel/
├── cmd/
│   └── logsentinel/          # Point d'entrée CLI
├── internal/
│   ├── watcher/              # Surveillance de fichiers
│   ├── detector/             # Détection de motifs
│   ├── alerter/              # Système d'alertes
│   ├── storage/              # Persistance des données
│   └── web/                  # Interface web
├── pkg/
│   └── config/               # Configuration
├── web/
│   ├── static/               # Assets web
│   └── templates/            # Templates HTML
├── configs/
│   └── examples/             # Configurations d'exemple
└── docs/                     # Documentation
```

## 🧪 Tests et Exemples

```bash
# Lancer les tests
go test ./...

# Test avec fichier d'exemple
echo "ERROR: Test error message" >> test.log
./logsentinel watch test.log
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour plus d'informations.

## 📄 License

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

## 👨‍💻 Auteur

**Jimmy Ramsamynaick**
- GitHub: [@JimmyRamsamynaick](https://github.com/JimmyRamsamynaick)
- Email: jimmyramsamynaick@gmail.com

---

<div align="center">
  <strong>⭐ N'hésitez pas à donner une étoile si ce projet vous est utile !</strong>
</div>