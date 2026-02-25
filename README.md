# proxy2

HTTP/HTTPS proxy in a single Python script – now with **Python 3.13+** and **Windows 11** support!

## Features

* Easy to customize – override `request_handler`, `response_handler`, `save_handler`
* No external Python modules required (only OpenSSL for HTTPS intercept)
* Supports IPv4 and IPv6
* HTTP/1.1 persistent connections
* Dynamic certificate generation for HTTPS interception
* **Enhanced console output** – live request viewer with colours, client IP, timing, size
* **Optional JSONL logging** – for integration with log analyzers
* **Windows ANSI colours** – works in PowerShell, cmd, Windows Terminal
* **Backward compatible** – your old Python 2 custom handlers still work!

## Requirements

- Python 3.13 or newer
- OpenSSL command line tool (for HTTPS intercept) – [Download for Windows](https://slproweb.com/products/Win32OpenSSL.html)

## Usage

```bash
# Basic HTTP proxy on port 8080
python proxy2.py

# Custom port and bind address
python proxy2.py --port 3128 --bind 127.0.0.1

# HTTPS intercept mode (client → proxy over SSL)
python proxy2.py --https-proxy --port 8443

# Enable verbose logging and file output
python proxy2.py --verbose --log-file proxy.log
```

Test with curl:
```bash
curl --proxy localhost:8080 http://example.com/
curl --proxy localhost:8080 https://example.com/   # if HTTPS intercept enabled
```

## Enable HTTPS Intercept

### Windows (PowerShell)
```powershell
.\setup_https_intercept.ps1
```

### Linux/macOS
```bash
chmod +x setup_https_intercept.sh
./setup_https_intercept.sh
```

Then visit **http://proxy2.test/** in your browser to download and install the CA certificate.

## Command Line Options

| Argument           | Description                                      |
|--------------------|--------------------------------------------------|
| `-p, --port`       | Port to listen on (default: 8080)               |
| `-b, --bind`       | Bind address (default: `""` – all interfaces)   |
| `--https-proxy`    | Run as **HTTPS proxy** (client→proxy SSL)       |
| `--log-file`       | Append JSONL logs to this file                  |
| `--no-color`       | Disable ANSI colours (for logging to file)      |
| `--verbose`        | Show full headers and body preview              |

## Customization Examples

The `examples/` folder contains ready‑to‑use custom proxies:

| Example        | Description                                      |
|----------------|--------------------------------------------------|
| `uachanger.py` | Change User‑Agent to Internet Explorer 5.01     |
| `sslstrip.py`  | Convert HTTPS links to HTTP (SSL stripping)     |
| `redirector.py`| Rewrite specific URLs (add your own rules)      |

Simply run:
```bash
python examples/uachanger.py --port 8000
```

## ✅ Windows'ta Test Etme

```powershell
# 1. Sertifikaları oluştur (bir kere)
.\setup_https_intercept.ps1

# 2. Proxy'yi başlat
python proxy2.py --port 8888 --verbose

# 3. Ayrı bir terminalde örnekleri çalıştır
python examples\uachanger.py --port 8000
python examples\sslstrip.py --port 8001
python examples\redirector.py --port 8002

# 4. Curl ile test et
curl --proxy localhost:8888 http://example.com/
curl --proxy localhost:8000 http://example.com/   # UA değişmiş
curl --proxy localhost:8001 https://example.com/  # SSL strip
curl --proxy localhost:8002 http://google.com/    # example.com'a yönlendirir
```

---

## 📦 Özet

| Dosya                          | Açıklama                                  |
|--------------------------------|-------------------------------------------|
| `proxy2.py`                    | Ana proxy – Python 3, Windows ANSI, log   |
| `setup_https_intercept.ps1`    | Windows için sertifika oluşturma scripti  |
| `https_trasparent.py`          | Eski HTTPS proxy server (opsiyonel)       |
| `examples/uachanger.py`        | User-Agent değiştirme örneği              |
| `examples/sslstrip.py`         | HTTPS → HTTP dönüştürücü                  |
| `examples/redirector.py`       | URL yeniden yazma / engelleme örneği      |
| `examples/proxy2.py`           | examples/ içinden ana proxy'yi çağırır    |

---

## ☕ Destek Olun / Support

Projemi beğendiyseniz, bana bir kahve ısmarlayarak destek olabilirsiniz!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/metatronslove)

Teşekkürler! 🙏
