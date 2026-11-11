# HackBeast — sandboxed runtime image.
#
# Bundles the recon/fuzz tooling (subfinder, httpx, nuclei, ffuf — Go-based,
# via ProjectDiscovery; nmap, sqlmap, nikto via apt) plus a headless Chromium
# for the Playwright browser checks, so you don't have to install any of
# this by hand on your host. Running the agent inside this container also
# means its scans and any tool it shells out to are isolated from your real
# machine's filesystem/network namespace.
#
# Build:
#   docker compose build
# Run (GUI at http://127.0.0.1:5000):
#   docker compose up
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    WEB_HOST=0.0.0.0

# --- OS-level pentest tools -------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        nikto \
        ffuf \
        curl \
        git \
        ca-certificates \
        wget \
        gnupg \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# --- Go toolchain (for subfinder / httpx / nuclei) --------------------------
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:${GOPATH}/bin"
RUN ARCH="$(dpkg --print-architecture)" && \
    case "$ARCH" in \
        amd64) GOARCH=amd64 ;; \
        arm64) GOARCH=arm64 ;; \
        *) GOARCH=amd64 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go1.23.2.linux-${GOARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    nuclei -update-templates || true

# --- Wordlists (for ffuf) ---------------------------------------------------
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -fsSL "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" \
        -o /usr/share/wordlists/dirb/common.txt || \
    echo "admin" > /usr/share/wordlists/dirb/common.txt

# --- Python deps + Playwright's Chromium -----------------------------------
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install -r requirements.txt && \
    python -m playwright install --with-deps chromium

COPY . .

RUN mkdir -p /app/outputs

EXPOSE 5000

# Launching webapp.py directly (not main.py) so the container starts the
# GUI immediately without needing an interactive "name your agent" prompt;
# set AGENT_NAME in .env or docker-compose.yml to brand it.
CMD ["python", "webapp.py"]
