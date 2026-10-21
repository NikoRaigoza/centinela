#!/usr/bin/env bash
# Prepara un servidor Ubuntu 24.04 recién creado para correr Centinela. Se ejecuta UNA vez, como el usuario
# administrador de la VM (no como root):
#   curl -fsSL https://raw.githubusercontent.com/<tu-usuario>/<tu-repo>/main/despliegue/preparar_servidor.sh | bash
#   (o copiándolo con scp y ejecutando: bash preparar_servidor.sh)
#
# Qué hace: actualizaciones automáticas de seguridad, cortafuegos (solo 22, 80 y 443), fail2ban contra ataques de
# fuerza bruta a SSH, SSH solo con llave, 2 GB de swap (la VM gratuita tiene 1 GB de RAM), Docker oficial y la
# carpeta /opt/centinela.
set -euo pipefail
[ "$(id -u)" -eq 0 ] && { echo "Ejecútalo con tu usuario normal (usa sudo por dentro), no como root."; exit 1; }

echo "==> Actualizando el sistema"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl git ufw fail2ban unattended-upgrades

echo "==> Actualizaciones de seguridad automáticas"
sudo dpkg-reconfigure -f noninteractive unattended-upgrades

echo "==> Cortafuegos: solo SSH, HTTP y HTTPS"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw --force enable

echo "==> SSH: solo con llave, sin contraseña ni root"
sudo tee /etc/ssh/sshd_config.d/90-centinela.conf > /dev/null <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
CONF
sudo systemctl reload ssh || sudo systemctl reload sshd
sudo systemctl enable --now fail2ban

echo "==> Memoria de intercambio (swap) de 2 GB"
if ! swapon --show | grep -q /swapfile; then
    sudo fallocate -l 2G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile > /dev/null
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
    echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/90-centinela.conf > /dev/null
    sudo sysctl -q --system
fi

echo "==> Docker (repositorio oficial)"
if ! command -v docker > /dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc
    # shellcheck source=/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker

echo "==> Carpeta del proyecto"
sudo mkdir -p /opt/centinela
sudo chown "$USER":"$USER" /opt/centinela

echo
echo "Listo. Cierra la sesión SSH y vuelve a entrar (para usar docker sin sudo) y sigue con despliegue/README.md (paso 6)."
