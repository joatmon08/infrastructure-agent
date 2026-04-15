#!/bin/sh
set -e

echo "Starting Vault plugin loader..."

# Plugin directory
PLUGIN_DIR="/vault/plugins"

# Ensure plugin directory exists and has correct permissions
mkdir -p "$${PLUGIN_DIR}"
chmod 755 "$${PLUGIN_DIR}"

# Function to download and verify plugin
download_plugin() {
  local plugin_name=$1
  local plugin_url=$2
  local plugin_sha256=$3
  
  echo "Downloading plugin: $${plugin_name}"
  

  wget --output-document=$${PLUGIN_DIR}/$${plugin_name} $${plugin_url}
  
  # Verify SHA256 checksum if provided
  if [ -n "$${plugin_sha256}" ]; then
    echo "Verifying checksum for $${plugin_name}..."
    echo "$${plugin_sha256}  $${PLUGIN_DIR}/$${plugin_name}" | sha256sum -c -
  fi
  
  # Make plugin executable
  chmod +x "$${PLUGIN_DIR}/$${plugin_name}"
  
  echo "Successfully loaded plugin: $${plugin_name}"
}

# Download plugins from configuration
%{ for plugin in PLUGINS ~}
download_plugin "${plugin.name}" "${plugin.url}" "${plugin.sha256}"
%{ endfor ~}

# List all plugins
echo "Plugins in $${PLUGIN_DIR}:"
ls -lh "$${PLUGIN_DIR}"

echo "Plugin loading complete!"