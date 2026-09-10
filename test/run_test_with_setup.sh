#!/bin/bash
# Pre-create /etc/ directories required by phosphor-networkd production code.
#
# The Manager and DnsUpdater constructors unconditionally attempt to create
# these hardcoded paths at startup (src/network_manager.cpp, src/dns_updater.cpp,
# src/firewall_configuration.hpp). Tests run as a non-root user, so we use
# passwordless sudo (configured in the CI Docker image) to create them once.
#
# Falls back gracefully if sudo is unavailable (e.g. local non-Docker builds).
#
# After setup this script exec's run_with_tmp, which manages per-test TMPDIR
# as required by the meson 'networkd' test setup.
#
# All phosphor-networkd test binaries share /var/channel_intf_data.json.
# Meson runs tests in parallel, so we hold an exclusive flock for the entire
# binary run to prevent concurrent read/write races on that file.

set -euo pipefail

readonly REQUIRED_DIRS=(
    /etc/dns.d
    /etc/arpcontrol
    /etc/interface/iptables
    /etc/interface/bonding
    /etc/iptables
    /etc/systemd/network
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        if sudo -n mkdir -p "$dir" 2>/dev/null; then
            sudo -n chmod 777 "$dir" 2>/dev/null || true
        fi
    fi
done

# /var/channel_intf_data.json is written by EthernetInterface constructor
# (getChannelPrivilege -> writeJsonFile). Always reset it to valid empty JSON
# before each test binary so readJsonFile() returns a proper object (not a
# discarded value from an empty/corrupted file) and operator[] does not throw
# json.exception.type_error.305.
#
# Use flock(1) to serialize all test binaries that share this file.
# The lock file itself is harmless; flock releases it when the binary exits.
readonly LOCK_FILE=/tmp/phosphor-networkd-channel-json.lock
sudo -n bash -c 'echo "{}" > /var/channel_intf_data.json && chmod 666 /var/channel_intf_data.json' 2>/dev/null || \
    bash -c 'echo "{}" > /var/channel_intf_data.json' 2>/dev/null || true

# Disable MALLOC_PERTURB_ as a defensive measure.  With certain byte values,
# heap perturbation can expose latent use-after-free or uninitialized-memory
# bugs in production code that are out of scope for test-side fixes.
export MALLOC_PERTURB_=0

exec flock "$LOCK_FILE" run_with_tmp "$@"
