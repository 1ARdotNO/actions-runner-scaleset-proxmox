package provisioner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeffresc/actions-runner-scaleset-proxmox/internal/config"
	"github.com/jeffresc/actions-runner-scaleset-proxmox/internal/testutil/fakeproxmox"
)

// These tests pin the per-clone VM firewall feature: Proxmox does not
// copy /etc/pve/firewall/<vmid>.fw on clone, so when
// proxmox.firewall.enabled is set the provisioner must (1) attach the
// security-group rule, (2) enable the VM firewall — both BEFORE the
// VM's first start — and (3) fail the whole clone when either call
// fails, so a runner that was supposed to be sandboxed never runs
// unsandboxed.

// newFirewallProvisioner builds a *pmox against the fake with the
// firewall block enabled. The client is unaffected by cfg.Firewall so
// mutating it after newTestProvisioner is safe.
func newFirewallProvisioner(t *testing.T, fp *fakeproxmox.Server, fw config.FirewallConfig) *pmox {
	t.Helper()
	p := newTestProvisioner(t, fp.Server, "pve1")
	p.cfg.Firewall = fw
	return p
}

// findVM plucks one VM out of the fake's snapshot by VMID.
func findVM(t *testing.T, fp *fakeproxmox.Server, vmid int) fakeproxmox.VMSnapshot {
	t.Helper()
	for _, v := range fp.Snapshot() {
		if v.VMID == vmid {
			return v
		}
	}
	t.Fatalf("vm %d not found in fake snapshot", vmid)
	return fakeproxmox.VMSnapshot{}
}

// TestClone_FirewallAppliedBeforeFirstStart: a hot-fill clone
// (PoweredOn=true starts the VM inside Clone) must have the group rule
// and the enable+dhcp options recorded BEFORE its first qmstart.
func TestClone_FirewallAppliedBeforeFirstStart(t *testing.T) {
	t.Parallel()
	fp := fakeproxmox.New(t, fakeproxmox.Options{})
	p := newFirewallProvisioner(t, fp, config.FirewallConfig{
		Enabled:       true,
		SecurityGroup: "gh-runner",
	})

	vm, err := p.Clone(context.Background(), CloneOptions{
		NewVMID: 10042, Node: "pve1", Name: "gh-runner-test-10042", PoweredOn: true,
	})
	require.NoError(t, err)

	got := findVM(t, fp, vm.VMID)
	require.Equal(t, []fakeproxmox.FirewallRuleRecord{
		{Type: "group", Action: "gh-runner", Enable: 1},
	}, got.FirewallRules, "exactly one security-group rule must be attached")
	require.EqualValues(t, 1, got.FirewallOptions["enable"], "vm firewall must be enabled")
	require.EqualValues(t, 1, got.FirewallOptions["dhcp"], "dhcp defaults true → wire value 1")
	require.True(t, got.Running)
	require.True(t, got.EverStarted)
	require.True(t, got.FirewallActiveAtFirstStart,
		"the sandbox must be active before the VM's first boot, not applied afterwards")
}

// TestClone_FirewallDHCPFalseOmitsDhcpFlag: dhcp:false marshals to an
// omitted field (go-proxmox IntOrBool + omitempty), which is
// wire-equivalent to PVE's dhcp default 0. Enable must still land.
func TestClone_FirewallDHCPFalseOmitsDhcpFlag(t *testing.T) {
	t.Parallel()
	fp := fakeproxmox.New(t, fakeproxmox.Options{})
	dhcp := false
	p := newFirewallProvisioner(t, fp, config.FirewallConfig{
		Enabled:       true,
		SecurityGroup: "gh-runner",
		DHCP:          &dhcp,
	})

	vm, err := p.Clone(context.Background(), CloneOptions{
		NewVMID: 10043, Node: "pve1", Name: "gh-runner-test-10043",
	})
	require.NoError(t, err)

	got := findVM(t, fp, vm.VMID)
	require.EqualValues(t, 1, got.FirewallOptions["enable"])
	require.NotContains(t, got.FirewallOptions, "dhcp",
		"dhcp:false is sent as an omitted field (PVE default 0)")
}

// TestClone_FirewallFailureFailsClone: when the firewall API errors the
// clone must FAIL — never warn-and-continue — and the VM must never
// have been started. The pool's existing failed-clone path then
// destroys the leftover VM.
func TestClone_FirewallFailureFailsClone(t *testing.T) {
	t.Parallel()
	fp := fakeproxmox.New(t, fakeproxmox.Options{})
	fp.InjectFault(fakeproxmox.Fault{Kind: fakeproxmox.FaultFirewallFail})
	p := newFirewallProvisioner(t, fp, config.FirewallConfig{
		Enabled:       true,
		SecurityGroup: "gh-runner",
	})

	_, err := p.Clone(context.Background(), CloneOptions{
		NewVMID: 10044, Node: "pve1", Name: "gh-runner-test-10044", PoweredOn: true,
	})
	require.Error(t, err, "a runner that was supposed to be sandboxed must not run unsandboxed")
	require.Contains(t, err.Error(), "apply firewall")

	// The clone exists in Proxmox (pool cleanup handles it) but must
	// never have booted.
	got := findVM(t, fp, 10044)
	require.False(t, got.EverStarted, "firewall failure must abort Clone before Start")
	require.False(t, got.Running)
}

// TestClone_FirewallDisabledMakesNoFirewallCalls: with the block absent
// (zero value) the clone path is byte-for-byte the pre-feature one — no
// firewall endpoints are ever touched.
func TestClone_FirewallDisabledMakesNoFirewallCalls(t *testing.T) {
	t.Parallel()
	fp := fakeproxmox.New(t, fakeproxmox.Options{})
	p := newTestProvisioner(t, fp.Server, "pve1")

	vm, err := p.Clone(context.Background(), CloneOptions{
		NewVMID: 10045, Node: "pve1", Name: "gh-runner-test-10045", PoweredOn: true,
	})
	require.NoError(t, err)

	got := findVM(t, fp, vm.VMID)
	require.Empty(t, got.FirewallRules)
	require.Nil(t, got.FirewallOptions)
	require.True(t, got.Running)
}

// TestEncodeNIC_FirewallFlagForced: a profile network override rebuilds
// net<N> from scratch, replacing the template's NIC string — so when
// the firewall feature is on, encodeNIC must re-add firewall=1 or the
// override would silently detach the VM firewall from the bridge.
func TestEncodeNIC_FirewallFlagForced(t *testing.T) {
	t.Parallel()
	require.Equal(t, "virtio,bridge=vmbr0,tag=42,firewall=1",
		encodeNIC(CloneNIC{Bridge: "vmbr0", VLANTag: 42}, true))
	require.Equal(t, "e1000,bridge=vmbr1,mtu=9000,firewall=1",
		encodeNIC(CloneNIC{Bridge: "vmbr1", MTU: 9000, Model: "e1000"}, true))
}

// TestBuildCloneConfig_NICOverridePreservesFirewallFlag: end-to-end
// through buildCloneConfig — every rebuilt net<N> option carries
// firewall=1 when the feature is enabled, and none do when disabled.
func TestBuildCloneConfig_NICOverridePreservesFirewallFlag(t *testing.T) {
	t.Parallel()
	opts := CloneOptions{
		NewVMID: 10042,
		Profile: "default",
		NICs: []CloneNIC{
			{Bridge: "vmbr0", VLANTag: 10},
			{Bridge: "vmbr1", VLANUntagged: true},
		},
	}

	on, err := buildCloneConfig("test-scaleset", opts, true)
	require.NoError(t, err)
	collected := map[string]any{}
	for _, o := range on {
		collected[o.Name] = o.Value
	}
	require.Equal(t, "virtio,bridge=vmbr0,tag=10,firewall=1", collected["net0"])
	require.Equal(t, "virtio,bridge=vmbr1,firewall=1", collected["net1"])

	off, err := buildCloneConfig("test-scaleset", opts, false)
	require.NoError(t, err)
	for _, o := range off {
		if o.Name == "net0" || o.Name == "net1" {
			require.NotContains(t, o.Value.(string), "firewall",
				"disabled feature must not inject the flag (%s)", o.Name)
		}
	}
}
