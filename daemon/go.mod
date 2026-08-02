module host-health-mcp/daemon

go 1.22

require (
	github.com/coreos/go-systemd/v22 v22.5.0
	golang.org/x/sync v0.7.0
	golang.org/x/sys v0.20.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/godbus/dbus/v5 v5.0.4 // indirect
