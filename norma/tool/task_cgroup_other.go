//go:build !linux

package tool

// cmdCgroup is a no-op stub on non-Linux platforms where termination falls back
// to process-group / job-tree signals.
type cmdCgroup struct{}

func newCmdCgroup() *cmdCgroup        { return nil }
func (c *cmdCgroup) attach(int) bool  { return false }
func (c *cmdCgroup) kill() error      { return nil }
func (c *cmdCgroup) cleanup()         {}
