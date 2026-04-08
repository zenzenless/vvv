package infra

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/v2fly/v2ray-core/v5/common/strmatcher"
	v2router "github.com/v2rayA/v2ray-lib/router"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

type DnsSupervisor struct {
	handles        map[string]*handle
	reqID          uint32
	inner          sync.Mutex
	reservedIpPool *ReservedIpPool
}

func New() *DnsSupervisor {
	return &DnsSupervisor{
		handles:        make(map[string]*handle),
		reservedIpPool: NewReservedIpPool(),
	}
}

func (d *DnsSupervisor) Exists(ifname string) bool {
	_, ok := d.handles[ifname]
	return ok
}

func (d *DnsSupervisor) Clear() {
	handles := d.ListHandles()
	for _, h := range handles {
		_ = d.DeleteHandles(h)
	}
	log.Trace("DnsSupervisor: Clear")
}

func (d *DnsSupervisor) Prepare(ifname string) (err error) {
	d.inner.Lock()
	defer d.inner.Unlock()
	if d.Exists(ifname) {
		return fmt.Errorf("Prepare: %v exists", ifname)
	}
	h, err := pcapgo.NewEthernetHandle(ifname)
	if err != nil {
		return
	}
	d.handles[ifname] = newHandle(d, h)
	return
}

func (d *DnsSupervisor) ListHandles() (ifnames []string) {
	d.inner.Lock()
	defer d.inner.Unlock()
	for ifname := range d.handles {
		ifnames = append(ifnames, ifname)
	}
	return
}

func (d *DnsSupervisor) DeleteHandles(ifname string) (err error) {
	d.inner.Lock()
	defer d.inner.Unlock()
	if !d.Exists(ifname) {
		return fmt.Errorf("DeleteHandles: handle not exists")
	}
	// Close done first so the Run loop treats the subsequent read error as intentional.
	close(d.handles[ifname].done)
	// Close the AF_PACKET socket to unblock any pending ReadPacketData call in Run.
	d.handles[ifname].EthernetHandle.Close()
	delete(d.handles, ifname)
	log.Trace("DnsSupervisor:%v deleted", ifname)
	return
}

func (d *DnsSupervisor) Run(ifname string, whitelistDnsServers *v2router.GeoIPMatcher, whitelistDomains strmatcher.MatcherGroup) (err error) {
	defer func() {
		recover()
	}()
	d.inner.Lock()
	handle, ok := d.handles[ifname]
	if !ok {
		d.inner.Unlock()
		return fmt.Errorf("Run: %v not exsits", ifname)
	}
	if handle.running {
		d.inner.Unlock()
		return fmt.Errorf("Run: %v is running", ifname)
	}
	handle.running = true
	log.Trace("[DnsSupervisor] " + ifname + ": running")
	// we only decode UDP packets
	pkgsrc := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	pkgsrc.NoCopy = true
	pkgsrc.Lazy = true
	d.inner.Unlock()
	// Use NextPacket directly instead of Packets() to avoid the internal
	// packetsToChannel goroutine, which reads from the socket in an
	// uncontrolled background goroutine and cannot be terminated other than
	// by closing the underlying EthernetHandle.
	for {
		packet, err := pkgsrc.NextPacket()
		if err != nil {
			// An error means the socket was closed (EthernetHandle.Close was
			// called in DeleteHandles). Check whether this was intentional.
			select {
			case <-handle.done:
				log.Trace("DnsSupervisor:%v closed", ifname)
				return nil
			default:
				// Transient read error; keep going.
				continue
			}
		}
		select {
		case <-handle.done:
			log.Trace("DnsSupervisor:%v closed", ifname)
			return nil
		default:
		}
		handle.handlePacket(packet, ifname, whitelistDnsServers, whitelistDomains)
	}
}
