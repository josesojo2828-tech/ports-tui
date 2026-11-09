package netinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procInfo describe el proceso dueño de un socket.
type procInfo struct {
	PID     int
	Comm    string
	Cmdline string
	UID     int
	User    string
}

// processCache evita recorrer todo /proc en cada refresco de la UI.
type processCache struct {
	mu       sync.Mutex
	byInode  map[uint64]procInfo
	expires  time.Time
	ttl      time.Duration
	procRoot string
}

// newProcessCache crea la caché con un TTL corto.
func newProcessCache(procRoot string) *processCache {
	return &processCache{
		byInode:  map[uint64]procInfo{},
		ttl:      3 * time.Second,
		procRoot: procRoot,
	}
}

// attachProcesses correlaciona los sockets con sus procesos propietarios.
func (c *Collector) attachProcesses(listeners []Listener) {
	cache := c.cache()
	owners := cache.snapshot()

	for i := range listeners {
		info, ok := owners[listeners[i].Inode]
		if !ok {
			continue
		}
		listeners[i].PID = info.PID
		listeners[i].Process = info.Comm
		listeners[i].Cmdline = info.Cmdline
		listeners[i].User = info.User
		if listeners[i].UID == 0 {
			listeners[i].UID = info.UID
		}
	}
}

// cache devuelve la caché de procesos del colector.
func (c *Collector) cache() *processCache {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cacheRef == nil {
		c.cacheRef = newProcessCache(c.ProcRoot)
	}
	return c.cacheRef
}

// snapshot devuelve el mapa inode→proceso, reconstruyolo si expiró.
func (p *processCache) snapshot() map[uint64]procInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Now().Before(p.expires) && len(p.byInode) > 0 {
		return p.byInode
	}

	p.byInode = scanProcesses(p.procRoot)
	p.expires = time.Now().Add(p.ttl)
	return p.byInode
}

// scanProcesses recorre /proc y construye el índice inode de socket → proceso.
func scanProcesses(procRoot string) map[uint64]procInfo {
	if procRoot == "" {
		procRoot = "/proc"
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return map[uint64]procInfo{}
	}

	result := map[uint64]procInfo{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// Sin permisos para otros procesos: se omite silenciosamente.
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(link)
			if !ok {
				continue
			}
			if _, exists := result[inode]; exists {
				continue
			}
			result[inode] = readProcInfo(procRoot, pid)
			break
		}
	}
	return result
}

// socketInode extrae el inode de un enlace "socket:[12345]".
func socketInode(link string) (uint64, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	value := link[len("socket:[") : len(link)-1]
	inode, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// readProcInfo lee nombre, cmdline y uid de un proceso.
func readProcInfo(procRoot string, pid int) procInfo {
	info := procInfo{PID: pid}

	if data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm")); err == nil {
		info.Comm = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline")); err == nil {
		parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		kept := parts[:0]
		for _, p := range parts {
			if p != "" {
				kept = append(kept, p)
			}
		}
		info.Cmdline = strings.Join(kept, " ")
	}
	if data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.UID, _ = strconv.Atoi(fields[1])
				}
				break
			}
		}
	}
	if info.UID != 0 {
		info.User = userName(info.UID)
	} else {
		info.User = "root"
	}
	return info
}

// userName resuelve un uid a nombre de usuario desde /etc/passwd.
func userName(uid int) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return strconv.Itoa(uid)
	}
	want := strconv.Itoa(uid)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == want {
			return parts[0]
		}
	}
	return want
}
