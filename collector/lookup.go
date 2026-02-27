package collector

import (
	"context"
	"fmt"
	"os/user"
	"sync"
	"time"
)

// UserEntry holds cached results from an NSS user lookup.
type UserEntry struct {
	Username     string
	UID          string
	GID          string
	Name         string // GECOS / display name
	PrimaryGroup string
	Err          error
	CachedAt     time.Time
}

// UserLookupCache provides timeout-protected and cached user/group lookups.
// All NSS calls (which may hit LDAP/SSSD) go through this cache to prevent
// slow or hung lookups from blocking the entire scrape.
type UserLookupCache struct {
	timeout  time.Duration
	cacheTTL time.Duration

	mu          sync.RWMutex
	byName      map[string]*UserEntry
	byUID       map[string]*UserEntry
	groupByGID  map[string]string // gid → group name
	groupCached map[string]time.Time
}

// NewUserLookupCache creates a cache with the given lookup timeout and cache TTL.
func NewUserLookupCache(timeout, cacheTTL time.Duration) *UserLookupCache {
	return &UserLookupCache{
		timeout:     timeout,
		cacheTTL:    cacheTTL,
		byName:      make(map[string]*UserEntry),
		byUID:       make(map[string]*UserEntry),
		groupByGID:  make(map[string]string),
		groupCached: make(map[string]time.Time),
	}
}

// LookupByName resolves a username to a UserEntry with timeout protection.
func (c *UserLookupCache) LookupByName(username string) *UserEntry {
	c.mu.RLock()
	if entry, ok := c.byName[username]; ok && time.Since(entry.CachedAt) < c.cacheTTL {
		c.mu.RUnlock()
		return entry
	}
	c.mu.RUnlock()

	entry := c.doLookupByName(username)

	c.mu.Lock()
	c.byName[username] = entry
	if entry.Err == nil {
		c.byUID[entry.UID] = entry
	}
	c.mu.Unlock()

	return entry
}

// LookupByUID resolves a numeric UID to a UserEntry with timeout protection.
func (c *UserLookupCache) LookupByUID(uid string) *UserEntry {
	c.mu.RLock()
	if entry, ok := c.byUID[uid]; ok && time.Since(entry.CachedAt) < c.cacheTTL {
		c.mu.RUnlock()
		return entry
	}
	c.mu.RUnlock()

	entry := c.doLookupByUID(uid)

	c.mu.Lock()
	c.byUID[uid] = entry
	if entry.Err == nil {
		c.byName[entry.Username] = entry
	}
	c.mu.Unlock()

	return entry
}

// LookupGroupByGID resolves a numeric GID to a group name with timeout protection.
func (c *UserLookupCache) LookupGroupByGID(gid string) (string, error) {
	c.mu.RLock()
	if name, ok := c.groupByGID[gid]; ok {
		if cached, exists := c.groupCached[gid]; exists && time.Since(cached) < c.cacheTTL {
			c.mu.RUnlock()
			return name, nil
		}
	}
	c.mu.RUnlock()

	name, err := c.doLookupGroup(gid)
	if err != nil {
		return gid, err // fallback to numeric GID
	}

	c.mu.Lock()
	c.groupByGID[gid] = name
	c.groupCached[gid] = time.Now()
	c.mu.Unlock()

	return name, nil
}

// doLookupByName performs the actual NSS lookup with timeout.
func (c *UserLookupCache) doLookupByName(username string) *UserEntry {
	type result struct {
		u   *user.User
		err error
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	ch := make(chan result, 1)
	go func() {
		u, err := user.Lookup(username)
		ch <- result{u, err}
	}()

	select {
	case <-ctx.Done():
		return &UserEntry{
			Username: username,
			Err:      fmt.Errorf("NSS lookup timed out after %s for user %q", c.timeout, username),
			CachedAt: time.Now(),
		}
	case r := <-ch:
		if r.err != nil {
			return &UserEntry{
				Username: username,
				Err:      r.err,
				CachedAt: time.Now(),
			}
		}
		return c.userToEntry(r.u)
	}
}

// doLookupByUID performs the actual NSS lookup by UID with timeout.
func (c *UserLookupCache) doLookupByUID(uid string) *UserEntry {
	type result struct {
		u   *user.User
		err error
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	ch := make(chan result, 1)
	go func() {
		u, err := user.LookupId(uid)
		ch <- result{u, err}
	}()

	select {
	case <-ctx.Done():
		return &UserEntry{
			UID:      uid,
			Err:      fmt.Errorf("NSS lookup timed out after %s for UID %s", c.timeout, uid),
			CachedAt: time.Now(),
		}
	case r := <-ch:
		if r.err != nil {
			return &UserEntry{
				UID:      uid,
				Err:      r.err,
				CachedAt: time.Now(),
			}
		}
		return c.userToEntry(r.u)
	}
}

// doLookupGroup performs the actual NSS group lookup with timeout.
func (c *UserLookupCache) doLookupGroup(gid string) (string, error) {
	type result struct {
		g   *user.Group
		err error
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	ch := make(chan result, 1)
	go func() {
		g, err := user.LookupGroupId(gid)
		ch <- result{g, err}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("NSS group lookup timed out after %s for GID %s", c.timeout, gid)
	case r := <-ch:
		if r.err != nil {
			return "", r.err
		}
		return r.g.Name, nil
	}
}

// userToEntry converts an os/user.User to a cached UserEntry.
func (c *UserLookupCache) userToEntry(u *user.User) *UserEntry {
	name := u.Name
	if name == "" {
		name = u.Username
	}

	// Resolve primary group via timeout-protected cache method
	primaryGroup, _ := c.LookupGroupByGID(u.Gid)

	return &UserEntry{
		Username:     u.Username,
		UID:          u.Uid,
		GID:          u.Gid,
		Name:         name,
		PrimaryGroup: primaryGroup,
		CachedAt:     time.Now(),
	}
}
