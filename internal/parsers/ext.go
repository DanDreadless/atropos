package parsers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

// extTimeline puts an ext2/3/4 volume's names on the timeline with their
// inodes' times, which are UTC. A deleted name found in a directory's
// unused space gets its inode's times only while the inode is free: once
// the inode belongs to another file, those times are that file's.
func extTimeline(ctx *Context, v imagefs.ExtVolume) error {
	key := "ext"
	if v.Where != "/" {
		key += "." + strings.TrimPrefix(v.Where, "/")
	}
	ctx.Fact(key+".volume", v.Describe, "an ext2, ext3 or ext4 volume in the image")
	ctx.Fact(key+".volume_uuid", v.UUID, "the volume's UUID, which /etc/fstab and the kernel's logs use to name it")
	if v.Label != "" {
		ctx.Fact(key+".volume_label", v.Label, "volume label from the superblock")
	}
	names, deleted, reused, freed := 0, 0, 0, 0
	err := imagefs.WalkExt(v.R, v.Size, func(e imagefs.ExtEntry) error {
		names++
		if e.Deleted {
			deleted++
		}
		if e.InodeReused {
			// No time belongs to this name; it is counted, not emitted.
			reused++
			return nil
		}
		path := e.Path
		if v.Where != "/" {
			path = v.Where + e.Path
		}
		fields := map[string]any{
			"name": path[strings.LastIndex(path, "/")+1:], "inode": e.Inode, "type": e.Type, "size": e.Size,
			"mode": fmt.Sprintf("%06o", e.Mode), "uid": e.UID, "gid": e.GID, "links": e.Links,
			"volume": v.Describe, "volume_uuid": v.UUID,
		}
		if e.Target != "" {
			fields["link_target"] = e.Target
		}
		ref := fmt.Sprintf("inode %d; name at byte %d of directory inode %d", e.Inode, e.DirOffset, e.Dir)
		if v.Where != "/" {
			ref = fmt.Sprintf("partition %s, %s", strings.TrimPrefix(v.Where, "/"), ref)
		}
		what := ""
		if e.Deleted {
			fields["deleted"] = true
			fields["recovered_from_slack"] = true
			what = "; a deleted name, recovered from unused space in its directory, whose inode is still free. Deleting a file sets its inode's changed and modified times to when it happened"
		}
		var t [4]time.Time
		for i, x := range []imagefs.ExtTime{e.Modified, e.Accessed, e.Changed, e.Born} {
			if x.Valid {
				t[i] = x.T
			}
		}
		groups := macb(t[0], t[1], t[2], t[3])
		keys := make([]time.Time, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
		for _, k := range keys {
			stamp, ok := timeutil.FromTimeNative(k, "")
			if !ok {
				continue
			}
			typ := "ext " + groups[k]
			if e.Deleted {
				typ = "deleted " + typ
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: typ, MACB: groups[k], Category: CatFileSystem, Source: "ext", Host: ctx.Host, Path: path,
				Message: fmt.Sprintf("ext %s  %s %s (%d bytes)%s", groups[k], e.Type, path, e.Size, what),
				Fields:  fields, Ref: ref,
			}); err != nil {
				return err
			}
		}
		if e.InodeFree && e.DeletedAt.Valid {
			freed++
			if stamp, ok := timeutil.FromTimeNative(e.DeletedAt.T, ""); ok {
				if err := ctx.Emit(Event{
					Stamp: stamp, Type: "inode freed (deletion time)", Category: CatDeletion, Source: "ext", Host: ctx.Host, Path: path,
					Message: fmt.Sprintf("Deleted: %s %s; its inode %d was freed at this time, and the name was recovered from its directory", e.Type, path, e.Inode),
					Fields:  fields, Ref: ref,
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		ctx.Warn("%s: %v", v.Describe, err)
	}
	ctx.Note("%s: %d names, %d of them deleted names recovered from directory slack (%d with a deletion time); %d deleted names whose inode now belongs to another file are counted but not put on the timeline", v.Describe, names, deleted, freed, reused)
	return nil
}
