package parsers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DanDreadless/atropos/internal/imagefs"
	"github.com/DanDreadless/atropos/internal/timeutil"
)

type fatStamp struct {
	t      imagefs.FATTime
	letter byte
	at     int
}

func fatTimeline(ctx *Context, v imagefs.FATVolume) error {
	serial := fmt.Sprintf("%08X", v.Serial)
	key := "fat"
	if v.Where != "/" {
		key += "." + strings.TrimPrefix(v.Where, "/")
	}
	ctx.Fact(key+".volume", v.Describe, "a FAT or exFAT volume in the image")
	ctx.Fact(key+".volume_serial", serial, "volume serial number; shortcut files and jump lists record it for the volume a target was on")
	if v.Label != "" {
		ctx.Fact(key+".volume_label", v.Label, "volume label from the boot sector")
	}
	files, deleted, local, offsets := 0, 0, 0, 0
	err := imagefs.WalkFAT(v.R, v.Size, func(e imagefs.FATEntry) error {
		files++
		if e.Deleted {
			deleted++
		}
		path := e.Path
		if v.Where != "/" {
			path = v.Where + e.Path
		}
		kind := "file"
		if e.IsDir {
			kind = "folder"
		}
		fields := map[string]any{
			"name": path[strings.LastIndex(path, "/")+1:], "is_dir": e.IsDir, "size": e.Size, "first_cluster": e.Cluster &^ (1 << 31),
			"volume": v.Describe, "volume_serial": serial, "entry_offset": e.Offset,
		}
		// Only on deleted entries, so that searching for the word finds them.
		if e.Deleted {
			fields["deleted"] = true
		}
		if e.ShortName != "" {
			fields["short_name"] = e.ShortName
		}
		if e.NameRecovered {
			fields["short_name_first_character_from_checksum"] = true
		}
		ref := fmt.Sprintf("directory entry at byte %d of the volume", e.Offset)
		if v.Where != "/" {
			ref = fmt.Sprintf("partition %s, %s", strings.TrimPrefix(v.Where, "/"), ref)
		}
		what := ""
		if e.Deleted {
			what = "; the entry is marked deleted: these are the file's own times as last recorded, not when it was deleted"
			switch {
			case e.NameRecovered:
				what += "; the first character of its short name, which deleting overwrote, was worked out from the long name's checksum"
			case e.ShortName != "":
				what += ", and the first character of its short name is lost (shown as _)"
			}
		}
		// Times that are the same instant share one event, as with NTFS.
		// FAT's last access is a day, never merged with a full time.
		stamps := []fatStamp{{e.Modified, 'M', 0}, {e.Accessed, 'A', 1}, {e.Created, 'B', 3}}
		groups := map[string][]fatStamp{}
		var order []string
		for _, s := range stamps {
			if !s.t.Valid {
				continue
			}
			k := fmt.Sprintf("%d/%v/%d/%v", s.t.Wall.UnixNano(), s.t.HasOffset, s.t.OffsetMinutes, s.t.DateOnly)
			if groups[k] == nil {
				order = append(order, k)
			}
			groups[k] = append(groups[k], s)
		}
		sort.Strings(order)
		for _, k := range order {
			g := groups[k]
			t := g[0].t
			letters := []byte("....")
			for _, s := range g {
				letters[s.at] = s.letter
			}
			mb := string(letters)
			var stamp timeutil.Stamp
			raw := t.Wall.Format("2006-01-02 15:04:05.00")
			if t.DateOnly {
				raw = t.Wall.Format("2006-01-02")
			}
			if t.HasOffset {
				offsets++
				z := time.FixedZone("", t.OffsetMinutes*60)
				w := t.Wall
				stamp = timeutil.FromExplicit(time.Date(w.Year(), w.Month(), w.Day(), w.Hour(), w.Minute(), w.Second(), w.Nanosecond(), z), raw+" "+offsetText(t.OffsetMinutes))
			} else {
				local++
				stamp = timeutil.FromLocal(t.Wall, raw+" (local clock, zone not recorded)", ctx.Local)
			}
			if !timeutil.Plausible(stamp.UTC) {
				continue
			}
			typ := "FAT " + mb
			msg := fmt.Sprintf("FAT %s  %s %s (%d bytes)%s", mb, kind, path, e.Size, what)
			f := fields
			if t.DateOnly {
				typ += " (day only)"
				msg = fmt.Sprintf("FAT %s  %s %s (%d bytes): last accessed on %s; FAT records the day, not the time%s", mb, kind, path, e.Size, raw, what)
				f = make(map[string]any, len(fields)+1)
				for k, v := range fields {
					f[k] = v
				}
				f["time_precision"] = "day"
			}
			if e.Deleted {
				typ = "deleted " + typ
			}
			if err := ctx.Emit(Event{
				Stamp: stamp, Type: typ, MACB: mb, Category: CatFileSystem, Source: "fat",
				Host: ctx.Host, Path: path, Message: msg, Fields: f, Ref: ref,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		ctx.Warn("%s: %v", v.Describe, err)
	}
	ctx.Note("%s: %d entries, %d of them deleted", v.Describe, files, deleted)
	if local > 0 {
		ctx.Note("FAT records times on the writing device's local clock without its zone; they were converted using %s (%s). A stick written by another computer or a camera may have used another zone", ctx.Local.ZoneName, ctx.Local.ZoneFrom)
	}
	return nil
}

func offsetText(minutes int) string {
	sign := "+"
	if minutes < 0 {
		sign, minutes = "-", -minutes
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, minutes/60, minutes%60)
}
