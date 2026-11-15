package imagefs

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"
)

type ntfsFS struct {
	ctx     *ntfs.NTFSContext
	label   string
	shadows *shadowSet // the volume's shadow copies, if it has any
}

func openNTFS(r io.ReaderAt, offset, size int64, label string) (FS, error) {
	// The volume is handed over as a reader of its own, starting at zero.
	// The library accepts an offset, but does not apply it everywhere.
	if offset != 0 {
		r = &shifted{r, offset}
		size -= offset
	}
	n, err := openNTFSVolume(r, label+shadowSummary(r))
	if err != nil {
		return nil, err
	}
	if copies, err := ShadowCopies(r, size); err == nil && len(copies) > 0 {
		n.shadows = &shadowSet{r: r, size: size, copies: copies, open: map[int]FS{}, errs: map[int]error{}}
	}
	return n, nil
}

func openNTFSVolume(r io.ReaderAt, label string) (fs *ntfsFS, err error) {
	defer func() {
		if p := recover(); p != nil {
			fs, err = nil, fmt.Errorf("NTFS volume could not be read: %v", p)
		}
	}()
	ctx, err := ntfs.GetNTFSContext(r, 0)
	if err != nil {
		return nil, err
	}
	if _, err := ctx.GetMFT(5); err != nil {
		ctx.Close()
		return nil, fmt.Errorf("NTFS volume has no readable root directory: %w", err)
	}
	return &ntfsFS{ctx: ctx, label: label}, nil
}

// shadowName is the folder a shadow copy appears as at the volume's root.
// "<" cannot occur in a Windows file name, so it cannot hide a real one.
func shadowName(i int) string { return fmt.Sprintf("<shadow copy %d>", i+1) }

// get opens shadow copy i as a volume of its own, once.
func (s *shadowSet) get(i int) (FS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fs, ok := s.open[i]; ok {
		return fs, nil
	}
	if err, ok := s.errs[i]; ok {
		return nil, err
	}
	v, err := OpenShadowCopy(s.r, s.size, s.copies, i)
	var fs *ntfsFS
	if err == nil {
		fs, err = openNTFSVolume(v, fmt.Sprintf("shadow copy %d, made %s", i+1, s.copies[i].CreatedTime().Format("2006-01-02 15:04:05 UTC")))
	}
	if err != nil {
		err = fmt.Errorf("shadow copy %d could not be read: %v", i+1, err)
		s.errs[i] = err
		return nil, err
	}
	s.open[i] = fs
	return fs, nil
}

func (s *shadowSet) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fs := range s.open {
		fs.Close()
	}
	s.open = map[int]FS{}
}

// route sends a path that starts in a shadow copy's folder to that copy:
// the copy, the folder's path, and the path within the copy.
func (n *ntfsFS) route(parts []string) (FS, string, string, bool, error) {
	if n.shadows == nil || len(parts) == 0 || !strings.HasPrefix(parts[0], "<shadow copy ") {
		return nil, "", "", false, nil
	}
	for i := range n.shadows.copies {
		if parts[0] == shadowName(i) {
			fs, err := n.shadows.get(i)
			return fs, "/" + parts[0], "/" + strings.Join(parts[1:], "/"), true, err
		}
	}
	return nil, "", "", false, nil
}

type shifted struct {
	r   io.ReaderAt
	off int64
}

func (s *shifted) ReadAt(p []byte, off int64) (int, error) { return s.r.ReadAt(p, off+s.off) }

func (n *ntfsFS) Describe() string { return n.label }
func (n *ntfsFS) Close() {
	if n.shadows != nil {
		n.shadows.close()
	}
	n.ctx.Close()
}

func (n *ntfsFS) entry(parts []string) (*ntfs.MFT_ENTRY, error) {
	root, err := n.ctx.GetMFT(5)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return root, nil
	}
	// A colon introduces an alternate data stream; the entry is the file's.
	last := parts[len(parts)-1]
	if i := strings.IndexByte(last, ':'); i > 0 {
		parts = append(append([]string{}, parts[:len(parts)-1]...), last[:i])
	}
	e, err := root.Open(n.ctx, strings.Join(parts, "/"))
	if err != nil {
		return nil, errors.New("not found in this volume")
	}
	return e, nil
}

func ns(t time.Time) int64 {
	if t.IsZero() || t.Year() < 1970 || t.Year() > 2200 {
		return 0
	}
	return t.UTC().UnixNano()
}

func (n *ntfsFS) List(path string) (out []Entry, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("directory could not be read: %v", p)
		}
	}()
	dir, parts, err := clean(path)
	if err != nil {
		return nil, err
	}
	if sub, prefix, inner, ok, err := n.route(parts); ok {
		if err != nil {
			return nil, err
		}
		list, err := sub.List(inner)
		for i := range list {
			list[i].Path = prefix + list[i].Path
		}
		return list, err
	}
	e, err := n.entry(parts)
	if err != nil {
		return nil, err
	}
	if !e.IsDir(n.ctx) {
		return nil, errors.New("not a directory")
	}
	seen := map[string]bool{}
	for _, fi := range ntfs.ListDir(n.ctx, e) {
		// Slack entries are remnants, not files; "." is the directory itself.
		// Short (DOS) names duplicate a long name already listed.
		if fi.IsSlack || fi.Name == "." || fi.Name == "" || seen[fi.Name] || fi.NameType == "DOS" {
			continue
		}
		seen[fi.Name] = true
		ent := Entry{Name: fi.Name, Path: join(dir, fi.Name), IsDir: fi.IsDir, Size: fi.Size,
			Modified: ns(fi.Mtime), Accessed: ns(fi.Atime), Changed: ns(fi.Ctime), Born: ns(fi.Btime)}
		if strings.Contains(fi.Name, ":") {
			ent.Note = "alternate data stream"
		}
		out = append(out, ent)
		if len(out) >= MaxListing {
			break
		}
	}
	if len(parts) == 0 && n.shadows != nil {
		for i, c := range n.shadows.copies {
			out = append(out, Entry{Name: shadowName(i), Path: "/" + shadowName(i), IsDir: true, Born: ns(c.CreatedTime()),
				Note: fmt.Sprintf("volume shadow copy made %s: the whole volume as it was then (store %s)", c.CreatedTime().Format("2006-01-02 15:04:05 UTC"), c.ID)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// sparseSkip wraps a stream whose beginning is unallocated. The NTFS change
// journal is the case that matters: it is a sparse file whose first several
// gigabytes are holes, and copying those out as zeros would waste the disk
// and tell the examiner nothing.
type rangeReader struct {
	r   io.ReaderAt
	off int64
	end int64
}

func (r *rangeReader) Read(p []byte) (int, error) {
	if r.off >= r.end {
		return 0, io.EOF
	}
	if int64(len(p)) > r.end-r.off {
		p = p[:r.end-r.off]
	}
	n, err := r.r.ReadAt(p, r.off)
	r.off += int64(n)
	if n > 0 && err == io.EOF {
		err = nil
	}
	// A short read inside the stream is a hole or a damaged run; the bytes
	// that could not be read are reported as zeros rather than ending the file
	// early, so offsets inside the extracted copy stay true.
	if n == 0 && err != nil && r.off < r.end {
		for i := range p {
			p[i] = 0
		}
		r.off += int64(len(p))
		return len(p), nil
	}
	return n, err
}

func (n *ntfsFS) Open(path string) (rd io.Reader, size int64, err error) {
	defer func() {
		if p := recover(); p != nil {
			rd, size, err = nil, 0, fmt.Errorf("file could not be read: %v", p)
		}
	}()
	full, parts, err := clean(path)
	if err != nil {
		return nil, 0, err
	}
	if len(parts) == 0 {
		return nil, 0, errors.New("not a file")
	}
	if sub, _, inner, ok, err := n.route(parts); ok {
		if err != nil {
			return nil, 0, err
		}
		return sub.Open(inner)
	}
	e, err := n.entry(parts)
	if err != nil {
		return nil, 0, err
	}
	if e.IsDir(n.ctx) && !strings.Contains(parts[len(parts)-1], ":") {
		return nil, 0, errors.New("that is a directory")
	}
	stream, err := ntfs.GetDataForPath(n.ctx, strings.TrimPrefix(full, "/"))
	if err != nil {
		return nil, 0, errors.New("the file has no readable content")
	}
	// The size comes from the file's own record where there is one; the
	// stream's extent is rounded up to whole clusters.
	size = ntfs.RangeSize(stream)
	name := parts[len(parts)-1]
	for _, fi := range ntfs.Stat(n.ctx, e) {
		if strings.EqualFold(fi.Name, name) || (!strings.Contains(name, ":") && !strings.Contains(fi.Name, ":")) {
			if fi.Size >= 0 && fi.Size <= size {
				size = fi.Size
			}
			break
		}
	}
	start := int64(0)
	if runs := stream.Ranges(); len(runs) > 1 && runs[0].IsSparse && runs[0].Length >= 64<<20 {
		// Leading hole: begin at the first allocated run.
		start = runs[0].Offset + runs[0].Length
	}
	if start >= size {
		start = 0
	}
	return &rangeReader{r: stream, off: start, end: size}, size - start, nil
}
