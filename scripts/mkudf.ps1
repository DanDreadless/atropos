param([string]$Out)
# Builds UDF disc images with Windows' own IMAPI2 file system writer, from a
# folder of made-up test files, in each UDF revision IMAPI2 writes.
$ErrorActionPreference = 'Stop'
$src = Join-Path $Out 'src'
New-Item -ItemType Directory -Force -Path (Join-Path $src 'Docs\Deep\Deeper') | Out-Null
Set-Content -NoNewline -Encoding ascii -Path (Join-Path $src 'readme.txt') -Value 'UDF test disc made by IMAPI2'
Set-Content -NoNewline -Encoding ascii -Path (Join-Path $src 'Docs\notes.txt') -Value ('line of notes ' * 200)
Set-Content -NoNewline -Encoding ascii -Path (Join-Path $src 'Docs\Deep\Deeper\bottom.log') -Value '2024-03-01T10:00:00Z deep'
[IO.File]::WriteAllBytes((Join-Path $src 'Docs\blob.bin'), [byte[]](0..255 * 300))
Set-Content -NoNewline -Encoding utf8 -Path (Join-Path $src ('Docs\' + [char]0x00E9 + 't' + [char]0x00E9 + ' r' + [char]0x00E9 + 'sum' + [char]0x00E9 + '.txt')) -Value 'unicode name'
(Get-Item (Join-Path $src 'readme.txt')).LastWriteTimeUtc = [datetime]::new(2024, 3, 1, 10, 0, 0, [DateTimeKind]::Utc)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class StreamSaver {
    public static void Save(object comStream, string path) {
        IStream s = (IStream)comStream;
        using (FileStream f = File.Create(path)) {
            byte[] buf = new byte[65536];
            IntPtr pRead = Marshal.AllocHGlobal(4);
            try {
                while (true) {
                    s.Read(buf, buf.Length, pRead);
                    int n = Marshal.ReadInt32(pRead);
                    if (n <= 0) break;
                    f.Write(buf, 0, n);
                }
            } finally { Marshal.FreeHGlobal(pRead); }
        }
    }
}
'@
foreach ($rev in 0x102, 0x150, 0x200, 0x201, 0x250) {
    $fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fs.FileSystemsToCreate = 4            # UDF only
    $fs.UDFRevision = $rev
    $fs.VolumeName = 'UDFTEST'
    $fs.ChooseImageDefaultsForMediaType(13) # DVD+R
    $fs.FileSystemsToCreate = 4
    $fs.UDFRevision = $rev
    $fs.Root.AddTree($src, $false)
    $img = $fs.CreateResultImage()
    $name = Join-Path $Out ('udf{0:x3}.iso' -f $rev)
    [StreamSaver]::Save($img.ImageStream, $name)
    '{0} {1}' -f $name, (Get-Item $name).Length
}
