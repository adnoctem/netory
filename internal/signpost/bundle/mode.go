package bundle

import "io/fs"

// modeSymlink is fs.ModeSymlink, named locally so extract.go reads without an
// io/fs import whose only use is one bit test.
const modeSymlink = fs.ModeSymlink
